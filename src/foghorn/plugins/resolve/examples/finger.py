from __future__ import annotations

import logging
import os
import pwd
from dataclasses import dataclass
from typing import List, Optional, Tuple

from dnslib import QTYPE, RR, TXT, DNSHeader, DNSRecord
from pydantic import BaseModel, Field, validator

from foghorn.plugins.resolve.base import (
    BasePlugin,
    PluginContext,
    PluginDecision,
    plugin_aliases,
)
from foghorn.utils.register_caches import registered_lru_cached

logger = logging.getLogger(__name__)


@dataclass
class FingerUserPolicy:
    """Brief: Normalized allow/deny policy for a single Finger instance.

    Inputs (fields):
      - domain: Lowercased DNS suffix under which this plugin serves answers
        (e.g. "example.com").
      - domain_labels: Tuple of domain labels used for qname parsing.
      - max_size: Integer maximum number of bytes to read from ~/.finger.
      - policy: Default policy string ("allow" or "deny").
      - allow_users: Normalized, lowercased list of explicitly allowed users.
      - deny_users: Normalized, lowercased list of explicitly denied users.

    Outputs:
      - FingerUserPolicy instances are used at runtime to evaluate whether a
        given user should be answered for a TXT query.
    """

    domain: str
    domain_labels: Tuple[str, ...]
    max_size: int
    policy: str
    allow_users: List[str]
    deny_users: List[str]


class FingerConfig(BaseModel):
    """Brief: Typed configuration model for the Finger resolve plugin.

    Inputs:
      - domain: DNS suffix under which to expose finger answers. A query name of
        the form ``<user>.<domain>`` will be handled when qtype=TXT.
      - max_size: Maximum number of bytes to read from ``$HOME/.finger``; any
        extra content is silently truncated.
      - location: Optional filesystem template for finger files. When set, this
        string should contain a ``"%u"`` placeholder which will be replaced with
        the queried username (for example, ``"/home/%u/.finger"`` or
        ``"/data/finger/%u"``) and that path will be used instead of
        ``$HOME/.finger``.
      - policy: Default policy when a user is not mentioned in allow/deny lists.
        Accepted values (case-insensitive): "allow" (default) or "deny".
      - allow_users: Optional list of usernames that should always be allowed.
      - deny_users: Optional list of usernames that should always be denied.

    Outputs:
      - FingerConfig instance with normalized field types.
    """

    domain: str = Field(...)
    max_size: int = Field(default=1024, ge=1, le=65536)
    location: Optional[str] = Field(default=None)
    policy: str = Field(default="allow")
    allow_users: List[str] = Field(default_factory=list)
    deny_users: List[str] = Field(default_factory=list)

    class Config:
        extra = "allow"

    @validator("domain", pre=True)
    def _normalize_domain(cls, v: object) -> str:  # type: ignore[override]
        """Brief: Normalize the configured domain suffix.

        Inputs:
          - v: Raw domain config value (string-like).

        Outputs:
          - str: Lowercased domain without trailing dot.
        """

        text = str(v or "").strip()
        if not text:
            raise ValueError("FingerConfig.domain must be a non-empty string")
        return text.rstrip(".").lower()

    @validator("policy", pre=True)
    def _normalize_policy(cls, v: object) -> str:  # type: ignore[override]
        """Brief: Normalize policy to either "allow" or "deny".

        Inputs:
          - v: Raw policy string (case-insensitive).

        Outputs:
          - str: "allow" or "deny".
        """

        text = str(v or "allow").strip().lower()
        if text not in {"allow", "deny"}:
            raise ValueError("FingerConfig.policy must be 'allow' or 'deny'")
        return text


@registered_lru_cached(maxsize=4096)
def _is_user_allowed_cached(
    username: str,
    policy: str,
    allow_users: Tuple[str, ...],
    deny_users: Tuple[str, ...],
) -> bool:
    """Brief: Evaluate allow/deny policy for a username with caching.

    Inputs:
      - username: Raw username label extracted from the qname (lowercase).
      - policy: Default policy ("allow" or "deny").
      - allow_users: Tuple of normalized usernames that should always be allowed.
      - deny_users: Tuple of normalized usernames that should always be denied.

    Outputs:
      - bool: True when the user is allowed according to the policy and lists.

    Behaviour:
      - deny_users always takes precedence.
      - When policy == "allow":
          * if allow_users is non-empty, only users in allow_users are allowed
            (and not in deny_users).
          * when allow_users is empty, all users are allowed except those in
            deny_users.
      - When policy == "deny":
          * only users in allow_users are allowed (and not in deny_users).
    """

    user = username.strip().lower()
    if not user:
        return False

    deny_set = set(u.strip().lower() for u in deny_users if u.strip())
    if user in deny_set:
        return False

    allow_set = set(u.strip().lower() for u in allow_users if u.strip())

    if policy == "allow":
        if allow_set:
            return user in allow_set
        return True

    # policy == "deny": only explicitly allowed users may pass.
    return user in allow_set


def _parse_finger_qname(qname: str, domain_labels: Tuple[str, ...]) -> Optional[str]:
    """Brief: Extract the username from a qname of the form ``user.<domain>``.

    Inputs:
      - qname: Full DNS qname string (any case, optional trailing dot).
      - domain_labels: Tuple of labels that comprise the configured domain
        suffix (for example, ("users", "zaa") for "users.zaa").

    Outputs:
      - str username when the qname matches the expected pattern; otherwise
        None.

    Behaviour:
      - Matches names whose rightmost labels equal ``domain_labels`` and which
        have at least one additional label to the left; that label immediately
        preceding the domain suffix is treated as the username.
      - For a configured domain of "users.zaa" (labels ("users", "zaa")), a
        qname of "zack.users.zaa" yields username "zack".
    """

    text = str(qname or "").rstrip(".").lower()
    if not text:
        return None

    parts = [p for p in text.split(".") if p]
    suffix_len = len(domain_labels)
    if suffix_len == 0:
        return None
    # Need at least one label for the username plus the domain suffix.
    if len(parts) <= suffix_len:
        return None

    # Tail must match the configured domain labels.
    if tuple(parts[-suffix_len:]) != domain_labels:
        return None

    # Username is the label immediately to the left of the domain suffix.
    username_idx = -suffix_len - 1
    username = parts[username_idx].strip()
    return username or None


def _resolve_user_finger_path(username: str) -> Optional[str]:
    """Brief: Resolve the filesystem path to a user's .finger file.

    Inputs:
      - username: System username to resolve via pwd.getpwnam.

    Outputs:
      - str absolute path to ``$HOME/.finger`` when the user exists; otherwise
        a best-effort fallback of ``/home/<username>/.finger`` when no home
        directory is found, or None when no reasonable path can be derived.
    """

    fallback = os.path.join("/home", str(username).strip(), ".finger")

    try:
        pw_entry = pwd.getpwnam(username)
    except KeyError:
        # No passwd entry; fall back to a conventional /home/<user> path and
        # let the caller decide whether the file exists.
        return fallback
    except Exception as exc:  # pragma: no cover - defensive: OS-specific errors
        logger.warning(
            "Finger: failed to resolve passwd entry for %s: %s", username, exc
        )
        return fallback

    home = getattr(pw_entry, "pw_dir", None) or ""
    home = str(home).strip()
    if not home:
        # Missing home directory in passwd entry; fall back to /home/<user>.
        return fallback

    return os.path.join(home, ".finger")


def _normalize_finger_text(text: str) -> str:
    """Brief: Filter .finger content down to printable characters.

    Inputs:
      - text: Raw decoded .finger content as a string.

    Outputs:
      - str: Text containing only printable characters (including Unicode
        characters) plus standard whitespace newlines and tabs; control
        characters such as backspace ("\x08") are removed.
    """

    if not text:
        return ""

    return "".join(ch for ch in text if ch.isprintable() or ch in "\r\n\t")


@plugin_aliases("finger")
class Finger(BasePlugin):
    """Brief: Serve $HOME/.finger contents over TXT DNS queries.

    Inputs:
      - name: Optional plugin instance name.
      - **config: Keyword arguments compatible with FingerConfig.

    Behaviour:
      - Handles TXT queries whose qname matches ``<user>.<domain>`` where
        ``domain`` is configured via the ``domain`` option.
      - When the queried user is allowed and their ``$HOME/.finger`` file is
        readable, the plugin returns a TXT answer containing up to ``max_size``
        bytes from the file (decoded as UTF-8 with replacement on errors).
      - When the user is not allowed, the domain does not match, the qtype is
        not TXT, or the file is missing/unreadable, the plugin returns None so
        normal resolution continues.
    """

    # Restrict this plugin to TXT qtypes by default.
    target_qtypes = ("TXT",)

    @classmethod
    def get_config_model(cls):
        """Brief: Return the Pydantic model used to validate plugin configuration.

        Inputs:
          - None.

        Outputs:
          - FingerConfig class for use by the core config loader.
        """

        return FingerConfig

    def __init__(self, **config: object) -> None:
        """Brief: Initialize Finger plugin and normalize configuration.

        Inputs:
          - **config: Arbitrary keyword configuration compatible with
            FingerConfig (typically provided via YAML/JSON).

        Outputs:
          - None; populates internal policy state used during query handling.
        """

        super().__init__(**config)

        cfg_model = FingerConfig(**self.config)
        domain = cfg_model.domain
        labels = tuple([p for p in domain.split(".") if p])
        if not labels:
            raise ValueError("Finger: domain must contain at least one label")

        raw_location = getattr(cfg_model, "location", None)
        if raw_location is not None:
            self._location_template = str(raw_location).strip() or None
        else:
            self._location_template = None

        self._policy = FingerUserPolicy(
            domain=domain,
            domain_labels=labels,
            max_size=int(cfg_model.max_size),
            policy=str(cfg_model.policy).lower(),
            allow_users=[u.strip().lower() for u in cfg_model.allow_users if u.strip()],
            deny_users=[u.strip().lower() for u in cfg_model.deny_users if u.strip()],
        )

        # TTL for synthesized TXT responses; reuse BasePlugin.ttl default when
        # present but allow config override via "ttl".
        raw_ttl = self.config.get("ttl", getattr(self.__class__, "ttl", 300))
        try:
            self._ttl = int(raw_ttl)
        except Exception:
            self._ttl = 300

    def pre_resolve(
        self,
        qname: str,
        qtype: int,
        req: bytes,
        ctx: PluginContext,
    ) -> Optional[PluginDecision]:
        """Brief: Intercept and answer matching TXT queries with .finger content.

        Inputs:
          - qname: Full query name from the DNS request.
          - qtype: Numeric DNS qtype code.
          - req: Raw DNS request bytes.
          - ctx: PluginContext instance for this request.

        Outputs:
          - PluginDecision("override") with a packed DNS response when this
            plugin serves the query, or None to fall back to normal handling.
        """

        logger.debug(
            "Finger: pre_resolve qname=%s qtype=%s client=%s",
            qname,
            qtype,
            getattr(ctx, "client_ip", None),
        )

        if not self.targets(ctx):
            logger.debug(
                "Finger: skipping non-target client %s for %s %s",
                getattr(ctx, "client_ip", None),
                qname,
                qtype,
            )
            return None

        # Only TXT queries are supported.
        try:
            if int(qtype) != int(QTYPE.TXT):
                logger.debug("Finger: ignoring non-TXT query %s type=%s", qname, qtype)
                return None
        except Exception:  # pragma: no cover - defensive conversion
            logger.debug("Finger: failed to interpret qtype %r for %s", qtype, qname)
            return None

        username = _parse_finger_qname(qname, self._policy.domain_labels)
        if not username:
            logger.debug(
                "Finger: qname %s does not match configured domain suffix %s",
                qname,
                self._policy.domain,
            )
            return None

        allowed = _is_user_allowed_cached(
            username=username.lower(),
            policy=self._policy.policy,
            allow_users=tuple(self._policy.allow_users),
            deny_users=tuple(self._policy.deny_users),
        )
        if not allowed:
            logger.debug(
                "Finger: user %s denied by policy=%s (allow=%s deny=%s)",
                username,
                self._policy.policy,
                self._policy.allow_users,
                self._policy.deny_users,
            )
            return None

        if getattr(self, "_location_template", None):
            path = str(self._location_template).replace("%u", username)
        else:
            path = _resolve_user_finger_path(username)

        if not path or not os.path.isfile(path):
            logger.debug(
                "Finger: no .finger file for user %s (path=%r)",
                username,
                path,
            )
            return None

        try:
            with open(path, "rb") as fh:
                raw = fh.read(self._policy.max_size)
        except OSError as exc:
            logger.warning(
                "Finger: failed reading .finger for user %s at %s: %s",
                username,
                path,
                exc,
            )
            return None

        try:
            text = raw.decode("utf-8", errors="replace") if raw else ""
        except Exception:  # pragma: no cover - defensive decode path
            logger.debug("Finger: decode error for %s at %s", username, path)
            text = ""

        text = _normalize_finger_text(text)

        if not text:
            # Empty content: fall back to normal resolution.
            logger.debug(
                "Finger: empty .finger content for user %s at %s", username, path
            )
            return None

        try:
            request = DNSRecord.parse(req)
        except Exception as exc:  # pragma: no cover - defensive parsing
            logger.warning("Finger: failed to parse request for %s: %s", qname, exc)
            return None

        reply = DNSRecord(
            DNSHeader(id=request.header.id, qr=1, aa=1, ra=1), q=request.q
        )
        reply.add_answer(
            RR(
                rname=request.q.qname,
                rtype=QTYPE.TXT,
                rclass=1,
                ttl=self._ttl,
                rdata=TXT(text),
            )
        )

        logger.debug(
            "Finger: serving TXT answer for user %s from %s (len=%d)",
            username,
            path,
            len(text),
        )

        return PluginDecision(action="override", response=reply.pack())

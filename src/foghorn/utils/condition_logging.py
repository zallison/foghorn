"""Sticky condition logging for flapping backends and endpoints.

Brief:
  - First failure logs WARNING; repeats are DEBUG until a re-warn interval
    elapses, then WARNING again with a suppressed-count suffix.
  - Recovery clears state and optionally logs INFO once.
  - State lives on the owner object (typically a BasePlugin instance).
"""

from __future__ import annotations

import logging
import threading
import time
from typing import Any

DEFAULT_REWARN_INTERVAL_SECONDS = 3600.0


def init_condition_logging(
    owner: Any,
    *,
    rewarn_interval_seconds: float | None = None,
) -> None:
    """Brief: Initialize sticky condition-log lock and maps on *owner*.

    Inputs:
      - owner: Object that will hold condition-log attributes.
      - rewarn_interval_seconds: Optional override; when None, keeps an
        existing owner/class value or DEFAULT_REWARN_INTERVAL_SECONDS.

    Outputs:
      - None.
    """

    owner._condition_log_lock = threading.Lock()
    owner._condition_failed_by_key: dict[str, bool] = {}
    owner._condition_suppressed_by_key: dict[str, int] = {}
    owner._condition_last_warned_by_key: dict[str, float] = {}
    if rewarn_interval_seconds is not None:
        owner._condition_rewarn_interval_seconds = float(rewarn_interval_seconds)
    elif not hasattr(owner, "_condition_rewarn_interval_seconds"):
        owner._condition_rewarn_interval_seconds = float(
            getattr(
                type(owner),
                "_condition_rewarn_interval_seconds",
                DEFAULT_REWARN_INTERVAL_SECONDS,
            )
        )


def ensure_condition_log_state(
    owner: Any,
    *,
    default_rewarn_interval_seconds: float = DEFAULT_REWARN_INTERVAL_SECONDS,
) -> None:
    """Brief: Lazily initialize sticky condition-log lock and maps on *owner*.

    Inputs:
      - owner: Object that will hold condition-log attributes.
      - default_rewarn_interval_seconds: Fallback interval when unset.

    Outputs:
      - None; creates lock/maps when not yet present (e.g. before setup).
    """

    if (
        not hasattr(owner, "_condition_log_lock")
        or getattr(owner, "_condition_log_lock", None) is None
    ):
        owner._condition_log_lock = threading.Lock()
    if (
        not hasattr(owner, "_condition_failed_by_key")
        or getattr(owner, "_condition_failed_by_key", None) is None
    ):
        owner._condition_failed_by_key = {}
    if (
        not hasattr(owner, "_condition_suppressed_by_key")
        or getattr(owner, "_condition_suppressed_by_key", None) is None
    ):
        owner._condition_suppressed_by_key = {}
    if (
        not hasattr(owner, "_condition_last_warned_by_key")
        or getattr(owner, "_condition_last_warned_by_key", None) is None
    ):
        owner._condition_last_warned_by_key = {}
    if not hasattr(owner, "_condition_rewarn_interval_seconds"):
        owner._condition_rewarn_interval_seconds = float(
            getattr(
                type(owner),
                "_condition_rewarn_interval_seconds",
                default_rewarn_interval_seconds,
            )
        )


def resolve_condition_logger(owner: Any) -> logging.Logger:
    """Brief: Logger used for sticky condition messages.

    Inputs:
      - owner: Object that may expose ``logger`` or a defining module.

    Outputs:
      - Logger: owner.logger when set, else logging.getLogger(owner module).
    """

    log = getattr(owner, "logger", None)
    if isinstance(log, logging.Logger):
        return log
    return logging.getLogger(type(owner).__module__)


def note_condition_failure(
    owner: Any,
    key: str,
    message: str,
    *args: object,
    logger: logging.Logger | None = None,
) -> None:
    """Brief: Log sticky-condition failures without flooding loops.

    Inputs:
      - owner: Object holding condition-log state (initialized lazily).
      - key: Stable identifier for the condition (e.g. endpoint URL).
      - message: Log message template for logger.warning().
      - args: Optional %-format arguments for message.
      - logger: Optional explicit logger; defaults via resolve_condition_logger.

    Outputs:
      - None.

    Notes:
      - First failure -> WARNING.
      - Repeats while failed -> DEBUG (count suppressed).
      - After owner._condition_rewarn_interval_seconds -> WARNING reminder.
      - Pair with note_condition_ok on recovery.

    Example:
      note_condition_failure(plugin, "upstream:a", "upstream %s down: %s", "a", exc)
    """

    ensure_condition_log_state(owner)
    now = time.monotonic()
    interval = float(
        getattr(
            owner, "_condition_rewarn_interval_seconds", DEFAULT_REWARN_INTERVAL_SECONDS
        )
    )
    with owner._condition_log_lock:
        prev_failed = bool(owner._condition_failed_by_key.get(key, False))
        last_warned = owner._condition_last_warned_by_key.get(key)
        if prev_failed:
            should_rewarn = interval > 0 and (
                last_warned is None or (now - last_warned) >= interval
            )
            if should_rewarn:
                suppressed = owner._condition_suppressed_by_key.get(key, 0)
                owner._condition_suppressed_by_key[key] = 0
                owner._condition_last_warned_by_key[key] = now
            else:
                owner._condition_suppressed_by_key[key] = (
                    owner._condition_suppressed_by_key.get(key, 0) + 1
                )
                suppressed = owner._condition_suppressed_by_key[key]
        else:
            owner._condition_failed_by_key[key] = True
            owner._condition_suppressed_by_key[key] = 0
            owner._condition_last_warned_by_key[key] = now
            suppressed = 0
            should_rewarn = False

    log = (
        logger
        if isinstance(logger, logging.Logger)
        else resolve_condition_logger(owner)
    )
    if not prev_failed:
        log.warning(message, *args)
        return

    if should_rewarn:
        if suppressed > 0:
            log.warning(
                message + " (still failing; suppressed %d repeated warning(s))",
                *args,
                suppressed,
            )
        else:
            log.warning(message + " (still failing)", *args)
        return

    log.debug(
        "suppressed repeated condition %s (count=%d): " + message,
        key,
        suppressed,
        *args,
    )


def note_condition_ok(
    owner: Any,
    key: str,
    recovery_message: str | None = None,
    *args: object,
    logger: logging.Logger | None = None,
) -> None:
    """Brief: Clear a sticky failure condition and log recovery once.

    Inputs:
      - owner: Object holding condition-log state.
      - key: Same identifier passed to note_condition_failure().
      - recovery_message: Optional logger.info() template.
      - args: Optional %-format arguments for recovery_message.
      - logger: Optional explicit logger; defaults via resolve_condition_logger.

    Outputs:
      - None.

    Example:
      note_condition_ok(plugin, "upstream:a", "upstream %s recovered", "a")
    """

    ensure_condition_log_state(owner)
    with owner._condition_log_lock:
        was_failed = bool(owner._condition_failed_by_key.get(key, False))
        suppressed = int(owner._condition_suppressed_by_key.get(key, 0) or 0)
        owner._condition_failed_by_key[key] = False
        owner._condition_suppressed_by_key[key] = 0
        owner._condition_last_warned_by_key.pop(key, None)

    if not was_failed or not recovery_message:
        return

    log = (
        logger
        if isinstance(logger, logging.Logger)
        else resolve_condition_logger(owner)
    )
    if suppressed > 0:
        log.info(
            recovery_message + " (suppressed %d repeated failure warning(s))",
            *args,
            suppressed,
        )
        return

    if args:
        log.info(recovery_message, *args)
    else:
        log.info("%s", recovery_message)

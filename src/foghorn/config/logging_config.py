from __future__ import annotations

import logging
import logging.handlers
import os
import re
import sys
from datetime import datetime, timezone
from typing import Any, Dict, Optional

_LEVELS = {
    "debug": logging.DEBUG,
    "info": logging.INFO,
    "warn": logging.WARNING,
    "warning": logging.WARNING,
    "error": logging.ERROR,
    "crit": logging.CRITICAL,
    "critical": logging.CRITICAL,
}

# ANSI palette (centralized for easier customization)
ANSI_RESET = "\033[0m"

COLOR_BRIGHT_GREEN = "\033[38;5;10m"
COLOR_BRIGHT_RED = "\033[91m"
COLOR_CYAN = "\033[38;5;14m"
COLOR_DARKER_BLUE = "\033[34m"
COLOR_DARK_CYAN = "\033[36m"
COLOR_DARK_GREEN = "\033[38;5;2m"
COLOR_DARK_GREY = "\033[90m"
COLOR_DARK_YELLOW = "\033[38;5;11m"
COLOR_LIGHT_GREY = "\033[38;5;250m"
COLOR_PURPLE = "\033[35m"

COLOR_IP_PORT = COLOR_DARK_CYAN
COLOR_KV_KEY = COLOR_DARK_GREEN
COLOR_KV_SEPARATOR = COLOR_LIGHT_GREY
COLOR_KV_VALUE = COLOR_DARK_YELLOW
COLOR_PLUGIN = COLOR_PURPLE
COLOR_QUOTED = COLOR_DARKER_BLUE

COLOR_INFO = COLOR_DARK_GREEN
COLOR_WARN = COLOR_DARK_YELLOW
COLOR_ERROR = COLOR_BRIGHT_RED
COLOR_CRITICAL = COLOR_PURPLE


class SyslogFormatter(logging.Formatter):
    """Formatter for syslog output without timestamps (syslog adds its own)."""

    _TAGS = {
        logging.DEBUG: "[debug]",
        logging.INFO: "[info]",
        logging.WARNING: "[warn]",
        logging.ERROR: "[error]",
        logging.CRITICAL: "[crit]",
    }

    def format(self, record):
        """Add level_tag attribute and format without timestamp."""
        record.level_tag = self._TAGS.get(record.levelno, f"[lvl{record.levelno}]")
        return f"{record.level_tag} {record.name}: {record.getMessage()}"


class BracketLevelFormatter(logging.Formatter):
    """Custom formatter that adds bracketed lowercase level tags and UTC timestamps."""

    _TAGS = {
        logging.DEBUG: "[debug]",
        logging.INFO: "[info]",
        logging.WARNING: "[warn]",
        logging.ERROR: "[error]",
        logging.CRITICAL: "[crit]",
    }
    _RESET = ANSI_RESET
    _LEVEL_COLORS = {
        logging.DEBUG: COLOR_DARK_CYAN,
        logging.INFO: COLOR_INFO,
        logging.WARNING: COLOR_WARN,
        logging.ERROR: COLOR_ERROR,
        logging.CRITICAL: COLOR_CRITICAL,
    }
    _LOGGER_NAME_PREFIXES = (
        "foghorn.plugins.",
        "foghorn.plugin.",
        "foghorn.",
    )
    _LOGGER_NAME_COLOR = COLOR_DARKER_BLUE
    _DATE_TIME_COLOR = COLOR_BRIGHT_GREEN
    _TZ_SEPARATOR_COLOR = COLOR_LIGHT_GREY
    _KV_KEY_COLOR = COLOR_KV_KEY
    _KV_EQUALS_COLOR = COLOR_KV_SEPARATOR
    _KV_VALUE_COLOR = COLOR_KV_VALUE
    _BRACKET_GRAY_COLOR = COLOR_DARK_GREY
    _PAREN_DARK_CYAN_COLOR = COLOR_DARK_CYAN
    _DOCKER_LONG_ID_COLOR = COLOR_DARK_GREY
    _IP_COLOR = COLOR_IP_PORT
    _PORT_COLOR = COLOR_IP_PORT
    _DOCKER_CONTAINER_ID_PATTERN = re.compile(
        r"(?P<short>[0-9a-fA-F]{12})\[(?P<long>[0-9a-fA-F]{12,})\]$"
    )
    _SHA1_ID_PATTERN = re.compile(
        r"(?P<short>[0-9a-fA-F]{6})(?P<long>[0-9a-fA-F]{12,})$"
    )
    _HIGHLIGHT_PATTERN = re.compile(
        r"(?P<kv>\b[A-Za-z_][\w.-]*=[^\s,;]+)"
        r"|(?P<date>\b\d{4}-\d{2}-\d{2}\b)"
        #        r"|(?P<ip>\b(https?://)?(?:25[0-5]|2[0-4]\d|1?\d?\d)(?:\.(?:25[0-5]|2[0-4]\d|1?\d?\d)){3}(?::\d{1,5})?\b)"
        r"|(?P<ip>((https?|tcp|smb|ftp)?://)?(?:www\.)?[-a-zA-Z0-9@:%._+~#=]{1,256}\.[a-zA-Z0-9()]{1,6}\b(?:[-a-zA-Z0-9()@:%_+.~#?&//=]*))"
        r"|(?P<bracket>\[[^\[\]\n]*\])"
        r"|(?P<paren>\([^()\n]*\))"
        r"|(?P<plugin_context>\b(?:plugin|pkugin)\s+[A-Za-z0-9_.-]+)"
        r'|(?P<quoted_double>"[^"\n]*")'
        r"|(?P<quoted_single>'[^'\n]*')"
        r"|(?P<hostname>(?<!/)\b(?:[A-Za-z0-9-]+\.)+[A-Za-z]{2,}\b)"
        r"|(?P<path>(?<!\S)(?:[.~]|/)[\w./-]+(?:\:\d+)?)"
        r"|(?P<plugin>\b[A-Z][A-Za-z0-9]+(?:[A-Z][A-Za-z0-9]+)+\b)"
        r"|(?P<error>\b(?:[A-Z_]+_[A-Z_]+|E\d{2,5}|ERR_[A-Z0-9_]+|[45]\d{2})\b)"
    )
    _TOKEN_COLORS = {
        "url": COLOR_IP_PORT,
        "date": COLOR_BRIGHT_GREEN,
        "quoted_double": COLOR_QUOTED,
        "quoted_single": COLOR_QUOTED,
        "hostname": COLOR_IP_PORT,
        "path": COLOR_BRIGHT_GREEN,
        "plugin": COLOR_PLUGIN,
        "error": COLOR_ERROR,
    }

    def __init__(self, *args, color: bool = False, **kwargs):
        """Initialize formatter.

        Inputs:
          - args/kwargs: Standard logging.Formatter constructor args.
          - color: Enable ANSI color rendering for level tags and key tokens.

        Outputs:
          - None
        """
        super().__init__(*args, **kwargs)
        self._color = bool(color)

    def formatTime(self, record, datefmt=None):
        """Format time as UTC ISO-8601 with Z suffix."""
        timestamp = datetime.fromtimestamp(record.created, timezone.utc).strftime(
            "%Y-%m-%dT%H:%M:%SZ"
        )
        if not self._color:
            return timestamp
        date_part = timestamp[:10]
        time_part = timestamp[11:19]
        return (
            f"{self._DATE_TIME_COLOR}{date_part}{self._RESET}"
            f"{self._TZ_SEPARATOR_COLOR}T{self._RESET}"
            f"{self._DATE_TIME_COLOR}{time_part}{self._RESET}"
            f"{self._TZ_SEPARATOR_COLOR}Z{self._RESET}"
        )

    def _apply_color(self, text: str, ansi_color: str) -> str:
        """Wrap text in ANSI color escape sequences when color mode is enabled."""
        if not self._color or not text:
            return text
        return f"{ansi_color}{text}{self._RESET}"

    def _highlight_message(self, message: str) -> str:
        """Highlight hostnames, file-like paths, and common error/status codes."""
        if not self._color or not message:
            return message
        return self._HIGHLIGHT_PATTERN.sub(self._replace_match, message)

    def _color_delimiters(self, text: str, base_color: str | None = None) -> str:
        """Color bracket/paren delimiters while preserving interior text.

        Inputs:
          - text: Raw text that may contain square and/or round brackets.
          - base_color: Optional ANSI color to apply to non-bracket characters.

        Outputs:
          - str: Text with colorized delimiters and optionally colored non-delimiter text.
        """
        delimiter_colors = {
            "[": self._BRACKET_GRAY_COLOR,
            "]": self._BRACKET_GRAY_COLOR,
            "(": self._PAREN_DARK_CYAN_COLOR,
            ")": self._PAREN_DARK_CYAN_COLOR,
        }
        parts: list[str] = []
        if base_color:
            parts.append(base_color)
        for ch in text:
            if ch in delimiter_colors:
                if base_color:
                    parts.append(self._RESET)
                parts.append(f"{delimiter_colors[ch]}{ch}{self._RESET}")
                if base_color:
                    parts.append(base_color)
            else:
                parts.append(ch)
        if base_color:
            parts.append(self._RESET)
        return "".join(parts)

    def _color_kv_value(self, value: str) -> str:
        """Colorize a key=value value segment.

        Inputs:
          - value: Value side of a key=value token.

        Outputs:
          - str: Colorized value string.
        """
        docker_match = self._DOCKER_CONTAINER_ID_PATTERN.match(value)
        if docker_match:
            short_id = docker_match.group("short")
            long_id = docker_match.group("long")
            return (
                f"{self._KV_VALUE_COLOR}{short_id}{self._RESET}"
                f"{self._BRACKET_GRAY_COLOR} [{self._RESET}"
                f"{self._DOCKER_LONG_ID_COLOR}{long_id}{self._RESET}"
                f"{self._BRACKET_GRAY_COLOR}]{self._RESET}"
            )

        sha1_match = self._SHA1_ID_PATTERN.match(value)
        if sha1_match:
            short_id = sha1_match.group("short")
            long_id = sha1_match.group("long")
            return (
                f"{self._KV_VALUE_COLOR}{short_id}{self._RESET}"
                f"{self._BRACKET_GRAY_COLOR} [{self._RESET}"
                f"{self._DOCKER_LONG_ID_COLOR}{long_id}{self._RESET}"
                f"{self._BRACKET_GRAY_COLOR}]{self._RESET}"
            )

        if len(value) >= 2 and value[0] == "[" and value[-1] == "]":
            inner = value[1:-1]
            return (
                f"{self._BRACKET_GRAY_COLOR}[{self._RESET}"
                f"{self._color_kv_value(inner)}"
                f"{self._BRACKET_GRAY_COLOR}]{self._RESET}"
            )

        if len(value) >= 2 and value[0] == "(" and value[-1] == ")":
            inner = value[1:-1]
            return (
                f"{self._PAREN_DARK_CYAN_COLOR}({self._RESET}"
                f"{self._color_kv_value(inner)}"
                f"{self._PAREN_DARK_CYAN_COLOR}){self._RESET}"
            )
        ip_port_match = re.match(
            r"^(?P<ip>(?:25[0-5]|2[0-4]\d|1?\d?\d)(?:\.(?:25[0-5]|2[0-4]\d|1?\d?\d)){3})(?::(?P<port>\d{1,5}))?$",
            value,
        )
        if ip_port_match:
            return self._color_ip_with_optional_port(value)
        if len(value) >= 2 and (
            (value[0] == "'" and value[-1] == "'")
            or (value[0] == '"' and value[-1] == '"')
        ):
            return f"{COLOR_QUOTED}{value}{self._RESET}"

        # key=value takes precedence over inner paren/bracket highlighting.
        return self._color_delimiters(value, base_color=self._KV_VALUE_COLOR)

    def _color_ip_with_optional_port(self, text: str) -> str:
        """Colorize IPv4 and IPv4:port where port should be yellow.

        Inputs:
          - text: Candidate IPv4 or IPv4:port token.

        Outputs:
          - str: Colorized token when parseable; otherwise original text.
        """
        ip_text, sep, port_text = text.partition(":")
        if not sep:
            return f"{self._IP_COLOR}{ip_text}{self._RESET}"
        return (
            f"{self._IP_COLOR}{ip_text}{self._RESET}"
            f"{self._IP_COLOR}:{self._RESET}"
            f"{self._PORT_COLOR}{port_text}{self._RESET}"
        )

    def _replace_match(self, match: re.Match[str]) -> str:
        """Apply color by token category for a regex match."""
        token_type = match.lastgroup
        token_text = match.group(0)
        if not token_type:
            return token_text
        if token_type == "kv":
            key, equals, value = token_text.partition("=")
            if not equals:
                return token_text
            return (
                f"{self._KV_KEY_COLOR}{key}{self._RESET}"
                f"{self._KV_EQUALS_COLOR}{equals}{self._RESET}"
                f"{self._color_kv_value(value)}"
            )
        if token_type == "ip":
            return self._color_ip_with_optional_port(token_text)
        if token_type == "bracket":
            inner = token_text[1:-1]
            highlighted_inner = self._HIGHLIGHT_PATTERN.sub(self._replace_match, inner)
            return (
                f"{self._BRACKET_GRAY_COLOR}[{self._RESET}"
                f"{highlighted_inner}"
                f"{self._BRACKET_GRAY_COLOR}]{self._RESET}"
            )
        if token_type == "paren":
            inner = token_text[1:-1]
            highlighted_inner = self._HIGHLIGHT_PATTERN.sub(self._replace_match, inner)
            return (
                f"{self._PAREN_DARK_CYAN_COLOR}({self._RESET}"
                f"{highlighted_inner}"
                f"{self._PAREN_DARK_CYAN_COLOR}){self._RESET}"
            )
        if token_type == "plugin_context":
            prefix, _, plugin_name = token_text.rpartition(" ")
            if not plugin_name:
                return token_text
            plugin_color = self._TOKEN_COLORS.get("plugin")
            if not plugin_color:
                return token_text
            return f"{prefix} {plugin_color}{plugin_name}{self._RESET}"
        ansi_color = self._TOKEN_COLORS.get(token_type)
        if not ansi_color:
            return token_text
        return f"{ansi_color}{token_text}{self._RESET}"

    def _shorten_logger_name(self, logger_name: str) -> str:
        """Shorten foghorn logger names by stripping known package prefixes.

        Inputs:
          - logger_name: Fully-qualified logger name.

        Outputs:
          - str: Display-friendly logger name.
        """
        for prefix in self._LOGGER_NAME_PREFIXES:
            if logger_name.startswith(prefix):
                shortened_name = logger_name[len(prefix) :]
                if shortened_name:
                    return shortened_name
        return logger_name

    def format(self, record):
        """Add level_tag attribute and format the record."""
        level_tag = self._TAGS.get(record.levelno, f"[lvl{record.levelno}]")
        original_msg = record.msg
        original_args = record.args
        original_name = record.name
        try:
            record.level_tag = self._apply_color(
                level_tag, self._LEVEL_COLORS.get(record.levelno, "\033[37m")
            )
            record.msg = self._highlight_message(record.getMessage())
            record.name = self._apply_color(
                self._shorten_logger_name(record.name), self._LOGGER_NAME_COLOR
            )
            record.args = ()
            return super().format(record)
        finally:
            record.msg = original_msg
            record.args = original_args
            record.name = original_name


def init_logging(cfg: Optional[Dict[str, Any]]) -> None:
    """
    Initialize logging configuration based on the provided config.

    Args:
        cfg: Logging configuration dictionary with optional keys:
            - level: debug, info, warn, error, crit (default: info)
            - stderr: boolean to log to stderr (default: True)
            - color: boolean to colorize stderr output (default: True)
            - file: string path to log file (optional)
            - syslog: boolean or dict to enable syslog logging (optional)
                Can be a boolean (True uses defaults) or a dict with:
                - address: Unix socket path (default: /dev/log) or (host, port) tuple
                - facility: syslog facility (default: USER)
                - tag: program identifier to prepend (default: foghorn)

    Example config:
        {
            'level': 'info',
            'stderr': True,
            'color': True,
            'file': './foghorn.log',
            'syslog': True  # or {'address': '/dev/log', 'tag': 'foghorn'}
        }
    """
    cfg = cfg or {}

    # Map string level to logging constant
    level_str = str(cfg.get("level", "info")).lower()
    level = _LEVELS.get(level_str, logging.INFO)

    # Toggle ANSI colors for stderr output (default-on), regardless of TTY.
    color_enabled = bool(cfg.get("color", True))

    # Create formatter with bracketed tags and UTC timestamps
    fmt = "%(asctime)s %(level_tag)s %(name)s: %(message)s"
    formatter = BracketLevelFormatter(fmt=fmt, color=color_enabled)
    plain_formatter = BracketLevelFormatter(fmt=fmt, color=False)

    # Configure root logger
    root = logging.getLogger()
    root.setLevel(level)

    # Remove existing handlers to avoid duplicates
    for h in list(root.handlers):
        root.removeHandler(h)

    # Add stderr handler if requested (default: True)
    if cfg.get("stderr", True):
        stderr_handler = logging.StreamHandler(sys.stderr)
        stderr_handler.setFormatter(formatter)
        root.addHandler(stderr_handler)

    # Add file handler if specified
    file_path = cfg.get("file")
    if isinstance(file_path, str) and file_path.strip():
        path = os.path.abspath(os.path.expanduser(file_path.strip()))
        # Create parent directories if they don't exist
        os.makedirs(os.path.dirname(path), exist_ok=True)
        file_handler = logging.FileHandler(path, mode="a", encoding="utf-8")
        file_handler.setFormatter(plain_formatter)
        root.addHandler(file_handler)

    # Add syslog handler if requested
    syslog_cfg = cfg.get("syslog")
    if syslog_cfg:
        try:
            syslog_formatter = SyslogFormatter()

            # Parse syslog configuration
            if isinstance(syslog_cfg, dict):
                address = syslog_cfg.get("address", "/dev/log")
                facility = getattr(
                    logging.handlers.SysLogHandler,
                    f"LOG_{syslog_cfg.get('facility', 'USER').upper()}",
                    logging.handlers.SysLogHandler.LOG_USER,
                )
            else:
                # syslog_cfg is True, use defaults
                address = "/dev/log"
                facility = logging.handlers.SysLogHandler.LOG_USER

            # Create syslog handler
            syslog_handler = logging.handlers.SysLogHandler(
                address=address, facility=facility
            )
            syslog_handler.setFormatter(syslog_formatter)
            root.addHandler(syslog_handler)
        except (
            OSError,
            ValueError,
        ) as e:  # pragma: no cover - defensive: low-value edge case or environment-specific behaviour that is hard to test reliably
            # Fall back gracefully if syslog is not available
            root.warning(f"Failed to configure syslog: {e}")

    # Capture warnings to use the same logging configuration
    logging.captureWarnings(True)

from __future__ import annotations

import logging
import logging.handlers
import os
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

    def formatTime(self, record, datefmt=None):
        """Format time as UTC ISO-8601 with Z suffix."""
        return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    def format(self, record):
        """Add level_tag attribute and format the record."""
        record.level_tag = self._TAGS.get(record.levelno, f"[lvl{record.levelno}]")
        return super().format(record)


def init_logging(cfg: Optional[Dict[str, Any]]) -> None:
    """
    Initialize logging configuration based on the provided config.

    Args:
        cfg: Logging configuration dictionary with optional keys:
            - level: debug, info, warn, error, crit (default: info)
            - stderr: boolean to log to stderr (default: True)
            - file: string path to log file (optional)
            - syslog: boolean or dict to enable syslog logging (optional)
                Can be a boolean (True uses defaults) or a dict with:
                - address: Unix socket path (default: /dev/log) or (host, port) tuple
                - facility: syslog facility (default: USER)
                - tag: program identifier to prepend (default: foghorn)

    Example config:
        {
            "level": "info",
            "stderr": True,
            "file": "./foghorn.log",
            "syslog": True  # or {"address": "/dev/log", "tag": "foghorn"}
        }
    """
    cfg = cfg or {}

    # Map string level to logging constant
    level_str = str(cfg.get("level", "info")).lower()
    level = _LEVELS.get(level_str, logging.INFO)

    # Create formatter with bracketed tags and UTC timestamps
    fmt = "%(asctime)s %(level_tag)s %(name)s: %(message)s"
    formatter = BracketLevelFormatter(fmt=fmt)

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
        file_handler.setFormatter(formatter)
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

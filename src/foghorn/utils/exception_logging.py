"""Helpers for intentionally suppressed exceptions.

Prefer these over bare ``except Exception: pass`` so failures remain visible
in logs without aborting the caller.
"""

from __future__ import annotations

import logging
import sys
from collections.abc import Callable
from typing import TypeVar

T = TypeVar("T")

_DEFAULT_LOGGER_NAME = "foghorn"


def warn_suppressed_exception(
    message: str,
    *args: object,
    logger: logging.Logger | None = None,
    logger_name: str = _DEFAULT_LOGGER_NAME,
) -> None:
    """Brief: Log a suppressed except-block failure, then continue.

    Inputs:
      - message: printf-style warning text describing what failed.
      - args: Interpolation values for ``message``.
      - logger: Optional logger instance; defaults to ``logging.getLogger(logger_name)``.
      - logger_name: Logger name used when ``logger`` is omitted.

    Outputs:
      - None.

    Notes:
      - Call from an ``except`` block. Logs exception type/message only — no
        traceback (suppressed paths should stay quiet in operator logs).
      - Use instead of bare ``pass`` when swallowing errors on cleanup,
        best-effort side effects, or non-fatal helper paths.

    Example:
      >>> try:
      ...     risky()
      ... except Exception:
      ...     warn_suppressed_exception("risky cleanup failed for id=%s", item_id)
    """
    log = (
        logger
        if logger is not None
        else logging.getLogger(str(logger_name or _DEFAULT_LOGGER_NAME))
    )
    exc = sys.exc_info()[1]
    if exc is not None:
        log.warning(message + " (%s: %s)", *args, type(exc).__name__, exc)
    else:
        log.warning(message, *args)


def call_warn_on_exception(
    description: str,
    fn: Callable[[], T],
    *,
    default: T | None = None,
    logger: logging.Logger | None = None,
    logger_name: str = _DEFAULT_LOGGER_NAME,
) -> T | None:
    """Brief: Run ``fn()``; on any exception log a warning and return ``default``.

    Inputs:
      - description: Short label for the failed operation (logged as \"%s failed\").
      - fn: Zero-arg callable to invoke.
      - default: Value returned when ``fn`` raises.
      - logger / logger_name: Logging destination (see ``warn_suppressed_exception``).

    Outputs:
      - Result of ``fn`` on success, otherwise ``default``.
    """
    try:
        return fn()
    except Exception:
        warn_suppressed_exception(
            "%s failed",
            description,
            logger=logger,
            logger_name=logger_name,
        )
        return default

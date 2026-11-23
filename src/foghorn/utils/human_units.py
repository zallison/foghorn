"""Parse human-readable byte sizes and durations for config fields.

Brief:
  Coerces ints/floats/strings into canonical units used by Foghorn:
  bytes (int) and seconds (float). SI prefixes use 1000; IEC (Ki/Mi/…) use 1024.
  Time strings are **durations only** (not wall-clock times).

Inputs:
  - parse_bytes(value): number or size string (e.g. 4096, \"4M\", \"256KiB\").
  - parse_duration_seconds(value): number or duration string
    (e.g. 15, \"2 days\", \"1h30m\", \"12:00:00\").

Outputs:
  - int bytes or float seconds.

Examples:
  >>> parse_bytes(\"4MB\")
  4000000
  >>> parse_bytes(\"4MiB\")
  4194304
  >>> parse_duration_seconds(\"1h30m\")
  5400.0
  >>> parse_duration_seconds(\"01:30:00\")
  5400.0
"""

from __future__ import annotations

import math
import re
from typing import Any

# SI: 1000^n — IEC: 1024^n
_SI_BYTE_UNITS: dict[str, int] = {
    "b": 1,
    "byte": 1,
    "bytes": 1,
    "k": 1000,
    "kb": 1000,
    "kilobyte": 1000,
    "kilobytes": 1000,
    "m": 1000**2,
    "mb": 1000**2,
    "megabyte": 1000**2,
    "megabytes": 1000**2,
    "g": 1000**3,
    "gb": 1000**3,
    "gigabyte": 1000**3,
    "gigabytes": 1000**3,
    "t": 1000**4,
    "tb": 1000**4,
    "terabyte": 1000**4,
    "terabytes": 1000**4,
    "p": 1000**5,
    "pb": 1000**5,
}

_IEC_BYTE_UNITS: dict[str, int] = {
    "ki": 1024,
    "kib": 1024,
    "kibibyte": 1024,
    "kibibytes": 1024,
    "mi": 1024**2,
    "mib": 1024**2,
    "mebibyte": 1024**2,
    "mebibytes": 1024**2,
    "gi": 1024**3,
    "gib": 1024**3,
    "gibibyte": 1024**3,
    "gibibytes": 1024**3,
    "ti": 1024**4,
    "tib": 1024**4,
    "tebibyte": 1024**4,
    "tebibytes": 1024**4,
    "pi": 1024**5,
    "pib": 1024**5,
}

_BYTE_UNIT_RE = re.compile(
    r"""
    ^\s*
    (?P<num>[+-]?(?:\d+(?:\.\d*)?|\.\d+)(?:[eE][+-]?\d+)?)
    \s*
    (?P<unit>[a-zA-Z]*)
    \s*$
    """,
    re.VERBOSE,
)

# Token duration: 1h30m15s, 2 days, 500ms, …
_DURATION_TOKEN_RE = re.compile(
    r"""
    (?P<num>[+-]?(?:\d+(?:\.\d*)?|\.\d+)(?:[eE][+-]?\d+)?)
    \s*
    (?P<unit>
        # Longest unit spellings first so "minutes" does not match "m".
        milliseconds?|millis?|ms
        |microseconds?|us|µs
        |nanoseconds?|ns
        |seconds?|secs?|s
        |minutes?|mins?|m
        |hours?|hrs?|h
        |days?|d
        |weeks?|w
    )?
    """,
    re.VERBOSE | re.IGNORECASE,
)

_DURATION_UNITS_SECONDS: dict[str, float] = {
    "ns": 1e-9,
    "nanosecond": 1e-9,
    "nanoseconds": 1e-9,
    "us": 1e-6,
    "µs": 1e-6,
    "microsecond": 1e-6,
    "microseconds": 1e-6,
    "ms": 1e-3,
    "milli": 1e-3,
    "millis": 1e-3,
    "millisecond": 1e-3,
    "milliseconds": 1e-3,
    "s": 1.0,
    "sec": 1.0,
    "secs": 1.0,
    "second": 1.0,
    "seconds": 1.0,
    "m": 60.0,
    "min": 60.0,
    "mins": 60.0,
    "minute": 60.0,
    "minutes": 60.0,
    "h": 3600.0,
    "hr": 3600.0,
    "hrs": 3600.0,
    "hour": 3600.0,
    "hours": 3600.0,
    "d": 86400.0,
    "day": 86400.0,
    "days": 86400.0,
    "w": 604800.0,
    "week": 604800.0,
    "weeks": 604800.0,
}

# Duration clock forms: H:MM[:SS[.frac]] or MM:SS[.frac] (elapsed, not wall clock).
_CLOCK_DURATION_RE = re.compile(
    r"""
    ^\s*
    (?P<a>\d+)
    :
    (?P<b>\d{1,2})
    (?:
        :
        (?P<c>\d{1,2}(?:\.\d+)?)
    )?
    \s*$
    """,
    re.VERBOSE,
)


def _as_finite_number(value: Any, *, what: str) -> float:
    """Brief: Coerce bool-rejected numeric input to float.

    Inputs:
      - value: int/float (bool rejected).
      - what: Label for error messages.

    Outputs:
      - float.

    Raises:
      - TypeError / ValueError on invalid input.
    """

    if isinstance(value, bool):
        raise TypeError(f"{what} must be a number or string, not bool")
    if isinstance(value, (int, float)):
        num = float(value)
        if not math.isfinite(num):
            raise ValueError(f"{what} must be finite, got {value!r}")
        return num
    raise TypeError(f"{what} must be a number or string, got {type(value).__name__}")


def parse_bytes(value: Any) -> int:
    """Brief: Parse a byte size to a non-negative int.

    Inputs:
      - value: int/float bytes, or string with optional SI/IEC unit
        (``4M``/``4MB`` = 4e6 SI; ``4MiB`` = 4 * 1024**2 IEC).

    Outputs:
      - int byte count (truncated toward zero from fractional inputs).

    Raises:
      - TypeError / ValueError when the value cannot be parsed or is negative.
    """

    if value is None:
        raise TypeError("byte size must not be None")

    if not isinstance(value, str):
        num = _as_finite_number(value, what="byte size")
        if num < 0:
            raise ValueError(f"byte size must be >= 0, got {value!r}")
        return int(num)

    text = value.strip()
    if not text:
        raise ValueError("byte size string must not be empty")

    # Underscore thousands separators in the numeric part only.
    match = _BYTE_UNIT_RE.match(text.replace("_", ""))
    if not match:
        raise ValueError(f"invalid byte size {value!r}")

    num = float(match.group("num"))
    if not math.isfinite(num):
        raise ValueError(f"byte size must be finite, got {value!r}")
    if num < 0:
        raise ValueError(f"byte size must be >= 0, got {value!r}")

    unit_raw = match.group("unit") or ""
    unit = unit_raw.strip().lower()
    if not unit:
        return int(num)

    if unit in _IEC_BYTE_UNITS:
        scale = _IEC_BYTE_UNITS[unit]
    elif unit in _SI_BYTE_UNITS:
        scale = _SI_BYTE_UNITS[unit]
    else:
        raise ValueError(
            f"unknown byte unit {unit_raw!r} in {value!r}; "
            "use SI (kB/MB/GB) or IEC (KiB/MiB/GiB)"
        )
    return int(num * scale)


def _parse_clock_duration(text: str) -> float | None:
    """Brief: Parse H:MM[:SS] or MM:SS duration; None if not a clock form.

    Inputs:
      - text: Stripped duration candidate.

    Outputs:
      - float seconds, or None when the string is not clock-shaped.

    Raises:
      - ValueError when clock-shaped but components are out of range.
    """

    match = _CLOCK_DURATION_RE.match(text)
    if not match:
        return None

    a = int(match.group("a"))
    b = int(match.group("b"))
    c_raw = match.group("c")

    if c_raw is not None:
        # H:MM:SS[.frac]
        hours, minutes, seconds = a, b, float(c_raw)
        if minutes >= 60 or seconds >= 60:
            raise ValueError(f"invalid duration clock {text!r} (MM/SS out of range)")
        if hours < 0 or minutes < 0 or seconds < 0:
            raise ValueError(f"duration must be >= 0, got {text!r}")
        return float(hours * 3600 + minutes * 60 + seconds)

    # MM:SS — if first field looks like hours (>=60) still treat as minutes:seconds
    # only when b is a valid seconds field.
    minutes, seconds = a, float(b)
    if seconds >= 60:
        raise ValueError(f"invalid duration clock {text!r} (SS out of range)")
    if minutes < 0 or seconds < 0:
        raise ValueError(f"duration must be >= 0, got {text!r}")
    return float(minutes * 60 + seconds)


def parse_duration_seconds(value: Any) -> float:
    """Brief: Parse a duration to seconds (duration-only; not wall-clock).

    Inputs:
      - value: int/float seconds, or string such as ``90``, ``1h30m``,
        ``2 days``, ``500ms``, ``12:00:00`` (elapsed H:MM:SS).

    Outputs:
      - float seconds (may be fractional).

    Raises:
      - TypeError / ValueError when the value cannot be parsed or is negative.
    """

    if value is None:
        raise TypeError("duration must not be None")

    if not isinstance(value, str):
        num = _as_finite_number(value, what="duration")
        if num < 0:
            raise ValueError(f"duration must be >= 0, got {value!r}")
        return float(num)

    text = value.strip()
    if not text:
        raise ValueError("duration string must not be empty")

    # Pure number string.
    try:
        pure = float(text.replace("_", ""))
    except ValueError:
        pure = None
    if pure is not None and re.fullmatch(
        r"[+-]?(?:\d+(?:\.\d*)?|\.\d+)(?:[eE][+-]?\d+)?", text.replace("_", "")
    ):
        if not math.isfinite(pure):
            raise ValueError(f"duration must be finite, got {value!r}")
        if pure < 0:
            raise ValueError(f"duration must be >= 0, got {value!r}")
        return float(pure)

    clock = _parse_clock_duration(text)
    if clock is not None:
        return clock

    total = 0.0
    pos = 0
    matched_any = False
    # Allow separators: whitespace, commas, "and"
    scrubbed = re.sub(r"[,]|(\band\b)", " ", text, flags=re.IGNORECASE)
    for match in _DURATION_TOKEN_RE.finditer(scrubbed):
        # Ensure we only skip whitespace between tokens.
        gap = scrubbed[pos : match.start()]
        if gap.strip():
            raise ValueError(f"invalid duration {value!r}")
        pos = match.end()
        matched_any = True
        num = float(match.group("num"))
        unit_raw = match.group("unit")
        if unit_raw is None or not str(unit_raw).strip():
            # Bare number token only valid if it is the entire string (handled above)
            # or as seconds when other tokens exist? Require explicit unit for multi.
            raise ValueError(
                f"duration component {match.group(0)!r} in {value!r} needs a unit"
            )
        unit = str(unit_raw).strip().lower()
        scale = _DURATION_UNITS_SECONDS.get(unit)
        if scale is None:
            raise ValueError(f"unknown duration unit {unit_raw!r} in {value!r}")
        total += num * scale

    if not matched_any or scrubbed[pos:].strip():
        raise ValueError(f"invalid duration {value!r}")

    if not math.isfinite(total):
        raise ValueError(f"duration must be finite, got {value!r}")
    if total < 0:
        raise ValueError(f"duration must be >= 0, got {value!r}")
    return float(total)


def parse_duration_seconds_int(value: Any) -> int:
    """Brief: Parse a duration to whole seconds (rounded).

    Inputs:
      - value: Same as parse_duration_seconds.

    Outputs:
      - int seconds (round half away from zero via round()).
    """

    return int(round(parse_duration_seconds(value)))


def _unit_kind_for_key(key: str) -> str | None:
    """Brief: Classify a config key as bytes, seconds, or milliseconds.

    Inputs:
      - key: Mapping key name.

    Outputs:
      - "bytes" | "seconds" | "milliseconds" | None.
    """

    k = str(key or "").strip().lower()
    if not k:
        return None
    # Byte *rates* still store a byte magnitude (e.g. 1M means 1e6 B/s).
    if k.endswith("_bytes_per_second") or k.endswith("_bytes_per_sec"):
        return "bytes"
    if k.endswith("_bytes") or k.endswith("_byte") or k == "max_bytes":
        return "bytes"
    if k.endswith("_seconds") or k.endswith("_secs"):
        return "seconds"
    if k.endswith("_milliseconds") or k.endswith("_ms"):
        return "milliseconds"
    return None


def _coerce_leaf_unit(key: str, value: Any, *, path: str) -> Any:
    """Brief: Coerce one leaf value when its key implies size/duration units.

    Inputs:
      - key: Parent mapping key.
      - value: Leaf value (None left unchanged).
      - path: Dotted path for error messages.

    Outputs:
      - Coerced value, or original when the key is not unit-typed.

    Raises:
      - ValueError when a unit-typed value cannot be parsed.
    """

    if value is None:
        return None
    kind = _unit_kind_for_key(key)
    if kind is None:
        return value
    try:
        if kind == "bytes":
            return parse_bytes(value)
        if kind == "seconds":
            return parse_duration_seconds(value)
        if kind == "milliseconds":
            if isinstance(value, (int, float)) and not isinstance(value, bool):
                # Bare numbers on *_ms keys stay milliseconds (legacy).
                num = float(value)
                if not math.isfinite(num) or num < 0:
                    raise ValueError(f"duration must be >= 0, got {value!r}")
                return int(num) if isinstance(value, int) or num.is_integer() else num
            # Human duration strings → milliseconds.
            secs = parse_duration_seconds(value)
            ms = secs * 1000.0
            return int(ms) if ms.is_integer() else ms
    except (TypeError, ValueError) as exc:
        raise ValueError(f"invalid {kind} value at {path}: {exc}") from exc
    return value


def coerce_config_human_units(obj: Any, *, path: str = "<root>") -> Any:
    """Brief: Recursively coerce human size/duration leaves in a config tree.

    Inputs:
      - obj: Config mapping/list/scalar (typically the full YAML root dict).
      - path: Path prefix for error messages.

    Outputs:
      - The same object graph, mutated in-place for dict/list containers, with
        unit-typed leaves replaced by canonical numbers.

    Notes:
      - Skips top-level ``variables`` / ``vars`` maps (interpolation sources).
      - Keys matching ``*_bytes`` / ``max_bytes`` / ``*_bytes_per_second`` → bytes.
      - Keys matching ``*_seconds`` → seconds (duration-only strings allowed).
      - Keys matching ``*_ms`` / ``*_milliseconds`` → ms (bare numbers stay ms;
        duration strings are converted from seconds).

    Raises:
      - ValueError when a unit-typed leaf cannot be parsed.
    """

    if isinstance(obj, dict):
        for key, val in list(obj.items()):
            key_s = str(key)
            child_path = f"{path}.{key_s}" if path != "<root>" else key_s
            # Do not rewrite variable tables; values are reused for interpolation.
            if path == "<root>" and key_s in {"variables", "vars"}:
                continue
            if isinstance(val, (dict, list)):
                coerce_config_human_units(val, path=child_path)
            else:
                obj[key] = _coerce_leaf_unit(key_s, val, path=child_path)
        return obj

    if isinstance(obj, list):
        for idx, item in enumerate(obj):
            child_path = f"{path}[{idx}]"
            if isinstance(item, (dict, list)):
                coerce_config_human_units(item, path=child_path)
            # list scalars inherit no key name — leave unchanged
        return obj

    return obj

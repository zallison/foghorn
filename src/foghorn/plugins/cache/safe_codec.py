from __future__ import annotations

import base64
import json
from typing import Any

RAW_BYTES_FLAG = 0
SAFE_SERIALIZED_FLAG = 2


def _to_jsonable(value: Any) -> Any:
    """Brief: Convert supported Python objects into JSON-safe tagged values.

    Inputs:
      - value: Supported object tree containing primitives, bytes, tuples,
        lists, and dictionaries.

    Outputs:
      - Any JSON-serializable tagged structure.
    """

    if value is None or isinstance(value, (bool, int, float, str)):
        return value

    if isinstance(value, (bytes, bytearray, memoryview)):
        return {
            "__foghorn_type__": "bytes",
            "b64": base64.b64encode(bytes(value)).decode("ascii"),
        }

    if isinstance(value, tuple):
        return {
            "__foghorn_type__": "tuple",
            "items": [_to_jsonable(item) for item in value],
        }

    if isinstance(value, list):
        return [_to_jsonable(item) for item in value]

    if isinstance(value, dict):
        return {
            "__foghorn_type__": "dict",
            "items": [[_to_jsonable(k), _to_jsonable(v)] for k, v in value.items()],
        }

    raise TypeError(
        f"Unsupported cache value type for safe serialization: {type(value)!r}"
    )


def _from_jsonable(value: Any) -> Any:
    """Brief: Decode JSON-safe tagged values back into Python objects.

    Inputs:
      - value: Tagged JSON-compatible structure.

    Outputs:
      - Decoded Python value.
    """

    if value is None or isinstance(value, (bool, int, float, str)):
        return value

    if isinstance(value, list):
        return [_from_jsonable(item) for item in value]

    if isinstance(value, dict):
        kind = value.get("__foghorn_type__")
        if kind == "bytes":
            encoded = value.get("b64")
            if not isinstance(encoded, str):
                raise ValueError("Invalid safe bytes payload")
            return base64.b64decode(encoded.encode("ascii"))

        if kind == "tuple":
            raw_items = value.get("items")
            if not isinstance(raw_items, list):
                raise ValueError("Invalid safe tuple payload")
            return tuple(_from_jsonable(item) for item in raw_items)

        if kind == "dict":
            raw_items = value.get("items")
            if not isinstance(raw_items, list):
                raise ValueError("Invalid safe dict payload")
            out: dict[Any, Any] = {}
            for item in raw_items:
                if not isinstance(item, list) or len(item) != 2:
                    raise ValueError("Invalid safe dict item payload")
                out[_from_jsonable(item[0])] = _from_jsonable(item[1])
            return out

        return {str(k): _from_jsonable(v) for k, v in value.items()}

    raise ValueError("Unsupported JSON payload in safe cache decoder")


def safe_serialize(value: Any) -> bytes:
    """Brief: Serialize cache payloads without executable object deserialization.

    Inputs:
      - value: Supported Python value.

    Outputs:
      - bytes JSON payload suitable for storage in external cache backends.
    """

    return json.dumps(
        _to_jsonable(value), separators=(",", ":"), sort_keys=True
    ).encode("utf-8")


def safe_deserialize(payload: bytes) -> Any:
    """Brief: Deserialize a safe JSON payload produced by safe_serialize().

    Inputs:
      - payload: UTF-8 JSON bytes from cache storage.

    Outputs:
      - Decoded Python value.
    """

    decoded = json.loads(bytes(payload).decode("utf-8"))
    return _from_jsonable(decoded)

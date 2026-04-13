"""SQL safety helpers for validated identifier and placeholder composition.

Inputs:
  - Called by SQL-backed plugin modules before composing SQL that must include
    identifiers (for example table names) or driver-specific placeholders.

Outputs:
  - Validated identifier strings and group-by column mappings safe to embed
    into SQL text after value parameters are still bound separately.
"""

from __future__ import annotations

import re
from collections.abc import Collection, Mapping

_SQL_IDENTIFIER_PATTERN = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")

DEFAULT_QUERY_LOG_GROUP_BY_COLUMNS: dict[str, str] = {
    "client_ip": "client_ip",
    "qtype": "qtype",
    "qname": "name",
    "rcode": "rcode",
}


def validate_sql_identifier(
    identifier: object,
    *,
    field_name: str = "identifier",
    max_length: int = 63,
) -> str:
    """Brief: Validate an SQL identifier used in interpolated SQL text.

    Inputs:
      - identifier: Candidate identifier value (must be a non-empty string).
      - field_name: Human-readable field label used in ValueError messages.
      - max_length: Maximum permitted identifier length.

    Outputs:
      - str: Trimmed identifier validated against /^[A-Za-z_][A-Za-z0-9_]*$/.
    """

    if not isinstance(identifier, str):
        raise ValueError(f"{field_name} must be a string")

    value = identifier.strip()
    if not value:
        raise ValueError(f"{field_name} must be a non-empty string")

    if len(value) > int(max_length):
        raise ValueError(
            f"{field_name} must be <= {int(max_length)} characters (got {len(value)})"
        )

    if not _SQL_IDENTIFIER_PATTERN.fullmatch(value):
        raise ValueError(
            f"{field_name} must match ^[A-Za-z_][A-Za-z0-9_]*$; got {value!r}"
        )

    return value


def validate_sql_placeholder(
    placeholder: object,
    *,
    allowed_placeholders: Collection[str],
) -> str:
    """Brief: Validate a driver placeholder token used in SQL templates.

    Inputs:
      - placeholder: Candidate placeholder token (for example '%s' or '?').
      - allowed_placeholders: Collection of permitted placeholder tokens.

    Outputs:
      - str: Validated placeholder token.
    """

    if not isinstance(placeholder, str):
        raise ValueError("placeholder must be a string")

    token = placeholder.strip()
    allowed = {str(item).strip() for item in allowed_placeholders if str(item).strip()}
    if token not in allowed:
        allowed_sorted = ", ".join(sorted(allowed))
        raise ValueError(
            f"placeholder must be one of [{allowed_sorted}]; got {token!r}"
        )
    return token


def resolve_query_log_group_column(
    group_by: object,
    *,
    mapping: Mapping[str, str] | None = None,
) -> tuple[str | None, str | None]:
    """Brief: Resolve and validate an optional query-log aggregation group column.

    Inputs:
      - group_by: Requested grouping key from API input.
      - mapping: Optional key-to-column mapping override.

    Outputs:
      - tuple[str | None, str | None]:
          - Resolved SQL column name when group_by is allowlisted, else None.
          - Normalized group-by label when resolved, else None.
    """

    if group_by is None:
        return None, None

    requested = str(group_by).strip().lower()
    if not requested:
        return None, None

    lookup = mapping if mapping is not None else DEFAULT_QUERY_LOG_GROUP_BY_COLUMNS
    column = lookup.get(requested)
    if column is None:
        return None, None

    validated = validate_sql_identifier(
        column,
        field_name="group_by SQL column",
        max_length=63,
    )
    return validated, requested

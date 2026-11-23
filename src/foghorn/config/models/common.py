"""Shared Pydantic helpers for Foghorn configuration models.

Inputs:
  - Used by section models under foghorn.config.models.

Outputs:
  - MetaFields base and common field types for schema generation.
"""

from __future__ import annotations

from typing import Annotated, Any

from pydantic import BaseModel, BeforeValidator, ConfigDict, Field, StringConstraints

from foghorn.utils.human_units import (
    parse_bytes,
    parse_duration_seconds,
    parse_duration_seconds_int,
)

# Identifier-style names for vars keys and similar.
IdentifierName = Annotated[str, StringConstraints(pattern=r"^[A-Za-z_][A-Za-z0-9_]*$")]

PortInt = Annotated[int, Field(ge=1, le=65535)]

# Human-readable size/duration input → canonical int/float at validation time.
# SI: MB=1000**2; IEC: MiB=1024**2. Durations only (not wall-clock).
BytesInt = Annotated[int, BeforeValidator(parse_bytes)]
SecondsFloat = Annotated[float, BeforeValidator(parse_duration_seconds)]
SecondsInt = Annotated[int, BeforeValidator(parse_duration_seconds_int)]


class MetaFields(BaseModel):
    """Brief: Optional comment/id metadata allowed on config objects.

    Inputs:
      - comment: Optional human-readable note (max 254 chars).
      - id: Optional stable identifier string (max 254 chars).

    Outputs:
      - MetaFields instance used as a base for core config objects.
    """

    comment: str | None = Field(
        default=None,
        max_length=254,
        description="Optional human metadata string (max 254 characters).",
    )
    id: str | None = Field(
        default=None,
        max_length=254,
        description="Optional human metadata string (max 254 characters).",
    )


class StrictModel(MetaFields):
    """Brief: Object model that forbids unknown keys (additionalProperties=false).

    Inputs:
      - Inherits comment/id from MetaFields plus subclass fields.

    Outputs:
      - Base for strict core config sections.
    """

    model_config = ConfigDict(extra="forbid")


class OpenModel(MetaFields):
    """Brief: Object model that allows unknown keys (additionalProperties=true).

    Inputs:
      - Inherits comment/id from MetaFields plus subclass fields.

    Outputs:
      - Base for intentionally free-form maps only (e.g. opaque backend blobs).

    Notes:
      - Prefer StrictModel for operator-facing config objects so unknown keys fail
        validation. Keep OpenModel rare.
    """

    model_config = ConfigDict(extra="allow")


class EmptyOpenObject(OpenModel):
    """Brief: Permissive object placeholder for truly free-form nested maps.

    Inputs:
      - Arbitrary keys (opaque plugin/backend payloads).

    Outputs:
      - Open mapping; avoid for structured sections — use StrictModel instead.
    """

    model_config = ConfigDict(extra="allow")


def schema_extra_forbid() -> dict[str, Any]:
    """Brief: JSON-schema hint helper (reserved for generator post-process).

    Inputs:
      - None.

    Outputs:
      - Empty dict; kept for future shared schema tweaks.
    """

    return {}

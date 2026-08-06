"""Variables block models for Foghorn configuration.

Inputs:
  - Top-level vars mapping of identifier names to arbitrary values.

Outputs:
  - VarsConfig model used by FoghornConfig and schema generation.
"""

from __future__ import annotations

from typing import Any

from pydantic import ConfigDict, Field

from foghorn.config.models.common import StrictModel


class VarsConfig(StrictModel):
    """Brief: Optional top-level vars expanded before validation.

    Inputs:
      - Dynamic identifier keys (pattern ^[A-Za-z_][A-Za-z0-9_]*$) with arbitrary
        JSON/YAML values. Known only at runtime; modeled as an open root with
        additionalProperties for Phase 0, tightened in generator if needed.

    Outputs:
      - VarsConfig instance.

    Notes:
      - Runtime strips vars before applying most schema checks. Editors still
        need the key present on the root schema.
    """

    # Pydantic cannot express patternProperties alone easily for free-form
    # values; allow extra keys here and let the generator annotate
    # patternProperties on the emitted schema.
    model_config = ConfigDict(extra="allow")

    def model_dump_values(self) -> dict[str, Any]:
        """Brief: Return vars payload excluding metadata fields.

        Inputs:
          - None (uses model fields/extras).

        Outputs:
          - Dict of variable name -> value.
        """

        data = self.model_dump(exclude_none=True)
        data.pop("comment", None)
        data.pop("id", None)
        return data


# Alias used in docs/legacy wording.
VariablesConfig = VarsConfig

# Field description reused by root model.
VARS_DESCRIPTION = (
    "Optional mapping of variable names to arbitrary values. "
    "These are expanded before validation and removed from the runtime config."
)

vars_field = Field(
    default=None,
    description=VARS_DESCRIPTION,
)

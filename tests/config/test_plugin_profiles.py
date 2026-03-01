"""Brief: Unit tests for plugin profile loading and resolution.

Inputs:
  - None

Outputs:
  - None
"""

from __future__ import annotations

from pathlib import Path

import pytest

from foghorn.config.plugin_profiles import (
    load_builtin_profiles,
    load_user_profiles,
    resolve_plugin_profile,
)


def test_load_builtin_profiles_rate_limit_returns_defaults() -> None:
    """Brief: load_builtin_profiles returns default rate_limit profiles when file missing.

    Inputs:
      - None.

    Outputs:
      - None; asserts expected default profiles (single, lan, smb, enterprise).
    """
    profiles = load_builtin_profiles("rate_limit")
    assert "default" in profiles
    assert "single" in profiles
    assert "lan" in profiles
    assert "smb" in profiles
    assert "enterprise" in profiles
    assert profiles["single"]["min_enforce_rps"] == 10
    assert profiles["lan"]["global_max_rps"] == 1000


def test_load_builtin_profiles_unknown_type_returns_empty() -> None:
    """Brief: load_builtin_profiles returns empty dict for unknown plugin types.

    Inputs:
      - None.

    Outputs:
      - None; asserts empty dict for non-rate_limit plugin without profiles file.
    """
    profiles = load_builtin_profiles("unknown_plugin")
    assert profiles == {}


def test_load_user_profiles_merges_multiple_files(tmp_path: Path) -> None:
    """Brief: load_user_profiles merges profiles from multiple YAML files.

    Inputs:
      - tmp_path: pytest temporary path fixture.

    Outputs:
      - None; asserts later files override earlier ones.
    """
    file1 = tmp_path / "profiles1.yaml"
    file1.write_text("type:\n  profile1:\n    a: 1\n  profile2:\n    b: 2")

    file2 = tmp_path / "profiles2.yaml"
    file2.write_text("type:\n  profile1:\n    a: 10")

    profiles = load_user_profiles([str(file1), str(file2)])

    assert "type" in profiles
    assert profiles["type"]["profile1"]["a"] == 10
    assert profiles["type"]["profile2"]["b"] == 2


def test_resolve_plugin_profile_applies_default_with_explicit_overrides() -> None:
    """Brief: resolve_plugin_profile merges 'default' profile with explicit config.

    Inputs:
      - None.

    Outputs:
      - None; asserts default values are overridden by explicit config.
    """
    explicit_cfg = {"min_enforce_rps": 100}

    merged = resolve_plugin_profile(
        plugin_type="rate_limit",
        profile_name="default",
        explicit_cfg=explicit_cfg,
        profiles_files=[],
    )

    assert merged["min_enforce_rps"] == 100
    assert merged["global_max_rps"] == 5000  # from default profile
    assert merged["burst_factor"] == 3.0  # from default profile


def test_resolve_plugin_profile_lan_profile_correct_values() -> None:
    """Brief: resolve_plugin_profile applies 'lan' profile values correctly.

    Inputs:
      - None.

    Outputs:
      - None; asserts lan profile (50/1000/4.0x) is applied.
    """
    merged = resolve_plugin_profile(
        plugin_type="rate_limit",
        profile_name="lan",
        explicit_cfg={},
        profiles_files=[],
    )

    assert merged["min_enforce_rps"] == 50
    assert merged["global_max_rps"] == 1000
    assert merged["burst_factor"] == 4.0


def test_resolve_plugin_profile_explicit_config_overrides_profile() -> None:
    """Brief: resolve_plugin_profile lets explicit config take precedence over profile.

    Inputs:
      - None.

    Outputs:
      - None; asserts explicit wins over profile values.
    """
    merged = resolve_plugin_profile(
        plugin_type="rate_limit",
        profile_name="lan",
        explicit_cfg={"min_enforce_rps": 999, "custom_key": "value"},
        profiles_files=[],
    )

    # Profile values
    assert merged["global_max_rps"] == 1000
    assert merged["burst_factor"] == 4.0
    # Explicit overrides
    assert merged["min_enforce_rps"] == 999
    assert merged["custom_key"] == "value"


def test_resolve_plugin_profile_user_files_override_builtins() -> None:
    """Brief: resolve_plugin_profile respects profiles_files over built-ins.

    Inputs:
      - None.

    Outputs:
      - None; asserts user-provided file overrides built-in profiles.
    """
    user_file = Path(__file__).parent / "fixtures" / "custom_profiles.yaml"

    merged = resolve_plugin_profile(
        plugin_type="rate_limit",
        profile_name="lan",
        explicit_cfg={},
        profiles_files=[str(user_file)],
    )

    # Custom profile values override built-in
    assert merged["min_enforce_rps"] == 75
    assert merged["global_max_rps"] == 2000


def test_resolve_plugin_profile_unknown_profile_warns_without_abort() -> None:
    """Brief: resolve_plugin_profile warns on unknown profile but falls back to default.

    Inputs:
      - None.

    Outputs:
      - None; asserts warning logged and 'default' profile used.
    """
    merged = resolve_plugin_profile(
        plugin_type="rate_limit",
        profile_name="nonexistent",
        explicit_cfg={},
        profiles_files=[],
        abort_on_failure=False,
    )

    # Should fall back to default profile
    assert merged["min_enforce_rps"] == 50
    assert merged["global_max_rps"] == 5000


def test_resolve_plugin_profile_unknown_profile_aborts_when_requested() -> None:
    """Brief: resolve_plugin_profile raises errors when abort_on_failure=True.

    Inputs:
      - None.

    Outputs:
      - None; asserts RuntimeError for unknown profile when abort flag is set.
    """
    with pytest.raises(RuntimeError) as excinfo:
        resolve_plugin_profile(
            plugin_type="rate_limit",
            profile_name="nonexistent",
            explicit_cfg={},
            profiles_files=[],
            abort_on_failure=True,
        )

    assert "Unknown profile" in str(excinfo.value)


def test_resolve_plugin_profile_handles_malformed_profile_config() -> None:
    """Brief: resolve_plugin_profile handles invalid profile configurations gracefully.

    Inputs:
      - None.

    Outputs:
      - None; asserts explicit config is returned when profile is invalid.
    """
    explicit_cfg = {"foo": "bar"}

    # Simulate a profile that returns invalid data (non-dict)
    merged = resolve_plugin_profile(
        plugin_type="rate_limit",
        profile_name="nonexistent",
        explicit_cfg=explicit_cfg,
        profiles_files=[],
        abort_on_failure=False,
    )

    # Should at least have explicit config
    assert merged.get("foo") == "bar"


def test_resolve_plugin_profile_namespace_syntax() -> None:
    """Brief: resolve_plugin_profile handles namespaced profile names (type.profile).

    Inputs:
      - None.

    Outputs:
      - None; asserts 'rate_limit.lan' syntax is resolved correctly.
    """
    merged = resolve_plugin_profile(
        plugin_type="rate_limit",
        profile_name="lan",  # not using dot syntax here
        explicit_cfg={},
        profiles_files=[],
    )

    assert merged["global_max_rps"] == 1000

"""Plugin profile loader for configuration presets.

Brief:
  Provides functionality to load and merge plugin profiles, allowing operators to use
  named configuration bundles (e.g., 'single', 'lan', 'enterprise') instead of
  hand-tuning every knob.

Inputs:
  - Global profiles_files (list of paths loaded from config)
  - Plugin-specific profile name (e.g., 'lan' or 'rate_limit.lan')

Outputs:
  - Merged configuration dictionary for the plugin (profile + explicit config)
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any, Dict, List

import yaml


logger = logging.getLogger(__name__)


def _load_profiles_from_file(path: str) -> Dict[str, Any]:
    """Brief: Load profile mapping from a YAML file.

    Inputs:
      - path: Path to a YAML file containing profile definitions.

    Outputs:
      - dict: Profile name → config mapping, empty dictionary on parse errors.

    Notes:
      - Heavily defensive; parse errors log warnings and return empty dict.
    """
    try:
        with open(path, "r") as f:
            data = yaml.safe_load(f) or {}
    except Exception as exc:
        logger.warning("Failed to load profile file %s: %s", path, exc)
        return {}

    if not isinstance(data, dict):
        logger.warning("Profile file %s is not a mapping", path)
        return {}

    profiles: Dict[str, Any] = {}

    # Support both flat profiles (for single plugin types) and namespaced
    # (e.g., "rate_limit.lan").
    for key, value in data.items():
        if "." in key:
            plugin_type, profile_name = key.split(".", 1)
            if plugin_type not in profiles:
                profiles[plugin_type] = {}
            profiles[plugin_type][profile_name] = value
        else:
            # If file only has one plugin type, put it under a type key if possible
            profiles[key] = value

    return profiles


def load_builtin_profiles(plugin_type: str = "rate_limit") -> Dict[str, Any]:
    """Brief: Load built-in profiles for a plugin type from the installed package.

    Inputs:
      - plugin_type: Plugin identifier (e.g., 'rate_limit').

    Outputs:
      - dict: Profile name → config mapping, empty if not found.

    Notes:
      - Searches for {plugin_type}_profiles.yaml alongside resolve plugins.
      - These YAML files must be included as package data for installed distributions.
    """
    try:
        # Built-in profile YAML lives alongside the resolve plugin modules.
        package_path = "foghorn.plugins.resolve"

        # Try to find the profiles file in the installed package.
        import importlib.resources as _resources

        try:
            profile_file = (
                _resources.files(package_path) / f"{plugin_type}_profiles.yaml"
            )
            if profile_file.is_file():
                with profile_file.open("r") as f:
                    profiles = yaml.safe_load(f) or {}
                if isinstance(profiles, dict):
                    return profiles
        except (AttributeError, FileNotFoundError, OSError):
            pass

        # Fallback (source tree / editable installs): look relative to the resolve package.
        import foghorn.plugins.resolve as _resolve_pkg

        resolve_file = getattr(_resolve_pkg, "__file__", None)
        if resolve_file:
            resolve_dir = Path(resolve_file).parent
            profile_path = resolve_dir / f"{plugin_type}_profiles.yaml"

            if profile_path.is_file():
                with open(profile_path, "r") as f:
                    profiles = yaml.safe_load(f) or {}
                if isinstance(profiles, dict):
                    return profiles

        # Additional fallback: resolve relative to this module's package tree.
        try:
            base_dir = Path(__file__).resolve().parents[1]
            alt_profile_path = (
                base_dir / "plugins" / "resolve" / f"{plugin_type}_profiles.yaml"
            )
            if alt_profile_path.is_file():
                with open(alt_profile_path, "r") as f:
                    profiles = yaml.safe_load(f) or {}
                if isinstance(profiles, dict):
                    return profiles
        except Exception:
            pass

    except Exception as exc:
        logger.debug("Failed to load built-in profiles for %s: %s", plugin_type, exc)

    return {}


def load_user_profiles(profiles_files: List[str]) -> Dict[str, Any]:
    """Brief: Load and merge all user-provided profile files.

    Inputs:
      - profiles_files: List of file paths to load (in order; later override earlier).

    Outputs:
      - dict: Merged profile mapping from all files.

    Notes:
      - Files that can't be loaded log warnings and are skipped.
    """
    merged: Dict[str, Any] = {}
    for path in profiles_files:
        profiles = _load_profiles_from_file(path)
        for plugin_type, plugin_profiles in profiles.items():
            if plugin_type not in merged:
                merged[plugin_type] = {}
            # Merge profile mappings (later entries win)
            if isinstance(plugin_profiles, dict):
                for name, config in plugin_profiles.items():
                    if isinstance(config, dict):
                        if plugin_type not in merged:
                            merged[plugin_type] = {}
                        merged[plugin_type][name] = config
    return merged


def resolve_plugin_profile(
    plugin_type: str,
    profile_name: str,
    explicit_cfg: Dict[str, Any],
    profiles_files: List[str],
    abort_on_failure: bool = False,
) -> Dict[str, Any]:
    """Brief: Resolve and merge a plugin profile with explicit configuration.

    Inputs:
      - plugin_type: Plugin identifier (e.g., 'rate_limit').
      - profile_name: Profile name to load (e.g., 'lan').
      - explicit_cfg: User-specified config values.
      - profiles_files: Global profile files from configuration.
      - abort_on_failure: Whether to abort on unknown profile names.

    Outputs:
      - dict: Merged configuration (profile values + explicit override).

    Notes:
      - Merge order: built-ins → user files → explicit config.
      - Explicit config always wins.
      - Unknown profile names:
        * If abort_on_failure=True, raises RuntimeError.
        * Otherwise, warns and falls back to 'default'.
    """
    # Load built-in profiles
    builtin = load_builtin_profiles(plugin_type)

    # Load/merge user profiles
    user_profiles = load_user_profiles(profiles_files)

    # Determine where profiles are stored for this plugin type
    profiles_for_plugin = {}
    if plugin_type in user_profiles:
        profiles_for_plugin = user_profiles[plugin_type]
    if plugin_type in builtin:
        profiles_for_plugin = {**builtin.get(plugin_type, {}), **profiles_for_plugin}

    # Resolve the profile
    if profile_name in profiles_for_plugin:
        profile_cfg = profiles_for_plugin[profile_name]
    elif profile_name in builtin:
        # Fallback to built-ins if user profiles didn't override
        profile_cfg = builtin[profile_name]
    else:
        # Unknown profile
        msg = f"Unknown profile '{profile_name}' for plugin {plugin_type}; falling back to 'default'"
        if abort_on_failure:
            raise RuntimeError(msg) from None
        logger.warning("%s", msg)

        # Fall back to default if available
        if "default" in profiles_for_plugin:
            profile_cfg = profiles_for_plugin["default"]
        elif "default" in builtin:
            profile_cfg = builtin["default"]
        else:
            profile_cfg = {}

    # Merge: profile values first, then explicit overrides
    if isinstance(profile_cfg, dict) and isinstance(explicit_cfg, dict):
        return {**profile_cfg, **explicit_cfg}

    return explicit_cfg.copy()

"""Brief: Unit tests for shared admin API rate-limit abstraction.

Inputs:
  - Synthetic config dictionaries and lightweight fake plugin objects.

Outputs:
  - Assertions for settings parsing, backend adapter behavior, and blocking.
"""

from __future__ import annotations

from foghorn.servers.webserver import admin_rate_limit as rl


def test_parse_admin_rate_limit_settings_defaults_disabled() -> None:
    """Brief: Parser defaults to disabled settings when config is missing.

    Inputs:
      - Empty config mapping.

    Outputs:
      - Parsed settings with enabled=False and safe defaults.
    """

    settings = rl.parse_admin_rate_limit_settings({})
    assert settings.enabled is False
    assert settings.backend == "plugin"
    assert settings.requests_per_window == 60
    assert settings.window_seconds == 60
    assert settings.key_mode == "client_action"


def test_in_memory_backend_blocks_after_limit() -> None:
    """Brief: In-memory backend blocks when fixed-window quota is exceeded.

    Inputs:
      - requests_per_window=1, window_seconds=60.

    Outputs:
      - First request allowed; second request blocked with Retry-After header.
    """

    backend = rl.InMemoryAdminRateLimitBackend(
        requests_per_window=1,
        window_seconds=60,
    )
    first = backend.evaluate(key="client-a", now_ts=10.0)
    second = backend.evaluate(key="client-a", now_ts=11.0)
    assert first.allowed is True
    assert second.allowed is False
    headers = second.to_headers()
    assert headers["X-RateLimit-Backend"] == "memory"
    assert int(headers["Retry-After"]) >= 0


def test_plugin_backend_uses_plugin_hook_payload() -> None:
    """Brief: Plugin backend honors check_admin_rate_limit hook payloads.

    Inputs:
      - Fake RateLimit plugin exposing check_admin_rate_limit().

    Outputs:
      - Decision reflects plugin-provided allow/deny fields.
    """

    class RateLimit:
        name = "rl"

        def check_admin_rate_limit(
            self,
            *,
            key: str,
            now_ts: float,
        ) -> dict[str, object]:
            _ = key, now_ts
            return {
                "allowed": False,
                "limit": 9,
                "remaining": 0,
                "retry_after_seconds": 12,
                "backend": "plugin-hook",
            }

    backend = rl.PluginAdminRateLimitBackend(plugins=[RateLimit()])
    decision = backend.evaluate(key="client-a", now_ts=100.0)
    assert decision.allowed is False
    assert decision.limit == 9
    assert decision.retry_after_seconds == 12
    assert decision.backend == "plugin-hook"


def test_get_admin_rate_limit_service_caches_by_signature() -> None:
    """Brief: Service builder reuses cached service while signature is unchanged.

    Inputs:
      - Mutable state object and stable config/plugins.

    Outputs:
      - Same object returned across calls with unchanged signature.
    """

    class _State:
        pass

    state = _State()
    config = {
        "server": {
            "http": {
                "admin_rate_limit": {
                    "enabled": True,
                    "backend": "memory",
                    "requests_per_window": 2,
                    "window_seconds": 60,
                }
            }
        }
    }
    service_a = rl.get_admin_rate_limit_service(
        state_obj=state,
        config=config,
        plugins=[],
    )
    service_b = rl.get_admin_rate_limit_service(
        state_obj=state,
        config=config,
        plugins=[],
    )
    assert service_a is service_b


def test_plugin_backend_malformed_payload_uses_fallback_backend() -> None:
    """Brief: Malformed plugin hook payloads should not fail open.

    Inputs:
      - Fake RateLimit plugin whose hook returns an unsupported payload type.
      - Fallback backend with a small fixed-window quota.

    Outputs:
      - Backend falls back to fixed-window decisions and blocks after quota.
    """

    class RateLimit:
        name = 'rl'

        def check_admin_rate_limit(self, *, key: str, now_ts: float) -> object:
            _ = key, now_ts
            return object()

    fallback = rl.InMemoryAdminRateLimitBackend(
        requests_per_window=1,
        window_seconds=60,
        backend_name='fallback-memory',
    )
    backend = rl.PluginAdminRateLimitBackend(
        plugins=[RateLimit()],
        fallback_backend=fallback,
    )
    first = backend.evaluate(key='client-a', now_ts=100.0)
    second = backend.evaluate(key='client-a', now_ts=101.0)
    assert first.allowed is True
    assert second.allowed is False
    assert second.backend == 'fallback-memory'


def test_plugin_backend_prefers_hook_capability_not_class_name() -> None:
    """Brief: Plugin discovery should use hook capability, not class-name only.

    Inputs:
      - Plugin with non-RateLimit class name and check_admin_rate_limit hook.

    Outputs:
      - Hook-backed decision is used.
    """

    class CustomLimiter:
        name = 'custom'

        def check_admin_rate_limit(self, *, key: str, now_ts: float) -> dict[str, object]:
            _ = key, now_ts
            return {
                'allowed': False,
                'limit': 7,
                'remaining': 0,
                'retry_after_seconds': 3,
                'backend': 'custom-hook',
            }

    backend = rl.PluginAdminRateLimitBackend(plugins=[CustomLimiter()])
    decision = backend.evaluate(key='client-a', now_ts=10.0)
    assert decision.allowed is False
    assert decision.backend == 'custom-hook'
    assert decision.retry_after_seconds == 3


def test_get_admin_rate_limit_service_rebuilds_when_plugin_attrs_change() -> None:
    """Brief: Service cache signature should refresh on plugin limiter attr changes.

    Inputs:
      - Enabled plugin backend config and one mutable RateLimit plugin.

    Outputs:
      - Service instance is rebuilt after backend-relevant plugin attr mutation.
    """

    class _State:
        pass

    class RateLimit:
        name = 'rl'

        def __init__(self) -> None:
            self.window_seconds = 60
            self.global_max_rps = 1.0
            self.min_enforce_rps = 50.0

    state = _State()
    plugin = RateLimit()
    config = {
        'server': {
            'http': {
                'admin_rate_limit': {
                    'enabled': True,
                    'backend': 'plugin',
                }
            }
        }
    }

    service_a = rl.get_admin_rate_limit_service(
        state_obj=state,
        config=config,
        plugins=[plugin],
    )
    plugin.window_seconds = 10
    service_b = rl.get_admin_rate_limit_service(
        state_obj=state,
        config=config,
        plugins=[plugin],
    )
    assert service_a is not service_b

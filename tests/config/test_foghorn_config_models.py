"""Brief: Unit tests for foghorn.config.models without writing schema files.

Inputs:
  - None; constructs FoghornConfig and nested models in-memory.

Outputs:
  - Assertions on required fields, defaults, and JSON Schema emission basics.
"""

from __future__ import annotations

from foghorn.config.models import FoghornConfig, UpstreamHost
from foghorn.config.models.server import EcsFeatureConfig, ServerConfig
from foghorn.config.models.upstreams import UpstreamsConfig, UpstreamsHealth


def test_foghorn_config_requires_server() -> None:
    """Brief: FoghornConfig requires a server block.

    Inputs:
      - None.

    Outputs:
      - None; asserts model_json_schema lists server as required.
    """

    schema = FoghornConfig.model_json_schema(mode="validation")
    assert "server" in schema.get("required", [])


def test_foghorn_config_accepts_minimal_server() -> None:
    """Brief: Empty server mapping is a valid FoghornConfig.

    Inputs:
      - None.

    Outputs:
      - None; constructs FoghornConfig(server={}) successfully.
    """

    cfg = FoghornConfig(server=ServerConfig())
    assert cfg.server is not None
    assert cfg.upstreams is None


def test_ecs_feature_defaults() -> None:
    """Brief: ECS feature model exposes expected defaults and bounds.

    Inputs:
      - None.

    Outputs:
      - None; asserts key defaults on EcsFeatureConfig.
    """

    ecs = EcsFeatureConfig()
    assert ecs.enabled is False
    assert ecs.source_prefix_v4 == 24
    assert ecs.source_prefix_v6 == 56
    assert ecs.trusted_listeners == []


def test_upstreams_health_and_host_defaults() -> None:
    """Brief: Upstream health and host models carry documented defaults.

    Inputs:
      - None.

    Outputs:
      - None; asserts health probe defaults and host transport default.
    """

    health = UpstreamsHealth()
    assert health.max_serv_fail == 3
    assert health.probe_percent == 1.0

    host = UpstreamHost(host="1.1.1.1")
    assert host.port == 53
    assert host.transport == "udp"

    ups = UpstreamsConfig(endpoints=[host])
    assert ups.strategy == "failover"
    assert ups.max_concurrent == 1

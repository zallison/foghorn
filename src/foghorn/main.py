from __future__ import annotations
import importlib
import sys
import argparse
from typing import List
import yaml

from .server import DNSServer
from .plugins.base import BasePlugin


def load_plugins(plugin_specs: List[dict]) -> List[BasePlugin]:
    plugins: List[BasePlugin] = []
    for spec in plugin_specs or []:
        module_path = spec.get("module")
        config = spec.get("config", {})
        if not module_path:
            continue
        # module_path is full dotted path to class
        module_name, class_name = module_path.rsplit(".", 1)
        mod = importlib.import_module(module_name)
        cls = getattr(mod, class_name)
        plugin = cls(**config)
        plugins.append(plugin)
    return plugins


def main(argv: List[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Caching DNS server with plugins")
    parser.add_argument("--config", default="config.yaml", help="Path to YAML config")
    args = parser.parse_args(argv)

    with open(args.config, "r") as f:
        cfg = yaml.safe_load(f) or {}

    listen = cfg.get("listen", {})
    host = listen.get("host", "127.0.0.1")
    port = int(listen.get("port", 5353))

    upstream = cfg.get("upstream", {})
    up_host = upstream.get("host", "1.1.1.1")
    up_port = int(upstream.get("port", 53))
    timeout_ms = int(upstream.get("timeout_ms", 2000))

    plugins = load_plugins(cfg.get("plugins", []))

    server = DNSServer(host, port, (up_host, up_port), plugins, timeout=timeout_ms/1000.0)
    print(f"DNS cache server listening on {host}:{port}, upstream {up_host}:{up_port}")
    server.serve_forever()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

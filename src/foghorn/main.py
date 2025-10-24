from __future__ import annotations
import importlib
import sys
import argparse
import logging
from typing import List
import yaml
from unittest.mock import patch, mock_open

from .server import DNSServer
from .plugins.base import BasePlugin
from .logging_config import init_logging


def load_plugins(plugin_specs: List[dict]) -> List[BasePlugin]:
    """
    Loads and initializes plugins from a list of plugin specifications.

    Supports either full dotted class paths or short aliases:
    - access_control | acl -> foghorn.plugins.access_control.AccessControlPlugin
    - new_domain_filter | new_domain -> foghorn.plugins.new_domain_filter.NewDomainFilterPlugin
    - upstream_router | router -> foghorn.plugins.upstream_router.UpstreamRouterPlugin

    Args:
        plugin_specs: A list where each item is either a dict with keys
                      {"module": <path-or-alias>, "config": {...}} or a string
                      alias/dotted path.

    Returns:
        A list of initialized plugin instances.

    Example use:
        >>> from foghorn.plugins.base import BasePlugin
        >>> class MyTestPlugin(BasePlugin):
        ...     pass
        >>> specs = [{"module": "__main__.MyTestPlugin"}]
        >>> plugins = load_plugins(specs)
        >>> isinstance(plugins[0], MyTestPlugin)
        True
        >>> # Using aliases
        >>> plugins = load_plugins(["acl", {"module": "router", "config": {}}])
    """
    aliases = {
        "access_control": "foghorn.plugins.access_control.AccessControlPlugin",
        "acl": "foghorn.plugins.access_control.AccessControlPlugin",
        "new_domain_filter": "foghorn.plugins.new_domain_filter.NewDomainFilterPlugin",
        "new_domain": "foghorn.plugins.new_domain_filter.NewDomainFilterPlugin",
        "upstream_router": "foghorn.plugins.upstream_router.UpstreamRouterPlugin",
        "router": "foghorn.plugins.upstream_router.UpstreamRouterPlugin",
    }

    plugins: List[BasePlugin] = []
    for spec in plugin_specs or []:
        if isinstance(spec, str):
            module_path = spec
            config = {}
        else:
            module_path = spec.get("module")
            config = spec.get("config", {})
        if not module_path:
            continue
        # Resolve alias if a short name was provided
        if "." not in module_path:
            module_path = aliases.get(module_path, module_path)
        # Dynamically import the plugin class from the module path.
        module_name, class_name = module_path.rsplit(".", 1)
        mod = importlib.import_module(module_name)
        cls = getattr(mod, class_name)
        plugin = cls(**config)
        plugins.append(plugin)
    return plugins


def main(argv: List[str] | None = None) -> int:
    """
    Main entry point for the DNS server.
    Parses arguments, loads configuration, initializes plugins, and starts the server.

    Args:
        argv: Command-line arguments.

    Returns:
        An exit code.

    Example use:
        CLI:
            PYTHONPATH=src python -m foghorn.main --config config.yaml

        Programmatic (for testing):
        (This is a simplified example; real usage involves creating a config file)
        >>> import threading
        >>> import time
        >>> with patch('builtins.open', mock_open(read_data='''
        ... listen:
        ...   host: 127.0.0.1
        ...   port: 5354
        ... upstream:
        ...   host: 1.1.1.1
        ...   port: 53
        ... ''')):
        ...     server_thread = threading.Thread(target=main, args=(["--config", "config.yaml"],), daemon=True)
        ...     server_thread.start()
        ...     time.sleep(0.1) # Give server time to start
    """
    parser = argparse.ArgumentParser(description="Caching DNS server with plugins")
    parser.add_argument("--config", default="config.yaml", help="Path to YAML config")
    args = parser.parse_args(argv)

    with open(args.config, "r") as f:
        cfg = yaml.safe_load(f) or {}

    # Initialize logging before any other operations
    init_logging(cfg.get("logging"))
    logger = logging.getLogger("foghorn.main")
    logger.info("Loaded config from %s", args.config)

    listen = cfg.get("listen", {})
    host = listen.get("host", "127.0.0.1")
    port = int(listen.get("port", 5353))

    upstream = cfg.get("upstream", {})
    up_host = upstream.get("host", "1.1.1.1")
    up_port = int(upstream.get("port", 53))
    timeout_ms = int(upstream.get("timeout_ms", 2000))

    plugins = load_plugins(cfg.get("plugins", []))
    logger.debug("Loaded %d plugins: %s", len(plugins), [p.__class__.__name__ for p in plugins])

    server = DNSServer(host, port, (up_host, up_port), plugins, timeout=timeout_ms/1000.0)
    logger.info("Starting Foghorn on %s:%d, upstream %s:%d", host, port, up_host, up_port)

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        logger.info("Received interrupt, shutting down")
    except Exception:
        logger.exception("Unhandled exception during server operation")
        return 1

    return 0


if __name__ == "__main__":
    raise SystemExit(main())

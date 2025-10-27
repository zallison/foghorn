from __future__ import annotations
import time
import os
import logging
import pathlib
from typing import Dict

from typing import Optional

from foghorn.plugins.base import PluginDecision, PluginContext
from foghorn.plugins.base import BasePlugin, plugin_aliases
from foghorn.cache import TTLCache

logger = logging.getLogger(__name__)


@plugin_aliases("hosts", "etc-hosts")
class BlocklistPlugin(BasePlugin):
    """
    Load /etc/hosts

    Brief: Load ips and host names from /etc/hosts, or another host file.
    """

    def __init__(self, **config) -> None:
        """
        Initialize plugin configuration and database.

        Inputs:
            **config: Supported keys
              - file_path (str): Path to the `hosts` file

        Outputs:
            None
        """
        super().__init__(**config)

        # Configuration
        self.file_path: str = self.config.get("file_path", "/etc/hosts")
        self._load_hosts()

    def _load_hosts() -> Dict[str, str]:
        """
        Read the system hosts file (/etc/hosts) and return a dictionary
        mapping each domain name to its corresponding IP address.

        The hosts file may contain comments and multiple domain names per IP.
        Only the first IP per line is used for the mapping.

        Returns:
        A dictionary where keys are domain names and values are IP addresses.
        """
        hosts_path = pathlib.Path(self.file_path)
        mapping: Dict[str, str] = {}
        if not hosts_path.is_file():
            return mapping

        with hosts_path.open("r", encoding="utf-8") as f:
            for line in f:
                stripped = line.strip()
                if not stripped or stripped.startswith("#"):
                    continue
                parts = stripped.split()
                if len(parts) < 2:
                    continue
                ip = parts[0]
                for domain in parts[1:]:
                    mapping[domain] = ip
        self.hosts = mapping

    def pre_resolve(
        self, qname: str, qtype: int, req: bytes, ctx: PluginContext
    ) -> Optional[PluginDecision]:
        """
        Decide whether to deny the query based on stored mode.

        Inputs:
            qname: Queried domain name.
            qtype: DNS record type (unused).
            req: Raw DNS request bytes (unused).
            ctx: Plugin context.
        Outputs:
            PluginDecision("deny") when domain is denied; otherwise None to proceed.

        Example:
            >>> from foghorn.plugins.base import PluginContext
            >>> p = BlocklistPlugin(blocklist=["bad.com"])  # doctest: +ELLIPSIS
            >>> p.pre_resolve("bad.com", 1, b"", PluginContext("127.0.0.1")).action
            'deny'
        """
        if self.is_allowed(qname):
            return None
        return PluginDecision(action="deny")

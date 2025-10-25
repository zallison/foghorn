from __future__ import annotations
import datetime as dt
import logging
from typing import Optional

import whois

from .base import BasePlugin, PluginDecision, PluginContext, plugin_aliases

logger = logging.getLogger(__name__)


@plugin_aliases("new_domain", "new_domain_filter", "ndf")
class NewDomainFilterPlugin(BasePlugin):
    """
    A plugin that filters out domains that have been registered recently.

    Example use:
        In config.yaml:
        plugins:
          - module: foghorn.plugins.new_domain_filter.NewDomainFilterPlugin
            config:
              threshold_days: 30
    """
    def __init__(self, **config):
        """
        Initializes the NewDomainFilterPlugin.

        Args:
            **config: Configuration for the plugin.

        Example use:
            >>> from foghorn.plugins.new_domain_filter import NewDomainFilterPlugin
            >>> config = {"threshold_days": 10}
            >>> plugin = NewDomainFilterPlugin(**config)
            >>> plugin.threshold_days
            10
        """
        super().__init__(**config)
        self.threshold_days: int = int(self.config.get("threshold_days", 7))

    def pre_resolve(self, qname: str, qtype: int, req: bytes, ctx: PluginContext) -> Optional[PluginDecision]:
        """
        Checks the age of the domain and denies the request if it's too new.
        Args:
            qname: The queried domain name.
            qtype: The query type.
            req: The raw DNS request.
            ctx: The plugin context.
        Returns:
            A PluginDecision to deny the request if the domain is too new, otherwise None.

        Example use:
            (Note: This is a simplified example that doesn't actually make a network request)
            >>> from foghorn.plugins.new_domain_filter import NewDomainFilterPlugin
            >>> from foghorn.plugins.base import PluginContext
            >>> from unittest.mock import patch
            >>> plugin = NewDomainFilterPlugin(threshold_days=30)
            >>> with patch.object(plugin, '_domain_age_days', return_value=10):
            ...     decision = plugin.pre_resolve("new.com", 1, b'', PluginContext("1.2.3.4"))
            ...     decision.action
            'deny'
        """
        age_days = self._domain_age_days(qname)
        if age_days is None:
            logger.debug("Domain age unknown for %s, allowing", qname)
            return None  # unknown; allow
        if age_days < self.threshold_days:
            logger.warning("Domain %s blocked (age: %d days, threshold: %d)", qname, age_days, self.threshold_days)
            return PluginDecision(action="deny")

        logger.debug("Domain %s allowed (age: %d days)", qname, age_days)
        return None

    def _domain_age_days(self, domain: str) -> Optional[int]:
        """
        Determines the age of a domain in days by querying whois.
        Args:
            domain: The domain name to check.
        Returns:
            The age of the domain in days, or None if it cannot be determined.

        Example use:
            (Note: This example is for illustration and won't make a real network request)
            >>> from unittest.mock import patch, MagicMock
            >>> from foghorn.plugins.new_domain_filter import NewDomainFilterPlugin
            >>> plugin = NewDomainFilterPlugin()
            >>> with patch('whois.whois') as mock_whois:
            ...     mock_whois.return_value.creation_date = dt.datetime(2023, 1, 1)
            ...     # The age will depend on the current date, so we just check it's an int
            ...     isinstance(plugin._domain_age_days("example.com"), int)
            True
        """
        try:
            w = whois.whois(domain)
            if not w.creation_date:
                return None

            creation_date = w.creation_date
            if isinstance(creation_date, list):
                creation_date = min(creation_date)

            now = dt.datetime.now(dt.timezone.utc)
            if creation_date.tzinfo is None:
                creation_date = creation_date.replace(tzinfo=dt.timezone.utc)

            delta = now - creation_date
            return max(0, delta.days)
        except Exception as e:
            logger.warning("Failed to get domain age for %s: %s", domain, str(e))
            return None

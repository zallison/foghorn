from __future__ import annotations
import datetime as dt
from typing import Optional

import requests

from .base import BasePlugin, PluginDecision, PluginContext

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
        self.rdap_endpoint: str = self.config.get("rdap_endpoint", "https://client.rdap.org/?type=domain&object=")
        self.timeout = int(self.config.get("timeout_ms", 2000)) / 1000.0

    def pre_resolve(self, qname: str, qtype: int, ctx: PluginContext) -> Optional[PluginDecision]:
        """
        Checks the age of the domain and denies the request if it's too new.
        Args:
            qname: The queried domain name.
            qtype: The query type.
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
            ...     decision = plugin.pre_resolve("new.com", 1, PluginContext("1.2.3.4"))
            ...     decision.action
            'deny'
        """
        age_days = self._domain_age_days(qname)
        if age_days is None:
            return None  # unknown; allow
        if age_days < self.threshold_days:
            return PluginDecision(action="deny")
        return None

    def _domain_age_days(self, domain: str) -> Optional[int]:
        """
        Determines the age of a domain in days by querying an RDAP endpoint.
        Args:
            domain: The domain name to check.
        Returns:
            The age of the domain in days, or None if it cannot be determined.

        Example use:
            (Note: This example is for illustration and won't make a real network request)
            >>> from unittest.mock import patch, MagicMock
            >>> from foghorn.plugins.new_domain_filter import NewDomainFilterPlugin
            >>> plugin = NewDomainFilterPlugin()
            >>> with patch('requests.get') as mock_get:
            ...     mock_response = MagicMock()
            ...     mock_response.status_code = 200
            ...     mock_response.json.return_value = {
            ...         'events': [{'eventAction': 'registration', 'eventDate': '2023-01-01T00:00:00Z'}]
            ...     }
            ...     mock_get.return_value = mock_response
            ...     # The age will depend on the current date, so we just check it's an int
            ...     isinstance(plugin._domain_age_days("example.com"), int)
            True
        """
        try:
            url = self.rdap_endpoint.rstrip("/") + "/" + domain.rstrip('.')
            r = requests.get(url, timeout=self.timeout)
            if r.status_code != 200:
                return None
            data = r.json()
            # Look for registration events in the RDAP response.
            events = data.get("events", [])
            reg_dates = [e.get("eventDate") for e in events if e.get("eventAction") == "registration" and e.get("eventDate")]
            if not reg_dates:
                # Some RDAP servers use "registrationDate" instead of events.
                reg = data.get("registrationDate")
                if reg:
                    reg_dates = [reg]
            if not reg_dates:
                return None
            # Parse the earliest registration date.
            reg_dt = min(dt.datetime.fromisoformat(d.replace("Z", "+00:00")) for d in reg_dates)
            now = dt.datetime.now(dt.timezone.utc)
            delta = now - reg_dt
            return max(0, delta.days)
        except Exception:
            return None

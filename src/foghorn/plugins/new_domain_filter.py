from __future__ import annotations
import datetime as dt
from typing import Optional

import requests

from .base import BasePlugin, PluginDecision, PluginContext

class NewDomainFilterPlugin(BasePlugin):
    def __init__(self, **config):
        super().__init__(**config)
        self.threshold_days: int = int(self.config.get("threshold_days", 7))
        self.rdap_endpoint: str = self.config.get("rdap_endpoint", "https://rdap.org/domain/")
        self.timeout = int(self.config.get("timeout_ms", 2000)) / 1000.0

    def pre_resolve(self, qname: str, qtype: int, ctx: PluginContext) -> Optional[PluginDecision]:
        age_days = self._domain_age_days(qname)
        if age_days is None:
            return None  # unknown; allow
        if age_days < self.threshold_days:
            return PluginDecision(action="deny")
        return None

    def _domain_age_days(self, domain: str) -> Optional[int]:
        try:
            url = self.rdap_endpoint.rstrip("/") + "/" + domain.rstrip('.')
            r = requests.get(url, timeout=self.timeout)
            if r.status_code != 200:
                return None
            data = r.json()
            # RDAP events with eventAction == "registration"
            events = data.get("events", [])
            reg_dates = [e.get("eventDate") for e in events if e.get("eventAction") == "registration" and e.get("eventDate")]
            if not reg_dates:
                # Some RDAP servers use "registrationDate"
                reg = data.get("registrationDate")
                if reg:
                    reg_dates = [reg]
            if not reg_dates:
                return None
            # Parse the earliest registration date
            reg_dt = min(dt.datetime.fromisoformat(d.replace("Z", "+00:00")) for d in reg_dates)
            now = dt.datetime.now(dt.timezone.utc)
            delta = now - reg_dt
            return max(0, delta.days)
        except Exception:
            return None

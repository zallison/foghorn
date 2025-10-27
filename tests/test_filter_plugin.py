import unittest
from unittest.mock import patch, MagicMock
from dnslib import DNSRecord, QTYPE, A, AAAA, CNAME
from foghorn.plugins.filter import FilterPlugin
from foghorn.cache import TTLCache
from foghorn.plugins.base import PluginContext
import ipaddress
import time
import os
import tempfile
import sqlite3
import pytest


class TestFilterPlugin(unittest.TestCase):
    def setUp(self):
        self.config = {
            "blocked_domains": ["blocked.com", "malware.org"],
            "blocked_patterns": [r".*\.porn\..*"],
            "blocked_keywords": ["spam", "ads"],
            "blocked_ips": [
                {"ip": "192.0.2.1", "action": "deny"},
                {"ip": "198.51.100.0/24", "action": "remove"},
                {"ip": "203.0.113.5", "action": "replace", "replace_with": "127.0.0.1"},
            ],
            "default": "allow",
            "db_path": ":memory:",
        }

    def test_init(self):
        plugin = FilterPlugin(**self.config)
        self.assertIsInstance(plugin, FilterPlugin)
        self.assertEqual(len(plugin.blocked_domains), 2)
        self.assertEqual(len(plugin.blocked_patterns), 1)
        self.assertEqual(len(plugin.blocked_keywords), 2)
        self.assertEqual(len(plugin.blocked_ips), 2)
        self.assertEqual(len(plugin.blocked_networks), 1)

    def test_pre_resolve_allowed_domain(self):
        plugin = FilterPlugin(**self.config)
        decision = plugin.pre_resolve("good.com", QTYPE.A, b"", None)
        self.assertIsNone(decision)

    def test_pre_resolve_blocked_domain(self):
        plugin = FilterPlugin(**self.config)
        decision = plugin.pre_resolve("blocked.com", QTYPE.A, b"", None)
        self.assertIsNotNone(decision)
        self.assertEqual(decision.action, "deny")

    def test_pre_resolve_blocked_pattern(self):
        plugin = FilterPlugin(**self.config)
        decision = plugin.pre_resolve("example.porn.site.com", QTYPE.A, b"", None)
        self.assertIsNotNone(decision)
        self.assertEqual(decision.action, "deny")

    def test_pre_resolve_blocked_keyword(self):
        plugin = FilterPlugin(**self.config)
        decision = plugin.pre_resolve("spam.com", QTYPE.A, b"", None)
        self.assertIsNotNone(decision)
        self.assertEqual(decision.action, "deny")

    def test_post_resolve_no_ips(self):
        plugin = FilterPlugin(**self.config)
        response = DNSRecord()
        response.rr = []
        decision = plugin.post_resolve("test.com", QTYPE.A, response.pack(), {})
        self.assertIsNone(decision)

    def test_post_resolve_blocked_ip_deny(self):
        plugin = FilterPlugin(**self.config)
        config = self.config.copy()
        config["blocked_ips"] = [{"ip": "192.0.2.1", "action": "deny"}]
        response = DNSRecord()
        response.rr = [A("192.0.2.1")]
        decision = plugin.post_resolve("test.com", QTYPE.A, response.pack(), {})
        self.assertIsNotNone(decision)
        self.assertEqual(decision["action"], "deny")

    def test_post_resolve_blocked_ip_remove(self):
        plugin = FilterPlugin(**self.config)
        response = DNSRecord()
        response.rr = [A("198.51.100.10")]
        decision = plugin.post_resolve("test.com", QTYPE.A, response.pack(), {})
        self.assertIsNotNone(decision)
        self.assertEqual(decision.action, "override")

    def test_post_resolve_blocked_ip_replace(self):
        plugin = FilterPlugin(**self.config)
        response = DNSRecord()
        response.rr = [A("203.0.113.5")]
        decision = plugin.post_resolve("test.com", QTYPE.A, response.pack(), {})
        self.assertIsNotNone(decision)
        self.assertEqual(decision.action, "override")

    def test_get_ip_action_exact_match(self):
        plugin = FilterPlugin(**self.config)
        action = plugin._get_ip_action(ipaddress.ip_address("192.0.2.1"))
        self.assertIsNotNone(action)
        self.assertEqual(action["action"], "deny")

    def test_get_ip_action_network_match(self):
        plugin = FilterPlugin(**self.config)
        action = plugin._get_ip_action(ipaddress.ip_address("198.51.100.10"))
        self.assertIsNotNone(action)
        self.assertEqual(action["action"], "remove")

    def test_get_ip_action_no_match(self):
        plugin = FilterPlugin(**self.config)
        action = plugin._get_ip_action(ipaddress.ip_address("10.0.0.1"))
        self.assertIsNone(action)

    def test_db_init(self):
        plugin = FilterPlugin(**self.config)
        plugin._db_init()
        cur = plugin.conn.execute("SELECT name FROM sqlite_master WHERE type='table';")
        tables = [row[0] for row in cur.fetchall()]
        self.assertIn("blocked_domains", tables)

    def test_db_insert_domain(self):
        plugin = FilterPlugin(**self.config)
        plugin._db_insert_domain("test.com", "test.txt", "deny")
        cur = plugin.conn.execute(
            "SELECT * FROM blocked_domains WHERE domain = 'test.com'"
        )
        row = cur.fetchone()
        self.assertIsNotNone(row)
        self.assertEqual(row[0], "test.com")
        self.assertEqual(row[2], "deny")

    def test_load_list_from_file(self):
        with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".txt") as f:
            f.write("domain1.com\n#comment\n#domain2.com\n")
            f.flush()
            temp_filename = f.name

        try:
            plugin = FilterPlugin(**self.config)
            plugin.load_list_from_file(temp_filename, "allow")
            cur = plugin.conn.execute(
                "SELECT * FROM blocked_domains WHERE domain = 'domain1.com'"
            )
            row = cur.fetchone()
            self.assertIsNotNone(row)
            self.assertEqual(row[2], "allow")
        finally:
            os.unlink(temp_filename)

    def test_is_allowed(self):
        plugin = FilterPlugin(**self.config)
        plugin._db_insert_domain("allowed.com", "test.txt", "allow")
        plugin._db_insert_domain("blocked.com", "test.txt", "deny")
        self.assertTrue(plugin.is_allowed("allowed.com"))
        self.assertFalse(plugin.is_allowed("blocked.com"))
        self.assertTrue(plugin.is_allowed("unknown.com"))  # default is allow

    def test_cache_integration(self):
        with (
            patch.object(TTLCache, "get") as mock_get,
            patch.object(TTLCache, "set") as mock_set,
        ):
            plugin = FilterPlugin(**self.config)
            mock_get.return_value = None
            decision = plugin.pre_resolve("good.com", QTYPE.A, b"", None)
            self.assertIsNone(decision)
            mock_set.assert_called_once()

    def test_empty_config(self):
        empty_config = {"db_path": ":memory:"}
        plugin = FilterPlugin(**empty_config)
        self.assertEqual(len(plugin.blocked_domains), 0)
        self.assertEqual(len(plugin.blocked_patterns), 0)
        self.assertEqual(len(plugin.blocked_keywords), 0)
        self.assertEqual(len(plugin.blocked_ips), 0)
        self.assertEqual(len(plugin.blocked_networks), 0)

    def test_post_resolve_invalid_dns(self):
        plugin = FilterPlugin(**self.config)
        invalid_dns = b"invalid dns data"
        decision = plugin.post_resolve("test.com", QTYPE.A, invalid_dns, {})
        self.assertIsNone(decision)

    def test_post_resolve_non_a_record(self):
        plugin = FilterPlugin(**self.config)
        response = DNSRecord()
        response.rr = [CNAME("example.com")]

        with pytest.raises(Exception) as e:
            decision = plugin.post_resolve("test.com", QTYPE.CNAME, response.pack(), {})
        assert "bad qtype" in str(e.value)

    def test_post_resolve_no_blocked_ips(self):
        config = self.config.copy()
        config["blocked_ips"] = []
        plugin = FilterPlugin(**config)
        response = DNSRecord()
        response.rr = [A("192.168.88.1")]
        decision = plugin.post_resolve("test.com", QTYPE.A, response.pack(), {})

        self.assertIsNone(decision)

    ## def test_post_resolve_replace_version_mismatch(self):
    ##     config = self.config.copy()
    ##     config["blocked_ips"] = [
    ##         {"ip": "2001:db8::1", "action": "replace", "replace_with": "192.0.2.1"}
    ##     ]
    ##     ctx = PluginContext(client_ip="127.0.0.1")

    ##     plugin = FilterPlugin(**config)
    ##     response = DNSRecord()
    ##     response.rr = [AAAA("2001:db8::1")]

    ##     decision = plugin.post_resolve("test.com", QTYPE.AAAA, response.pack(), ctx)
    ##     self.assertIsNotNone(decision)
    ##     self.assertEqual(decision.action, "override")


if __name__ == "__main__":
    unittest.main()

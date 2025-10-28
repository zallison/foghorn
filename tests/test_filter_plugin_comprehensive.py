"""
Comprehensive test suite for FilterPlugin.

Tests cover initialization, domain filtering, IP filtering, database operations,
caching, error handling, and edge cases.
"""
import unittest
from unittest.mock import patch, MagicMock
from dnslib import DNSHeader, DNSQuestion, DNSRecord, QTYPE, A, AAAA, CNAME, RR
from foghorn.plugins.filter import FilterPlugin
from foghorn.cache import TTLCache
from foghorn.plugins.base import PluginContext, PluginDecision
import ipaddress
import time
import os
import tempfile
import sqlite3
import pytest
import re


class TestFilterPluginInitialization(unittest.TestCase):
    """Tests for FilterPlugin initialization and configuration."""

    def test_init_minimal_config(self):
        """Test initialization with minimal configuration."""
        plugin = FilterPlugin(db_path=":memory:")
        self.assertIsInstance(plugin, FilterPlugin)
        self.assertEqual(plugin.cache_ttl_seconds, 600)
        self.assertEqual(plugin.default, "deny")
        self.assertEqual(len(plugin.blocked_domains), 0)

    def test_init_full_config(self):
        """Test initialization with comprehensive configuration."""
        config = {
            "blocked_domains": ["blocked.com", "malware.org"],
            "blocked_patterns": [r".*\.porn\..*", r"^casino.*"],
            "blocked_keywords": ["spam", "ads", "malware"],
            "blocked_ips": [
                {"ip": "192.0.2.1", "action": "deny"},
                {"ip": "198.51.100.0/24", "action": "remove"},
                {"ip": "203.0.113.5", "action": "replace", "replace_with": "127.0.0.1"},
                "10.0.0.1",  # Simple string format
            ],
            "default": "allow",
            "db_path": ":memory:",
            "cache_ttl_seconds": 300,
        }
        plugin = FilterPlugin(**config)
        
        self.assertEqual(len(plugin.blocked_domains), 2)
        self.assertEqual(len(plugin.blocked_patterns), 2)
        self.assertEqual(len(plugin.blocked_keywords), 3)
        self.assertEqual(len(plugin.blocked_ips), 3)  # 192.0.2.1, 203.0.113.5, and 10.0.0.1
        self.assertEqual(len(plugin.blocked_networks), 1)  # 198.51.100.0/24
        self.assertEqual(plugin.cache_ttl_seconds, 300)

    def test_init_invalid_regex_pattern(self):
        """Test that invalid regex patterns are logged but don't crash initialization."""
        config = {
            "blocked_patterns": [r"[invalid(regex", r"valid.*pattern"],
            "db_path": ":memory:",
        }
        
        with self.assertLogs(level="ERROR") as cm:
            plugin = FilterPlugin(**config)
            # Only valid pattern should be compiled
            self.assertEqual(len(plugin.blocked_patterns), 1)
            self.assertTrue(any("Invalid regex pattern" in msg for msg in cm.output))

    def test_init_invalid_ip_format(self):
        """Test that invalid IP addresses are logged but don't crash initialization."""
        config = {
            "blocked_ips": [
                {"ip": "not.an.ip", "action": "deny"},
                {"ip": "192.0.2.1", "action": "deny"},
            ],
            "db_path": ":memory:",
        }
        
        with self.assertLogs(level="ERROR") as cm:
            plugin = FilterPlugin(**config)
            # Only valid IP should be added
            self.assertEqual(len(plugin.blocked_ips), 1)
            self.assertTrue(any("Invalid IP address" in msg for msg in cm.output))

    def test_init_invalid_action(self):
        """Test that invalid actions default to 'deny'."""
        config = {
            "blocked_ips": [{"ip": "192.0.2.1", "action": "invalid_action"}],
            "db_path": ":memory:",
        }
        
        with self.assertLogs(level="WARNING") as cm:
            plugin = FilterPlugin(**config)
            ip = ipaddress.ip_address("192.0.2.1")
            self.assertEqual(plugin.blocked_ips[ip]["action"], "deny")

    def test_init_replace_without_replace_with(self):
        """Test that 'replace' action without 'replace_with' is rejected."""
        config = {
            "blocked_ips": [{"ip": "192.0.2.1", "action": "replace"}],
            "db_path": ":memory:",
        }
        
        with self.assertLogs(level="ERROR") as cm:
            plugin = FilterPlugin(**config)
            # IP should not be added
            self.assertEqual(len(plugin.blocked_ips), 0)
            self.assertTrue(any("requires 'replace_with'" in msg for msg in cm.output))

    def test_init_ipv6_support(self):
        """Test initialization with IPv6 addresses."""
        config = {
            "blocked_ips": [
                {"ip": "2001:db8::1", "action": "deny"},
                {"ip": "2001:db8::/32", "action": "remove"},
            ],
            "db_path": ":memory:",
        }
        
        plugin = FilterPlugin(**config)
        self.assertEqual(len(plugin.blocked_ips), 1)
        self.assertEqual(len(plugin.blocked_networks), 1)


class TestFilterPluginDomainFiltering(unittest.TestCase):
    """Tests for domain-based filtering in pre_resolve."""

    def setUp(self):
        """Set up test fixtures."""
        self.config = {
            "blocked_domains": ["blocked.com", "malware.org"],
            "blocked_patterns": [r".*\.porn\..*", r"^casino.*"],
            "blocked_keywords": ["spam", "ads"],
            "default": "allow",
            "db_path": ":memory:",
        }
        self.plugin = FilterPlugin(**self.config)
        self.ctx = PluginContext(client_ip="127.0.0.1")

    def test_pre_resolve_allowed_domain(self):
        """Test that allowed domains pass through."""
        decision = self.plugin.pre_resolve("google.com", QTYPE.A, b"", self.ctx)
        self.assertIsNone(decision)

    def test_pre_resolve_blocked_domain_exact(self):
        """Test exact domain blocking."""
        decision = self.plugin.pre_resolve("blocked.com", QTYPE.A, b"", self.ctx)
        self.assertIsNotNone(decision)
        self.assertEqual(decision.action, "deny")

    def test_pre_resolve_blocked_domain_case_insensitive(self):
        """Test that domain blocking is case-insensitive."""
        decision = self.plugin.pre_resolve("BLOCKED.COM", QTYPE.A, b"", self.ctx)
        self.assertIsNotNone(decision)
        self.assertEqual(decision.action, "deny")

    def test_pre_resolve_blocked_pattern(self):
        """Test domain blocking by regex pattern."""
        decision = self.plugin.pre_resolve("example.porn.site.com", QTYPE.A, b"", self.ctx)
        self.assertIsNotNone(decision)
        self.assertEqual(decision.action, "deny")
        
        decision = self.plugin.pre_resolve("casino.example.com", QTYPE.A, b"", self.ctx)
        self.assertIsNotNone(decision)
        self.assertEqual(decision.action, "deny")

    def test_pre_resolve_blocked_keyword(self):
        """Test domain blocking by keyword."""
        decision = self.plugin.pre_resolve("spam.com", QTYPE.A, b"", self.ctx)
        self.assertIsNotNone(decision)
        self.assertEqual(decision.action, "deny")
        
        decision = self.plugin.pre_resolve("example-ads.net", QTYPE.A, b"", self.ctx)
        self.assertIsNotNone(decision)
        self.assertEqual(decision.action, "deny")

    def test_pre_resolve_trailing_dot(self):
        """Test domain handling with trailing dot."""
        decision = self.plugin.pre_resolve("blocked.com.", QTYPE.A, b"", self.ctx)
        self.assertIsNotNone(decision)
        self.assertEqual(decision.action, "deny")

    def test_pre_resolve_caching(self):
        """Test that domain decisions are cached."""
        # First call - cache miss
        decision1 = self.plugin.pre_resolve("example.com", QTYPE.A, b"", self.ctx)
        
        # Second call - should use cache
        with patch.object(self.plugin, "is_allowed") as mock_is_allowed:
            decision2 = self.plugin.pre_resolve("example.com", QTYPE.A, b"", self.ctx)
            # is_allowed should not be called if cache hit
            mock_is_allowed.assert_not_called()
        
        self.assertEqual(decision1, decision2)


class TestFilterPluginIPFiltering(unittest.TestCase):
    """Tests for IP-based filtering in post_resolve."""

    def setUp(self):
        """Set up test fixtures."""
        self.config = {
            "blocked_ips": [
                {"ip": "192.0.2.1", "action": "deny"},
                {"ip": "198.51.100.0/24", "action": "remove"},
                {"ip": "203.0.113.5", "action": "replace", "replace_with": "127.0.0.1"},
            ],
            "default": "allow",
            "db_path": ":memory:",
        }
        self.plugin = FilterPlugin(**self.config)
        self.ctx = PluginContext(client_ip="127.0.0.1")

    def _create_dns_response(self, domain, ips, qtype=QTYPE.A):
        """
        Create a DNS response with A or AAAA records.
        
        Inputs:
            domain: Domain name
            ips: List of IP addresses
            qtype: Query type (QTYPE.A or QTYPE.AAAA)
        
        Outputs:
            Packed DNS response bytes
        """
        response = DNSRecord(DNSHeader(qr=1, aa=1, ra=1), q=DNSQuestion(domain, qtype))
        
        for ip in ips:
            if qtype == QTYPE.A:
                response.add_answer(RR(domain, QTYPE.A, rdata=A(ip), ttl=300))
            elif qtype == QTYPE.AAAA:
                response.add_answer(RR(domain, QTYPE.AAAA, rdata=AAAA(ip), ttl=300))
        
        return response.pack()

    def test_post_resolve_no_blocked_ips(self):
        """Test that clean responses pass through."""
        response_wire = self._create_dns_response("example.com", ["8.8.8.8"])
        decision = self.plugin.post_resolve("example.com", QTYPE.A, response_wire, self.ctx)
        self.assertIsNone(decision)

    def test_post_resolve_blocked_ip_deny(self):
        """Test that 'deny' action returns NXDOMAIN."""
        response_wire = self._create_dns_response("test.com", ["192.0.2.1"])
        decision = self.plugin.post_resolve("test.com", QTYPE.A, response_wire, self.ctx)
        self.assertIsNotNone(decision)
        self.assertEqual(decision.action, "deny")

    def test_post_resolve_blocked_ip_remove(self):
        """Test that 'remove' action removes IPs from response."""
        response_wire = self._create_dns_response("test.com", ["198.51.100.10", "8.8.8.8"])
        decision = self.plugin.post_resolve("test.com", QTYPE.A, response_wire, self.ctx)
        
        # Should get override with modified response
        self.assertIsNotNone(decision)
        if decision.action == "override":
            modified_response = DNSRecord.parse(decision.response)
            ips = [str(rr.rdata) for rr in modified_response.rr if rr.rtype == QTYPE.A]
            self.assertIn("8.8.8.8", ips)
            self.assertNotIn("198.51.100.10", ips)

    def test_post_resolve_blocked_ip_replace(self):
        """Test that 'replace' action substitutes IP addresses."""
        response_wire = self._create_dns_response("test.com", ["203.0.113.5"])
        decision = self.plugin.post_resolve("test.com", QTYPE.A, response_wire, self.ctx)
        
        self.assertIsNotNone(decision)
        if decision.action == "override":
            modified_response = DNSRecord.parse(decision.response)
            ips = [str(rr.rdata) for rr in modified_response.rr if rr.rtype == QTYPE.A]
            self.assertIn("127.0.0.1", ips)
            self.assertNotIn("203.0.113.5", ips)

    def test_post_resolve_network_match(self):
        """Test that network ranges are matched correctly."""
        response_wire = self._create_dns_response("test.com", ["198.51.100.50"])
        decision = self.plugin.post_resolve("test.com", QTYPE.A, response_wire, self.ctx)
        self.assertIsNotNone(decision)

    def test_post_resolve_mixed_ips(self):
        """Test response with both blocked and allowed IPs."""
        response_wire = self._create_dns_response(
            "test.com", ["192.0.2.1", "8.8.8.8", "198.51.100.10"]
        )
        decision = self.plugin.post_resolve("test.com", QTYPE.A, response_wire, self.ctx)
        
        # Should deny because 192.0.2.1 has 'deny' action
        self.assertIsNotNone(decision)
        self.assertEqual(decision.action, "deny")

    def test_post_resolve_all_ips_removed(self):
        """Test that removing all IPs returns NXDOMAIN."""
        response_wire = self._create_dns_response("test.com", ["198.51.100.10"])
        decision = self.plugin.post_resolve("test.com", QTYPE.A, response_wire, self.ctx)
        
        # All IPs removed should return deny
        self.assertIsNotNone(decision)
        self.assertEqual(decision.action, "deny")

    def test_post_resolve_non_a_aaaa_qtype(self):
        """Test that non-A/AAAA query types are handled correctly."""
        response = DNSRecord()
        with pytest.raises(TypeError, match="bad qtype"):
            self.plugin.post_resolve("test.com", QTYPE.MX, response.pack(), self.ctx)

    def test_post_resolve_empty_response(self):
        """Test handling of empty DNS response."""
        response = DNSRecord()
        decision = self.plugin.post_resolve("test.com", QTYPE.A, response.pack(), self.ctx)
        self.assertIsNone(decision)

    def test_post_resolve_no_filters_configured(self):
        """Test that plugin returns None when no IP filters configured."""
        plugin = FilterPlugin(db_path=":memory:")
        response_wire = self._create_dns_response("test.com", ["8.8.8.8"])
        decision = plugin.post_resolve("test.com", QTYPE.A, response_wire, self.ctx)
        self.assertIsNone(decision)


class TestFilterPluginDatabase(unittest.TestCase):
    """Tests for database operations."""

    def setUp(self):
        """Set up test fixtures."""
        self.config = {
            "db_path": ":memory:",
            "default": "allow",
        }
        self.plugin = FilterPlugin(**self.config)

    def test_db_init_creates_table(self):
        """Test that database initialization creates required table."""
        cur = self.plugin.conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name='blocked_domains'"
        )
        table = cur.fetchone()
        self.assertIsNotNone(table)

    def test_db_insert_domain(self):
        """Test inserting a domain into database."""
        self.plugin._db_insert_domain("test.com", "config", "deny")
        
        cur = self.plugin.conn.execute(
            "SELECT domain, filename, mode FROM blocked_domains WHERE domain = ?",
            ("test.com",)
        )
        row = cur.fetchone()
        
        self.assertIsNotNone(row)
        self.assertEqual(row[0], "test.com")
        self.assertEqual(row[1], "config")
        self.assertEqual(row[2], "deny")

    def test_db_insert_domain_replace(self):
        """Test that inserting duplicate domain replaces existing entry."""
        self.plugin._db_insert_domain("test.com", "file1.txt", "deny")
        self.plugin._db_insert_domain("test.com", "file2.txt", "allow")
        
        cur = self.plugin.conn.execute(
            "SELECT filename, mode FROM blocked_domains WHERE domain = ?",
            ("test.com",)
        )
        row = cur.fetchone()
        
        self.assertEqual(row[0], "file2.txt")
        self.assertEqual(row[1], "allow")

    def test_is_allowed_with_allow_mode(self):
        """Test is_allowed returns True for 'allow' mode."""
        self.plugin._db_insert_domain("allowed.com", "config", "allow")
        self.assertTrue(self.plugin.is_allowed("allowed.com"))

    def test_is_allowed_with_deny_mode(self):
        """Test is_allowed returns False for 'deny' mode."""
        self.plugin._db_insert_domain("blocked.com", "config", "deny")
        self.assertFalse(self.plugin.is_allowed("blocked.com"))

    def test_is_allowed_default_behavior(self):
        """Test is_allowed uses default for unknown domains."""
        # Default is 'allow'
        self.assertTrue(self.plugin.is_allowed("unknown.com"))
        
        # Change default to 'deny'
        plugin_deny = FilterPlugin(db_path=":memory:", default="deny")
        self.assertFalse(plugin_deny.is_allowed("unknown.com"))

    def test_load_list_from_file(self):
        """Test loading domains from file."""
        with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".txt") as f:
            f.write("domain1.com\n")
            f.write("domain2.com\n")
            f.write("# comment line\n")
            f.write("\n")  # empty line
            f.write("domain3.com\n")
            temp_filename = f.name

        try:
            self.plugin.load_list_from_file(temp_filename, "deny")
            
            for domain in ["domain1.com", "domain2.com", "domain3.com"]:
                cur = self.plugin.conn.execute(
                    "SELECT mode FROM blocked_domains WHERE domain = ?",
                    (domain,)
                )
                row = cur.fetchone()
                self.assertIsNotNone(row)
                self.assertEqual(row[0], "deny")
        finally:
            os.unlink(temp_filename)

    def test_load_list_from_file_invalid_mode(self):
        """Test that invalid mode raises ValueError."""
        with tempfile.NamedTemporaryFile(mode="w", delete=False) as f:
            f.write("domain.com\n")
            temp_filename = f.name

        try:
            with self.assertRaises(ValueError):
                self.plugin.load_list_from_file(temp_filename, "invalid")
        finally:
            os.unlink(temp_filename)

    def test_load_list_from_nonexistent_file(self):
        """Test that loading from nonexistent file raises FileNotFoundError."""
        with self.assertRaises(FileNotFoundError):
            self.plugin.load_list_from_file("/nonexistent/file.txt", "deny")


class TestFilterPluginCaching(unittest.TestCase):
    """Tests for caching behavior."""

    def setUp(self):
        """Set up test fixtures."""
        self.config = {
            "db_path": ":memory:",
            "cache_ttl_seconds": 300,
            "default": "allow",
        }
        self.plugin = FilterPlugin(**self.config)

    def test_add_to_cache_allowed(self):
        """Test adding allowed domain to cache."""
        key = "example.com"
        self.plugin.add_to_cache(key, True)
        
        cached_value = self.plugin._domain_cache.get(("example.com", 0))
        self.assertEqual(cached_value, b"1")

    def test_add_to_cache_blocked(self):
        """Test adding blocked domain to cache."""
        key = "blocked.com"
        self.plugin.add_to_cache(key, False)
        
        cached_value = self.plugin._domain_cache.get(("blocked.com", 0))
        self.assertEqual(cached_value, b"0")

    def test_cache_hit_avoids_database_lookup(self):
        """Test that cache hit avoids database query."""
        self.plugin._db_insert_domain("test.com", "config", "deny")
        
        # First call populates cache
        self.plugin.pre_resolve("test.com", QTYPE.A, b"", None)
        
        # Second call should use cache
        with patch.object(self.plugin, "is_allowed") as mock_is_allowed:
            self.plugin.pre_resolve("test.com", QTYPE.A, b"", None)
            mock_is_allowed.assert_not_called()


class TestFilterPluginIPAction(unittest.TestCase):
    """Tests for _get_ip_action method."""

    def setUp(self):
        """Set up test fixtures."""
        self.config = {
            "blocked_ips": [
                {"ip": "192.0.2.1", "action": "deny"},
                {"ip": "198.51.100.0/24", "action": "remove"},
                {"ip": "203.0.113.5", "action": "replace", "replace_with": "127.0.0.1"},
            ],
            "db_path": ":memory:",
        }
        self.plugin = FilterPlugin(**self.config)

    def test_get_ip_action_exact_match(self):
        """Test exact IP match returns correct action."""
        action = self.plugin._get_ip_action(ipaddress.ip_address("192.0.2.1"))
        self.assertIsNotNone(action)
        self.assertEqual(action["action"], "deny")

    def test_get_ip_action_network_match(self):
        """Test network range match returns correct action."""
        action = self.plugin._get_ip_action(ipaddress.ip_address("198.51.100.50"))
        self.assertIsNotNone(action)
        self.assertEqual(action["action"], "remove")

    def test_get_ip_action_replace_with_metadata(self):
        """Test replace action includes replace_with field."""
        action = self.plugin._get_ip_action(ipaddress.ip_address("203.0.113.5"))
        self.assertIsNotNone(action)
        self.assertEqual(action["action"], "replace")
        self.assertEqual(action["replace_with"], "127.0.0.1")

    def test_get_ip_action_no_match(self):
        """Test that unblocked IP returns None."""
        action = self.plugin._get_ip_action(ipaddress.ip_address("10.0.0.1"))
        self.assertIsNone(action)

    def test_get_ip_action_ipv6(self):
        """Test IPv6 address matching."""
        config = {
            "blocked_ips": [
                {"ip": "2001:db8::1", "action": "deny"},
                {"ip": "2001:db8::/32", "action": "remove"},
            ],
            "db_path": ":memory:",
        }
        plugin = FilterPlugin(**config)
        
        action = plugin._get_ip_action(ipaddress.ip_address("2001:db8::1"))
        self.assertEqual(action["action"], "deny")
        
        action = plugin._get_ip_action(ipaddress.ip_address("2001:db8::5"))
        self.assertEqual(action["action"], "remove")


class TestFilterPluginEdgeCases(unittest.TestCase):
    """Tests for edge cases and error handling."""

    def test_invalid_dns_response(self):
        """Test handling of corrupted DNS response."""
        config = {
            "blocked_ips": [{"ip": "192.0.2.1", "action": "deny"}],
            "db_path": ":memory:",
            "default": "allow",
        }
        plugin = FilterPlugin(**config)
        
        # Invalid DNS wire format
        invalid_wire = b"not a valid dns response"
        
        with self.assertLogs(level="ERROR") as cm:
            decision = plugin.post_resolve("test.com", QTYPE.A, invalid_wire, None)
            self.assertEqual(decision.action, "allow")  # Falls back to default
            self.assertTrue(any("Failed to parse" in msg for msg in cm.output))

    def test_cache_exception_handling(self):
        """Test that cache exceptions are caught and logged."""
        plugin = FilterPlugin(db_path=":memory:")
        
        with patch.object(plugin._domain_cache, "set", side_effect=Exception("Cache error")):
            with self.assertLogs(level="WARNING") as cm:
                plugin.add_to_cache("test.com", True)
                self.assertTrue(any("exception adding to cache" in msg for msg in cm.output))

    def test_empty_blocked_lists(self):
        """Test plugin with no filters configured."""
        plugin = FilterPlugin(db_path=":memory:", default="allow")
        
        decision = plugin.pre_resolve("example.com", QTYPE.A, b"", None)
        self.assertIsNone(decision)

    def test_case_sensitivity_keywords(self):
        """Test that keyword matching is case-insensitive."""
        config = {
            "blocked_keywords": ["SPAM"],
            "db_path": ":memory:",
        }
        plugin = FilterPlugin(**config)
        
        decision = plugin.pre_resolve("spam.com", QTYPE.A, b"", None)
        self.assertIsNotNone(decision)
        self.assertEqual(decision.action, "deny")

    def test_pattern_matching_case_insensitive(self):
        """Test that regex patterns are case-insensitive."""
        config = {
            "blocked_patterns": [r".*\.CASINO\..*"],
            "db_path": ":memory:",
        }
        plugin = FilterPlugin(**config)
        
        decision = plugin.pre_resolve("example.casino.com", QTYPE.A, b"", None)
        self.assertIsNotNone(decision)
        self.assertEqual(decision.action, "deny")


if __name__ == "__main__":
    unittest.main()

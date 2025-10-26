"""
Tests for TTL floor (min_cache_ttl) behavior.

This module tests the compute_effective_ttl function and TTL floor application
for all response types.
"""

import pytest
from dnslib import DNSRecord, QTYPE, RCODE, RR, A, AAAA
from unittest.mock import Mock

# Import the function to test
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../src"))
from foghorn.server import compute_effective_ttl


def build_dns_record(rcode=RCODE.NOERROR, answer_ttls=None):
    """
    Builds a mock DNSRecord for testing.

    Inputs:
      - rcode: int, response code (default NOERROR)
      - answer_ttls: list of int, TTL values for answer RRs (default None = no answers)

    Outputs:
      - DNSRecord: mock record with specified rcode and answer TTLs
    """
    record = Mock(spec=DNSRecord)
    record.header = Mock()
    record.header.rcode = rcode

    if answer_ttls:
        # Create mock RRs with specified TTLs
        record.rr = []
        for ttl in answer_ttls:
            rr = Mock()
            rr.ttl = ttl
            record.rr.append(rr)
    else:
        record.rr = []

    return record


def test_noerror_with_answers_below_floor():
    """Test NOERROR with answer TTLs below min_cache_ttl uses floor."""
    resp = build_dns_record(RCODE.NOERROR, answer_ttls=[30, 45])
    result = compute_effective_ttl(resp, 60)
    assert result == 60  # Floor applied


def test_noerror_with_answers_above_floor():
    """Test NOERROR with answer TTLs above min_cache_ttl uses minimum answer TTL."""
    resp = build_dns_record(RCODE.NOERROR, answer_ttls=[120, 180])
    result = compute_effective_ttl(resp, 60)
    assert result == 120  # Min answer TTL used


def test_noerror_with_mixed_ttls():
    """Test NOERROR with mixed TTLs - some above, some below floor."""
    resp = build_dns_record(RCODE.NOERROR, answer_ttls=[30, 90, 45])
    result = compute_effective_ttl(resp, 60)
    assert result == 60  # Floor applied since min(30,90,45) = 30 < 60


def test_nxdomain_uses_floor():
    """Test NXDOMAIN responses use min_cache_ttl."""
    resp = build_dns_record(RCODE.NXDOMAIN)
    result = compute_effective_ttl(resp, 60)
    assert result == 60


def test_servfail_uses_floor():
    """Test SERVFAIL responses use min_cache_ttl."""
    resp = build_dns_record(RCODE.SERVFAIL)
    result = compute_effective_ttl(resp, 60)
    assert result == 60


def test_noerror_no_answers_uses_floor():
    """Test NOERROR with no answer RRs (NODATA) uses min_cache_ttl."""
    resp = build_dns_record(RCODE.NOERROR, answer_ttls=None)
    result = compute_effective_ttl(resp, 60)
    assert result == 60


def test_zero_min_cache_ttl():
    """Test min_cache_ttl=0 results in 0 TTL (no caching)."""
    resp = build_dns_record(RCODE.NXDOMAIN)
    result = compute_effective_ttl(resp, 0)
    assert result == 0


def test_exception_handling():
    """Test exception handling falls back to min_cache_ttl."""
    # Create a record that will cause an exception when accessing rr
    resp = Mock()
    resp.header = Mock()
    resp.header.rcode = RCODE.NOERROR
    resp.rr = Mock(side_effect=Exception("Test exception"))

    result = compute_effective_ttl(resp, 60)
    assert result == 60  # Should fall back to min_cache_ttl

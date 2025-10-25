#!/usr/bin/env python3
"""
Tests for multi-upstream failover functionality.
"""

import pytest
from unittest.mock import Mock, patch
from dnslib import DNSRecord, QTYPE, RCODE

from foghorn.main import normalize_upstream_config
from foghorn.server import send_query_with_failover, DNSUDPHandler
from foghorn.plugins.base import PluginContext
from foghorn.plugins.upstream_router import UpstreamRouterPlugin


def test_normalize_upstream_config_list_format():
    """Test normalization of new list format."""
    config = {
        'upstream': [
            {'host': '1.1.1.1', 'port': 53},
            {'host': '1.0.0.1', 'port': 53}
        ],
        'timeout_ms': 1500
    }
    upstreams, timeout_ms = normalize_upstream_config(config)
    
    assert len(upstreams) == 2
    assert upstreams[0] == {'host': '1.1.1.1', 'port': 53}
    assert upstreams[1] == {'host': '1.0.0.1', 'port': 53}
    assert timeout_ms == 1500


def test_normalize_upstream_config_legacy_dict():
    """Test normalization of legacy dict format."""
    config = {
        'upstream': {'host': '8.8.8.8', 'port': 53, 'timeout_ms': 3000},
        'timeout_ms': 2000  # Top-level should win
    }
    upstreams, timeout_ms = normalize_upstream_config(config)
    
    assert len(upstreams) == 1
    assert upstreams[0] == {'host': '8.8.8.8', 'port': 53}
    assert timeout_ms == 2000  # Top-level wins over legacy


def test_normalize_upstream_config_defaults():
    """Test defaults when no upstream config provided."""
    config = {}
    upstreams, timeout_ms = normalize_upstream_config(config)
    
    assert len(upstreams) == 1
    assert upstreams[0] == {'host': '1.1.1.1', 'port': 53}
    assert timeout_ms == 2000


def test_upstream_router_single_upstream():
    """Test upstream router plugin with single upstream (legacy)."""
    config = {
        'routes': [
            {'suffix': 'corp', 'upstream': {'host': '10.0.0.1', 'port': 53}}
        ]
    }
    plugin = UpstreamRouterPlugin(**config)
    
    # Check route normalization
    assert len(plugin.routes) == 1
    assert plugin.routes[0]['suffix'] == 'corp'
    assert plugin.routes[0]['upstream_candidates'] == [{'host': '10.0.0.1', 'port': 53}]
    
    # Test matching
    ctx = PluginContext('1.2.3.4')
    result = plugin.pre_resolve('test.corp', 1, ctx)
    
    assert result is None  # Plugin doesn't override, just sets context
    assert ctx.upstream_candidates == [{'host': '10.0.0.1', 'port': 53}]
    assert ctx.upstream_override == ('10.0.0.1', 53)  # Backward compat


def test_upstream_router_multiple_upstreams():
    """Test upstream router plugin with multiple upstreams."""
    config = {
        'routes': [
            {
                'suffix': 'internal',
                'upstreams': [
                    {'host': '10.0.0.1', 'port': 53},
                    {'host': '10.0.0.2', 'port': 53}
                ]
            }
        ]
    }
    plugin = UpstreamRouterPlugin(**config)
    
    # Check route normalization
    assert len(plugin.routes) == 1
    assert len(plugin.routes[0]['upstream_candidates']) == 2
    
    # Test matching
    ctx = PluginContext('1.2.3.4')
    result = plugin.pre_resolve('test.internal', 1, ctx)
    
    assert result is None
    assert len(ctx.upstream_candidates) == 2
    assert ctx.upstream_candidates[0] == {'host': '10.0.0.1', 'port': 53}
    assert ctx.upstream_candidates[1] == {'host': '10.0.0.2', 'port': 53}
    # No single upstream override for multiple upstreams
    assert ctx.upstream_override is None


@patch('foghorn.server.logger')
def test_send_query_with_failover_success_first(mock_logger):
    """Test failover succeeds on first upstream."""
    # Mock successful query
    mock_query = Mock()
    mock_response = b'mock_response_data'
    mock_query.send.return_value = mock_response
    
    # Mock parsing to return NOERROR
    with patch('foghorn.server.DNSRecord.parse') as mock_parse:
        mock_record = Mock()
        mock_record.header.rcode = RCODE.NOERROR
        mock_parse.return_value = mock_record
        
        upstreams = [{'host': '1.1.1.1', 'port': 53}]
        result, used_upstream, reason = send_query_with_failover(
            mock_query, upstreams, 2000, 'example.com', 1
        )
        
        assert result == mock_response
        assert used_upstream == {'host': '1.1.1.1', 'port': 53}
        assert reason == 'ok'
        mock_query.send.assert_called_once_with('1.1.1.1', 53, timeout=2.0)


@patch('foghorn.server.logger')
def test_send_query_with_failover_servfail_then_success(mock_logger):
    """Test failover on SERVFAIL, then success."""
    mock_query = Mock()
    
    # First call returns SERVFAIL, second returns NOERROR
    responses = [b'servfail_response', b'success_response']
    mock_query.send.side_effect = responses
    
    with patch('foghorn.server.DNSRecord.parse') as mock_parse:
        # First response is SERVFAIL, second is NOERROR
        records = []
        for rcode in [RCODE.SERVFAIL, RCODE.NOERROR]:
            mock_record = Mock()
            mock_record.header.rcode = rcode
            records.append(mock_record)
        mock_parse.side_effect = records
        
        upstreams = [
            {'host': '1.1.1.1', 'port': 53},
            {'host': '1.0.0.1', 'port': 53}
        ]
        result, used_upstream, reason = send_query_with_failover(
            mock_query, upstreams, 2000, 'example.com', 1
        )
        
        assert result == b'success_response'
        assert used_upstream == {'host': '1.0.0.1', 'port': 53}
        assert reason == 'ok'
        assert mock_query.send.call_count == 2


@patch('foghorn.server.logger')
def test_send_query_with_failover_no_failover_on_nxdomain(mock_logger):
    """Test that NXDOMAIN doesn't trigger failover."""
    mock_query = Mock()
    mock_response = b'nxdomain_response'
    mock_query.send.return_value = mock_response
    
    with patch('foghorn.server.DNSRecord.parse') as mock_parse:
        mock_record = Mock()
        mock_record.header.rcode = RCODE.NXDOMAIN
        mock_parse.return_value = mock_record
        
        upstreams = [
            {'host': '1.1.1.1', 'port': 53},
            {'host': '1.0.0.1', 'port': 53}
        ]
        result, used_upstream, reason = send_query_with_failover(
            mock_query, upstreams, 2000, 'example.com', 1
        )
        
        assert result == mock_response
        assert used_upstream == {'host': '1.1.1.1', 'port': 53}
        assert reason == 'ok'
        # Should not try second upstream
        assert mock_query.send.call_count == 1


@patch('foghorn.server.logger')
def test_send_query_with_failover_all_fail(mock_logger):
    """Test all upstreams fail."""
    mock_query = Mock()
    mock_query.send.side_effect = Exception('Connection failed')
    
    upstreams = [
        {'host': '1.1.1.1', 'port': 53},
        {'host': '1.0.0.1', 'port': 53}
    ]
    result, used_upstream, reason = send_query_with_failover(
        mock_query, upstreams, 2000, 'example.com', 1
    )
    
    assert result is None
    assert used_upstream is None
    assert reason == 'all_failed'
    assert mock_query.send.call_count == 2
    mock_logger.warning.assert_called_once()


if __name__ == '__main__':
    pytest.main([__file__])
"""Brief: Tests for AdminRuntimeState in-memory admin state management.

Inputs:
  - None.

Outputs:
  - None; pytest assertions cover state mutation and branch behavior.
"""

from __future__ import annotations


import pytest

from foghorn.servers.webserver.admin_state import AdminRuntimeState


def test_last_config_verify_roundtrip_and_copy_semantics() -> None:
    """Brief: Last config verify payload is copied on write and read.

    Inputs:
      - None.

    Outputs:
      - None; asserts None default and copy semantics.
    """

    state = AdminRuntimeState()
    assert state.get_last_config_verify() is None

    payload = {'ok': True, 'nested': {'a': 1}}
    state.set_last_config_verify(payload)
    out = state.get_last_config_verify()
    assert out == payload
    assert out is not payload


def test_restart_pending_payload_fields() -> None:
    """Brief: Restart metadata includes schedule and optional reason fields.

    Inputs:
      - None.

    Outputs:
      - None; asserts payload shape and optional reason handling.
    """

    state = AdminRuntimeState()
    with_reason = state.set_restart_pending(
        delay_seconds=5.0,
        reason='config reload',
        signal_name='SIGTERM',
    )
    assert with_reason['scheduled'] is True
    assert with_reason['signal'] == 'SIGTERM'
    assert with_reason['delay_seconds'] == 5.0
    assert with_reason['reason'] == 'config reload'
    assert with_reason['expected_at_ts'] >= with_reason['scheduled_at_ts']

    no_reason = state.set_restart_pending(delay_seconds=1.0, reason=None)
    assert no_reason['reason'] is None
    assert state.get_restart_pending() == no_reason


def test_audit_event_bounded_ring_filtering_and_clear_count() -> None:
    """Brief: Audit events enforce bounded retention and support filtering/clear.

    Inputs:
      - None.

    Outputs:
      - None; asserts ring truncation, action filtering, and clear count.
    """

    state = AdminRuntimeState(audit_max_entries=2)
    state.add_audit_event(action='a', target='t1', ok=True)
    state.add_audit_event(action='b', target='t2', ok=False)
    state.add_audit_event(action='a', target='t3', ok=True)

    events = state.list_audit_events(limit=10)
    assert [it['target'] for it in events] == ['t3', 't2']

    filtered = state.list_audit_events(action='a')
    assert [it['target'] for it in filtered] == ['t3']

    removed = state.clear_audit_events()
    assert removed == 2
    assert state.list_audit_events() == []


def test_list_audit_events_limit_normalization() -> None:
    """Brief: Audit listing treats zero as default and clamps large limits.

    Inputs:
      - None.

    Outputs:
      - None; asserts zero fallback-to-default and upper-bound clamping behavior.
    """

    state = AdminRuntimeState()
    for idx in range(3):
        state.add_audit_event(action='x', target=f't{idx}', ok=True)

    low = state.list_audit_events(limit=0)
    assert len(low) == 3

    high = state.list_audit_events(limit=10_000)
    assert len(high) == 3


def test_upsert_temporary_record_preserves_created_ts_and_applies_ttl_rules() -> None:
    """Brief: Temporary upsert applies zero-default and negative-clamp ttl rules.

    Inputs:
      - None.

    Outputs:
      - None; asserts ttl normalization and created_at_ts preservation.
    """

    state = AdminRuntimeState()
    created = state.upsert_temporary_record(
        key='k1',
        target='etc_hosts',
        plugin='p1',
        payload={'v': 1},
        ttl_seconds=0,
    )
    assert created['ttl_seconds'] == 300
    created_ts = created['created_at_ts']

    clamped = state.upsert_temporary_record(
        key='k2',
        target='etc_hosts',
        plugin='p1',
        payload={'v': 3},
        ttl_seconds=-5,
    )
    assert clamped['ttl_seconds'] == 1

    updated = state.upsert_temporary_record(
        key='k1',
        target='etc_hosts',
        plugin='p1',
        payload={'v': 2},
        ttl_seconds=10,
    )
    assert updated['created_at_ts'] == created_ts
    assert updated['payload']['v'] == 2
    assert updated['updated_at_ts'] >= created_ts


def test_remove_temporary_record_returns_boolean() -> None:
    """Brief: Temporary record removal reports existence correctly.

    Inputs:
      - None.

    Outputs:
      - None; asserts True for existing key and False otherwise.
    """

    state = AdminRuntimeState()
    state.upsert_temporary_record(key='k2', target='etc_hosts', plugin='p2')
    assert state.remove_temporary_record(key='k2') is True
    assert state.remove_temporary_record(key='k2') is False


def test_list_temporary_records_filters_expiry_and_limit() -> None:
    """Brief: Temporary listing supports filters, expiry gating, and limit behavior.

    Inputs:
      - None.

    Outputs:
      - None; asserts include_expired, filters, and zero-limit default behavior.
    """

    state = AdminRuntimeState()
    now = 100.0
    state._temporary_records = {
        'a': {  # type: ignore[attr-defined]
            'key': 'a',
            'target': 'etc_hosts',
            'plugin': 'p1',
            'updated_at_ts': 3.0,
            'expires_at_ts': 50.0,
        },
        'b': {  # type: ignore[attr-defined]
            'key': 'b',
            'target': 'zone_records',
            'plugin': 'p2',
            'updated_at_ts': 4.0,
            'expires_at_ts': 150.0,
        },
    }

    def _fake_time() -> float:
        return now

    from foghorn.servers.webserver import admin_state as admin_state_mod

    original_time = admin_state_mod.time.time
    admin_state_mod.time.time = _fake_time  # type: ignore[assignment]
    try:
        all_items = state.list_temporary_records(limit=0)
        assert len(all_items) == 2
        assert [it['key'] for it in all_items] == ['b', 'a']
        assert all_items[0]['expired'] is False

        p1_items = state.list_temporary_records(
            target='etc_hosts',
            plugin='p1',
            include_expired=True,
            limit=10,
        )
        assert len(p1_items) == 1
        assert p1_items[0]['expired'] is True

        non_expired = state.list_temporary_records(include_expired=False, limit=10)
        assert [it['key'] for it in non_expired] == ['b']
    finally:
        admin_state_mod.time.time = original_time  # type: ignore[assignment]


def test_purge_expired_temporary_records_handles_mixed_entries() -> None:
    """Brief: Purge removes only expired dict records and leaves others untouched.

    Inputs:
      - None.

    Outputs:
      - None; asserts mixed-state handling and now_ts override behavior.
    """

    state = AdminRuntimeState()
    state._temporary_records = {  # type: ignore[attr-defined]
        'bad': 'not-a-dict',
        'no-expiry': {'key': 'k0', 'expires_at_ts': 0.0},
        'future': {'key': 'k1', 'expires_at_ts': 20.0},
        'expired': {'key': 'k2', 'expires_at_ts': 5.0},
    }

    removed = state.purge_expired_temporary_records(now_ts=10.0)
    assert [it['key'] for it in removed] == ['k2']
    assert 'expired' not in state._temporary_records  # type: ignore[attr-defined]
    assert 'future' in state._temporary_records  # type: ignore[attr-defined]
    assert 'bad' in state._temporary_records  # type: ignore[attr-defined]


def test_add_task_defaults_bounded_history_and_list_filters() -> None:
    """Brief: Task history enforces ring bounds and supports filters/limit behavior.

    Inputs:
      - None.

    Outputs:
      - None; asserts default values, truncation, and zero-limit default behavior.
    """

    state = AdminRuntimeState(audit_max_entries=2)
    first = state.add_task(task_type='', status='', details={'n': 1})
    state.add_task(task_type='sync', status='done')
    state.add_task(task_type='sync', status='failed')

    assert first['task_type'] == 'unknown'
    assert first['status'] == 'done'

    tasks = state.list_tasks(limit=10)
    assert [it['status'] for it in tasks] == ['failed', 'done']

    filtered = state.list_tasks(task_type='sync', status='failed', limit=10)
    assert len(filtered) == 1
    assert filtered[0]['status'] == 'failed'

    low = state.list_tasks(limit=0)
    assert len(low) == 2


def test_limit_parsing_raises_for_non_numeric_limit_values() -> None:
    """Brief: List helpers propagate ValueError for non-numeric limit values.

    Inputs:
      - None.

    Outputs:
      - None; asserts int() conversion failures are surfaced.
    """

    state = AdminRuntimeState()
    with pytest.raises(ValueError):
        state.list_audit_events(limit='bad')  # type: ignore[arg-type]
    with pytest.raises(ValueError):
        state.list_temporary_records(limit='bad')  # type: ignore[arg-type]
    with pytest.raises(ValueError):
        state.list_tasks(limit='bad')  # type: ignore[arg-type]


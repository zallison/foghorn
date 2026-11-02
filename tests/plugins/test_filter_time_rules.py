"""
Brief: Tests for Filter time-of-day / day-of-week rules (time_rules).

Inputs:
  - None

Outputs:
  - None
"""

from datetime import UTC, datetime
from zoneinfo import ZoneInfo

import pytest
from dnslib import QTYPE, RCODE, DNSRecord
from pydantic import ValidationError

from foghorn.plugins.resolve.base import PluginContext
from foghorn.plugins.resolve.filter import Filter, FilterConfig, TimeRule, TimeWindow

# Fixed instant used for timezone conversion tests: 17:30 UTC on a November
# day, which is 12:30 in America/New_York (EST, UTC-5).
FIXED_INSTANT_UTC = datetime(2026, 11, 1, 17, 30, tzinfo=UTC)


def _make_plugin(instant_utc: datetime, **config):
    """
    Brief: Build a Filter with setup() done and a pinned clock.

    Inputs:
      - instant_utc: Fixed UTC instant the plugin clock reports.
      - **config: Plugin configuration kwargs; the default policy is "allow"
        unless overridden so time rules are the only denial source.

    Outputs:
      - Filter whose _now() returns instant_utc converted to its timezone.
    """
    config.setdefault("default", "allow")
    plugin = Filter(**config)
    plugin.setup()

    def _pinned_now():
        return instant_utc.astimezone(plugin._time_tz)

    plugin._now = _pinned_now
    return plugin


def _ctx(client_ip: str = "192.168.1.50") -> PluginContext:
    """
    Brief: Build a minimal PluginContext for pre_resolve calls.

    Inputs:
      - client_ip: Client IP to place in the context.

    Outputs:
      - PluginContext instance.
    """
    return PluginContext(client_ip=client_ip, listener="udp", secure=False)


def _question(qname: str = "ads.example.com.") -> bytes:
    """
    Brief: Pack a minimal DNS question for pre_resolve calls.

    Inputs:
      - qname: Domain name to query.

    Outputs:
      - bytes: Packed DNS question record.
    """
    return DNSRecord.question(qname, "A").pack()


def _is_pass(decision) -> bool:
    """
    Brief: True when a pre_resolve decision lets the query continue.

    Inputs:
      - decision: PluginDecision (or None).

    Outputs:
      - bool: True for None or action="skip".
    """
    return decision is None or getattr(decision, "action", None) == "skip"


def test_config_model_normalizes_windows_and_domains():
    """
    Brief: Verify the config model parses HH:MM windows and normalizes domains.

    Inputs:
      - config: one rule with 'Ads.Example.COM.' and a 09:00-17:00 window

    Outputs:
      - None: Asserts minutes normalization and domain lower-casing
    """
    cfg = FilterConfig(
        time_rules=[
            {
                "domains": ["Ads.Example.COM."],
                "windows": [{"start": "09:00", "end": "17:00"}],
            }
        ]
    )
    rule = cfg.time_rules[0]
    assert rule.domains == ["ads.example.com"]
    assert rule.windows[0].start == 9 * 60
    assert rule.windows[0].end == 17 * 60
    assert rule.action == "deny"


def test_config_model_accepts_single_domain_string():
    """
    Brief: Verify a bare domain string is accepted as a one-item list.

    Inputs:
      - config: rule with domains given as a single string

    Outputs:
      - None: Asserts it normalizes to a one-element list
    """
    cfg = FilterConfig(
        time_rules=[
            {"domains": "example.com", "windows": [{"start": "00:00", "end": "01:00"}]}
        ]
    )
    assert cfg.time_rules[0].domains == ["example.com"]


def test_config_model_rejects_invalid_times():
    """
    Brief: Verify malformed time strings fail validation.

    Inputs:
      - config: rules with '25:00', '12:60', and 'noon' values

    Outputs:
      - None: Asserts ValidationError is raised for each
    """
    bad_values = ["25:00", "12:60", "noon"]
    for value in bad_values:
        with pytest.raises(ValidationError):
            FilterConfig(
                time_rules=[
                    {
                        "domains": ["example.com"],
                        "windows": [{"start": value, "end": "17:00"}],
                    }
                ]
            )


def test_config_model_requires_domains():
    """
    Brief: Verify rules need at least one domain; empty windows become full-day.

    Inputs:
      - config: rule with empty domains; rule with no windows

    Outputs:
      - None: Asserts ValidationError for empty domains and full-day default windows
    """
    with pytest.raises(ValidationError):
        FilterConfig(
            time_rules=[
                {"domains": [], "windows": [{"start": "09:00", "end": "17:00"}]}
            ]
        )
    cfg = FilterConfig(time_rules=[{"domains": ["example.com"], "windows": []}])
    assert cfg.time_rules[0].windows[0].start == 0
    assert cfg.time_rules[0].windows[0].end == 0


def test_setup_without_time_rules_is_inert():
    """
    Brief: Verify setup() with no time rules leaves queries untouched.

    Inputs:
      - config: none (default policy allow)

    Outputs:
      - None: Asserts pre_resolve passes the query and a timezone is set
    """
    plugin = Filter(default="allow")
    plugin.setup()
    assert plugin._time_tz is not None
    assert plugin._time_rules == []
    assert _is_pass(
        plugin.pre_resolve("example.com.", QTYPE.A, _question("example.com."), _ctx())
    )


def test_setup_rejects_unknown_timezone():
    """
    Brief: Verify setup() raises on an unknown IANA timezone name.

    Inputs:
      - config: timezone set to a bogus name

    Outputs:
      - None: Asserts ValueError is raised
    """
    plugin = Filter(timezone="Not/AZone")
    with pytest.raises(ValueError):
        plugin.setup()


def test_setup_resolves_iana_timezone():
    """
    Brief: Verify setup() stores the configured ZoneInfo.

    Inputs:
      - config: timezone set to America/New_York

    Outputs:
      - None: Asserts the resolved zone matches
    """
    plugin = Filter(timezone="America/New_York")
    plugin.setup()
    assert plugin._time_tz == ZoneInfo("America/New_York")


def test_setup_rejects_non_mapping_rule_entry():
    """
    Brief: Verify a non-mapping time rule entry raises TypeError.

    Inputs:
      - config: time_rules containing a bare integer

    Outputs:
      - None: Asserts TypeError is raised by setup()
    """
    plugin = Filter(time_rules=[42])
    with pytest.raises(ValidationError):
        plugin.setup()


def test_setup_rejects_invalid_action():
    """
    Brief: Verify an unknown rule action raises ValueError.

    Inputs:
      - config: rule with action 'block'

    Outputs:
      - None: Asserts ValueError is raised by setup()
    """
    plugin = Filter(
        time_rules=[
            {
                "domains": ["example.com"],
                "windows": [{"start": "09:00", "end": "17:00"}],
                "action": "block",
            }
        ]
    )
    with pytest.raises(ValidationError):
        plugin.setup()


def test_setup_rejects_rule_without_domains():
    """
    Brief: Verify rules need at least one domain (raw path).

    Inputs:
      - config: rule missing domains; rule with empty windows defaults full-day

    Outputs:
      - None: Asserts ValidationError without domains; empty windows compile
    """
    with pytest.raises(ValidationError):
        Filter(time_rules=[{"windows": [{"start": "09:00", "end": "17:00"}]}]).setup()
    plugin = Filter(time_rules=[{"domains": ["example.com"], "windows": []}])
    plugin.setup()
    assert plugin._time_rules == [(("example.com",), ((0, 0),), frozenset(), "deny")]


def test_setup_rejects_invalid_window_type():
    """
    Brief: Verify a window that is not a mapping raises TypeError.

    Inputs:
      - config: rule whose windows list holds a bare string

    Outputs:
      - None: Asserts TypeError is raised by setup()
    """
    plugin = Filter(
        time_rules=[
            {
                "domains": ["example.com"],
                "windows": ["09:00-17:00"],
            }
        ]
    )
    with pytest.raises(ValidationError):
        plugin.setup()


def test_setup_rejects_out_of_range_time():
    """
    Brief: Verify an out-of-range HH:MM value raises ValueError (raw path).

    Inputs:
      - config: rule with start '25:00'

    Outputs:
      - None: Asserts ValueError is raised by setup()
    """
    plugin = Filter(
        time_rules=[
            {
                "domains": ["example.com"],
                "windows": [{"start": "25:00", "end": "17:00"}],
            }
        ]
    )
    with pytest.raises(ValidationError):
        plugin.setup()


def test_setup_accepts_model_instances():
    """
    Brief: Verify setup() compiles TimeRule/TimeWindow model instances.

    Inputs:
      - config: time_rules holding a TimeRule with a TimeWindow

    Outputs:
      - None: Asserts the compiled internal form
    """
    plugin = Filter(
        timezone="UTC",
        time_rules=[
            TimeRule(
                domains=["example.com"],
                windows=[TimeWindow(start="09:00", end="17:00")],
            )
        ],
    )
    plugin.setup()
    assert plugin._time_rules == [
        (("example.com",), ((540, 1020),), frozenset(), "deny")
    ]


def test_deny_inside_window():
    """
    Brief: Verify a matching domain inside its window is denied.

    Inputs:
      - config: rule blocking ads.example.com 09:00-17:00 UTC
      - clock: 12:00 UTC

    Outputs:
      - None: Asserts a deny decision
    """
    plugin = _make_plugin(
        datetime(2026, 11, 1, 12, 0, tzinfo=UTC),
        timezone="UTC",
        time_rules=[
            {
                "domains": ["ads.example.com"],
                "windows": [{"start": "09:00", "end": "17:00"}],
            }
        ],
    )
    decision = plugin.pre_resolve("ads.example.com.", QTYPE.A, _question(), _ctx())
    assert decision is not None
    assert decision.action == "deny"


def test_allow_outside_window():
    """
    Brief: Verify a matching domain outside its window passes through.

    Inputs:
      - config: rule blocking ads.example.com 09:00-17:00 UTC
      - clock: 18:00 UTC

    Outputs:
      - None: Asserts the query is allowed to continue
    """
    plugin = _make_plugin(
        datetime(2026, 11, 1, 18, 0, tzinfo=UTC),
        timezone="UTC",
        time_rules=[
            {
                "domains": ["ads.example.com"],
                "windows": [{"start": "09:00", "end": "17:00"}],
            }
        ],
    )
    assert _is_pass(
        plugin.pre_resolve("ads.example.com.", QTYPE.A, _question(), _ctx())
    )


def test_window_boundaries_start_inclusive_end_exclusive():
    """
    Brief: Verify the start minute blocks and the end minute passes.

    Inputs:
      - config: rule blocking 09:00-17:00 UTC
      - clock: exactly 09:00, then exactly 17:00

    Outputs:
      - None: Asserts deny at start and pass at end
    """
    rules = [
        {
            "domains": ["example.com"],
            "windows": [{"start": "09:00", "end": "17:00"}],
        }
    ]
    at_start = _make_plugin(
        datetime(2026, 11, 1, 9, 0, tzinfo=UTC), timezone="UTC", time_rules=rules
    )
    decision = at_start.pre_resolve(
        "example.com.", QTYPE.A, _question("example.com."), _ctx()
    )
    assert decision is not None and decision.action == "deny"

    at_end = _make_plugin(
        datetime(2026, 11, 1, 17, 0, tzinfo=UTC), timezone="UTC", time_rules=rules
    )
    assert _is_pass(
        at_end.pre_resolve("example.com.", QTYPE.A, _question("example.com."), _ctx())
    )


def test_wraparound_window_across_midnight():
    """
    Brief: Verify a window whose start is after its end wraps midnight.

    Inputs:
      - config: rule blocking 22:00-06:00 UTC
      - clock: 23:00, 03:00, and 12:00

    Outputs:
      - None: Asserts deny before and after midnight, pass at noon
    """
    rules = [
        {
            "domains": ["example.com"],
            "windows": [{"start": "22:00", "end": "06:00"}],
        }
    ]
    for hour in (23, 3):
        plugin = _make_plugin(
            datetime(2026, 11, 1, hour, 0, tzinfo=UTC),
            timezone="UTC",
            time_rules=rules,
        )
        decision = plugin.pre_resolve(
            "example.com.", QTYPE.A, _question("example.com."), _ctx()
        )
        assert decision is not None and decision.action == "deny"

    noon = _make_plugin(
        datetime(2026, 11, 1, 12, 0, tzinfo=UTC), timezone="UTC", time_rules=rules
    )
    assert _is_pass(
        noon.pre_resolve("example.com.", QTYPE.A, _question("example.com."), _ctx())
    )


def test_full_day_window_when_start_equals_end():
    """
    Brief: Verify a window with start == end blocks the entire day.

    Inputs:
      - config: rule blocking 00:00-00:00 UTC
      - clock: 00:30 and 23:59

    Outputs:
      - None: Asserts deny at both times
    """
    rules = [
        {
            "domains": ["example.com"],
            "windows": [{"start": "00:00", "end": "00:00"}],
        }
    ]
    for hour, minute in ((0, 30), (23, 59)):
        plugin = _make_plugin(
            datetime(2026, 11, 1, hour, minute, tzinfo=UTC),
            timezone="UTC",
            time_rules=rules,
        )
        decision = plugin.pre_resolve(
            "example.com.", QTYPE.A, _question("example.com."), _ctx()
        )
        assert decision is not None and decision.action == "deny"


def test_any_window_matches():
    """
    Brief: Verify a rule with multiple windows triggers on any of them.

    Inputs:
      - config: rule blocking 08:00-09:00 or 12:00-13:00 UTC
      - clock: 12:30 (second window) and 10:00 (neither)

    Outputs:
      - None: Asserts deny in the second window, pass between them
    """
    rules = [
        {
            "domains": ["example.com"],
            "windows": [
                {"start": "08:00", "end": "09:00"},
                {"start": "12:00", "end": "13:00"},
            ],
        }
    ]
    lunch = _make_plugin(
        datetime(2026, 11, 1, 12, 30, tzinfo=UTC), timezone="UTC", time_rules=rules
    )
    decision = lunch.pre_resolve(
        "example.com.", QTYPE.A, _question("example.com."), _ctx()
    )
    assert decision is not None and decision.action == "deny"

    between = _make_plugin(
        datetime(2026, 11, 1, 10, 0, tzinfo=UTC), timezone="UTC", time_rules=rules
    )
    assert _is_pass(
        between.pre_resolve("example.com.", QTYPE.A, _question("example.com."), _ctx())
    )


def test_domain_suffix_matching():
    """
    Brief: Verify a rule domain matches itself and subdomains only.

    Inputs:
      - config: rule blocking ads.example.com 00:00-23:59 UTC
      - qnames: exact, subdomain, lookalike, and parent names

    Outputs:
      - None: Asserts deny for exact/subdomain, pass for lookalike/parent
    """
    plugin = _make_plugin(
        datetime(2026, 11, 1, 12, 0, tzinfo=UTC),
        timezone="UTC",
        time_rules=[
            {
                "domains": ["ads.example.com"],
                "windows": [{"start": "00:00", "end": "23:59"}],
            }
        ],
    )
    assert (
        plugin.pre_resolve("ads.example.com.", QTYPE.A, _question(), _ctx()) is not None
    )
    assert (
        plugin.pre_resolve(
            "sub.ads.example.com.", QTYPE.A, _question("sub.ads.example.com."), _ctx()
        )
        is not None
    )
    # "notads.example.com" shares a label suffix but is a different host.
    assert _is_pass(
        plugin.pre_resolve(
            "notads.example.com.", QTYPE.A, _question("notads.example.com."), _ctx()
        )
    )
    # The parent domain is not covered by the rule.
    assert _is_pass(
        plugin.pre_resolve("example.com.", QTYPE.A, _question("example.com."), _ctx())
    )


def test_qname_case_and_trailing_dot_normalization():
    """
    Brief: Verify qname matching is case-insensitive and dot-tolerant.

    Inputs:
      - config: rule blocking ads.example.com 00:00-23:59 UTC
      - qnames: mixed-case with trailing dot, and without trailing dot

    Outputs:
      - None: Asserts deny for both spellings of the same name
    """
    plugin = _make_plugin(
        datetime(2026, 11, 1, 12, 0, tzinfo=UTC),
        timezone="UTC",
        time_rules=[
            {
                "domains": ["ads.example.com"],
                "windows": [{"start": "00:00", "end": "23:59"}],
            }
        ],
    )
    assert (
        plugin.pre_resolve(
            "ADS.Example.COM.", QTYPE.A, _question("ADS.Example.COM."), _ctx()
        )
        is not None
    )
    assert (
        plugin.pre_resolve(
            "ads.example.com", QTYPE.A, _question("ads.example.com"), _ctx()
        )
        is not None
    )


def test_drop_action():
    """
    Brief: Verify a rule with action 'drop' returns a drop decision.

    Inputs:
      - config: rule with action 'drop', active window covering the clock

    Outputs:
      - None: Asserts decision.action == 'drop'
    """
    plugin = _make_plugin(
        datetime(2026, 11, 1, 12, 0, tzinfo=UTC),
        timezone="UTC",
        time_rules=[
            {
                "domains": ["example.com"],
                "windows": [{"start": "09:00", "end": "17:00"}],
                "action": "drop",
            }
        ],
    )
    decision = plugin.pre_resolve(
        "example.com.", QTYPE.A, _question("example.com."), _ctx()
    )
    assert decision is not None
    assert decision.action == "drop"


def test_base_plugin_targets_still_apply():
    """
    Brief: Verify BasePlugin IP targeting bypasses the time rules.

    Inputs:
      - config: targets 10.0.0.0/8 with an always-active rule
      - clients: one inside and one outside the target CIDR

    Outputs:
      - None: Asserts deny for the targeted client, pass for the other
    """
    plugin = _make_plugin(
        datetime(2026, 11, 1, 12, 0, tzinfo=UTC),
        timezone="UTC",
        targets=["10.0.0.0/8"],
        time_rules=[
            {
                "domains": ["example.com"],
                "windows": [{"start": "00:00", "end": "23:59"}],
            }
        ],
    )
    decision = plugin.pre_resolve(
        "example.com.", QTYPE.A, _question("example.com."), _ctx("10.0.0.5")
    )
    assert decision is not None and decision.action == "deny"
    assert _is_pass(
        plugin.pre_resolve(
            "example.com.", QTYPE.A, _question("example.com."), _ctx("192.0.2.7")
        )
    )


def test_timezone_conversion_uses_configured_zone():
    """
    Brief: Verify the same instant blocks in one zone and passes in another.

    Inputs:
      - config: rule blocking 12:00-13:00, timezone America/New_York vs UTC
      - clock: fixed 17:30 UTC (12:30 EST)

    Outputs:
      - None: Asserts deny in New York time and pass in UTC
    """
    rules = [
        {
            "domains": ["example.com"],
            "windows": [{"start": "12:00", "end": "13:00"}],
        }
    ]
    ny = _make_plugin(FIXED_INSTANT_UTC, timezone="America/New_York", time_rules=rules)
    decision = ny.pre_resolve(
        "example.com.", QTYPE.A, _question("example.com."), _ctx()
    )
    assert decision is not None and decision.action == "deny"

    utc = _make_plugin(FIXED_INSTANT_UTC, timezone="UTC", time_rules=rules)
    assert _is_pass(
        utc.pre_resolve("example.com.", QTYPE.A, _question("example.com."), _ctx())
    )


def test_empty_qname_returns_no_decision():
    """
    Brief: Verify empty or dot-only qnames never match a rule.

    Inputs:
      - config: always-active rule
      - qnames: empty string and bare trailing dot

    Outputs:
      - None: Asserts no blocking decision is returned
    """
    plugin = _make_plugin(
        datetime(2026, 11, 1, 12, 0, tzinfo=UTC),
        timezone="UTC",
        time_rules=[
            {
                "domains": ["example.com"],
                "windows": [{"start": "00:00", "end": "23:59"}],
            }
        ],
    )
    assert _is_pass(plugin.pre_resolve("", QTYPE.A, b"", _ctx()))
    assert _is_pass(plugin.pre_resolve(".", QTYPE.A, b"", _ctx()))


def test_time_rule_deny_respects_deny_response_policy():
    """
    Brief: Verify a time-rule deny follows the plugin deny_response policy.

    Inputs:
      - config: deny_response 'refused' with a rule active at 12:00 UTC

    Outputs:
      - None: Asserts an override decision carrying REFUSED
    """
    plugin = _make_plugin(
        datetime(2026, 11, 1, 12, 0, tzinfo=UTC),
        timezone="UTC",
        deny_response="refused",
        time_rules=[
            {
                "domains": ["example.com"],
                "windows": [{"start": "09:00", "end": "17:00"}],
            }
        ],
    )
    decision = plugin.pre_resolve(
        "example.com.", QTYPE.A, _question("example.com."), _ctx()
    )
    assert decision is not None
    assert decision.action == "override"
    reply = DNSRecord.parse(decision.response)
    assert reply.header.rcode == RCODE.REFUSED


def test_time_rules_not_served_from_decision_cache():
    """
    Brief: Verify time decisions bypass the TTL decision cache in both directions.

    Inputs:
      - config: rule blocking 09:00-17:00 UTC; clock moves 18:00 -> 12:00 -> 18:30

    Outputs:
      - None: Asserts pass, then deny despite the cached allow, then pass again
        (proving the in-window deny was never cached)
    """
    rules = [
        {
            "domains": ["example.com"],
            "windows": [{"start": "09:00", "end": "17:00"}],
        }
    ]
    plugin = _make_plugin(
        datetime(2026, 11, 1, 18, 0, tzinfo=UTC), timezone="UTC", time_rules=rules
    )
    # Outside the window: allowed and cached as such.
    assert _is_pass(
        plugin.pre_resolve("example.com.", QTYPE.A, _question("example.com."), _ctx())
    )

    def _pinned_noon():
        return datetime(2026, 11, 1, 12, 0, tzinfo=UTC).astimezone(plugin._time_tz)

    plugin._now = _pinned_noon
    # Inside the window: denied even though an allow decision is cached.
    decision = plugin.pre_resolve(
        "example.com.", QTYPE.A, _question("example.com."), _ctx()
    )
    assert decision is not None and decision.action == "deny"

    def _pinned_evening():
        return datetime(2026, 11, 1, 18, 30, tzinfo=UTC).astimezone(plugin._time_tz)

    plugin._now = _pinned_evening
    # After the window closes: allowed again (the deny was never cached).
    assert _is_pass(
        plugin.pre_resolve("example.com.", QTYPE.A, _question("example.com."), _ctx())
    )


def test_time_rule_takes_precedence_over_allowlist():
    """
    Brief: Verify an active time rule blocks even an explicitly allowed domain.

    Inputs:
      - config: default deny, allowlisted example.com, rule 09:00-17:00 UTC
      - clock: 12:00 (inside window) then 18:00 (outside)

    Outputs:
      - None: Asserts deny inside the window and pass outside it
    """
    plugin = _make_plugin(
        datetime(2026, 11, 1, 12, 0, tzinfo=UTC),
        timezone="UTC",
        default="deny",
        allowed_domains=["example.com"],
        time_rules=[
            {
                "domains": ["example.com"],
                "windows": [{"start": "09:00", "end": "17:00"}],
            }
        ],
    )
    decision = plugin.pre_resolve(
        "example.com.", QTYPE.A, _question("example.com."), _ctx()
    )
    assert decision is not None and decision.action == "deny"

    def _pinned_evening():
        return datetime(2026, 11, 1, 18, 0, tzinfo=UTC).astimezone(plugin._time_tz)

    plugin._now = _pinned_evening
    assert _is_pass(
        plugin.pre_resolve("example.com.", QTYPE.A, _question("example.com."), _ctx())
    )


def test_config_model_parses_days_aliases_and_groups():
    """
    Brief: Verify day names, numbers, and groups normalize to ISO weekdays.

    Inputs:
      - config: rules using mon/Friday/1 and weekdays/weekend groups

    Outputs:
      - None: Asserts frozenset day membership
    """
    cfg = FilterConfig(
        time_rules=[
            {
                "domains": ["example.com"],
                "windows": [{"start": "09:00", "end": "17:00"}],
                "days": ["mon", "Friday", 1, "7"],
            },
            {
                "domains": ["example.com"],
                "windows": [{"start": "09:00", "end": "17:00"}],
                "days": "weekdays",
            },
            {
                "domains": ["example.com"],
                "windows": [{"start": "09:00", "end": "17:00"}],
                "days": ["weekend"],
            },
        ]
    )
    assert cfg.time_rules[0].days == frozenset({1, 5, 7})
    assert cfg.time_rules[1].days == frozenset({1, 2, 3, 4, 5})
    assert cfg.time_rules[2].days == frozenset({6, 7})


def test_config_model_rejects_invalid_days():
    """
    Brief: Verify unknown day tokens fail validation.

    Inputs:
      - config: rule with days=['funday']

    Outputs:
      - None: Asserts ValidationError
    """
    with pytest.raises(ValidationError):
        FilterConfig(
            time_rules=[
                {
                    "domains": ["example.com"],
                    "windows": [{"start": "09:00", "end": "17:00"}],
                    "days": ["funday"],
                }
            ]
        )


def test_days_filter_allows_only_selected_weekdays():
    """
    Brief: Verify a daytime window only matches configured weekdays.

    Inputs:
      - config: weekdays-only 09:00-17:00 rule
      - clock: Monday noon, Saturday noon

    Outputs:
      - None: Asserts deny on Monday and pass on Saturday
    """
    # 2026-11-02 is a Monday; 2026-11-07 is a Saturday.
    rules = [
        {
            "domains": ["example.com"],
            "windows": [{"start": "09:00", "end": "17:00"}],
            "days": "weekdays",
        }
    ]
    monday = _make_plugin(
        datetime(2026, 11, 2, 12, 0, tzinfo=UTC), timezone="UTC", time_rules=rules
    )
    decision = monday.pre_resolve(
        "example.com.", QTYPE.A, _question("example.com."), _ctx()
    )
    assert decision is not None and decision.action == "deny"

    saturday = _make_plugin(
        datetime(2026, 11, 7, 12, 0, tzinfo=UTC), timezone="UTC", time_rules=rules
    )
    assert _is_pass(
        saturday.pre_resolve("example.com.", QTYPE.A, _question("example.com."), _ctx())
    )


def test_overnight_window_owned_by_start_day():
    """
    Brief: Verify wraparound windows stay owned by the start weekday.

    Inputs:
      - config: days=['mon'], window 22:00-06:00
      - clock: Monday 23:00, Tuesday 03:00, Tuesday 23:00, Sunday 23:00

    Outputs:
      - None: Asserts deny Mon night and Tue morning; pass Tue night and Sun night
    """
    rules = [
        {
            "domains": ["example.com"],
            "windows": [{"start": "22:00", "end": "06:00"}],
            "days": ["mon"],
        }
    ]
    # Monday 2026-11-02 23:00 UTC
    mon_night = _make_plugin(
        datetime(2026, 11, 2, 23, 0, tzinfo=UTC), timezone="UTC", time_rules=rules
    )
    decision = mon_night.pre_resolve(
        "example.com.", QTYPE.A, _question("example.com."), _ctx()
    )
    assert decision is not None and decision.action == "deny"

    # Tuesday 2026-11-03 03:00 still owned by Monday start day
    tue_morning = _make_plugin(
        datetime(2026, 11, 3, 3, 0, tzinfo=UTC), timezone="UTC", time_rules=rules
    )
    decision = tue_morning.pre_resolve(
        "example.com.", QTYPE.A, _question("example.com."), _ctx()
    )
    assert decision is not None and decision.action == "deny"

    # Tuesday night is not Monday-owned
    tue_night = _make_plugin(
        datetime(2026, 11, 3, 23, 0, tzinfo=UTC), timezone="UTC", time_rules=rules
    )
    assert _is_pass(
        tue_night.pre_resolve(
            "example.com.", QTYPE.A, _question("example.com."), _ctx()
        )
    )

    # Sunday night is not Monday-owned
    sun_night = _make_plugin(
        datetime(2026, 11, 1, 23, 0, tzinfo=UTC), timezone="UTC", time_rules=rules
    )
    assert _is_pass(
        sun_night.pre_resolve(
            "example.com.", QTYPE.A, _question("example.com."), _ctx()
        )
    )


def test_days_only_rule_defaults_to_full_day_window():
    """
    Brief: Verify omitting windows blocks the whole selected day.

    Inputs:
      - config: days=['sat'] with no windows
      - clock: Saturday noon and Friday noon

    Outputs:
      - None: Asserts deny Saturday, pass Friday
    """
    rules = [{"domains": ["example.com"], "days": ["sat"]}]
    saturday = _make_plugin(
        datetime(2026, 11, 7, 12, 0, tzinfo=UTC), timezone="UTC", time_rules=rules
    )
    decision = saturday.pre_resolve(
        "example.com.", QTYPE.A, _question("example.com."), _ctx()
    )
    assert decision is not None and decision.action == "deny"

    friday = _make_plugin(
        datetime(2026, 11, 6, 12, 0, tzinfo=UTC), timezone="UTC", time_rules=rules
    )
    assert _is_pass(
        friday.pre_resolve("example.com.", QTYPE.A, _question("example.com."), _ctx())
    )


def test_window_matches_helper_unit():
    """
    Brief: Unit-check _window_matches for plain, full-day, and wrap cases.

    Inputs:
      - weekday/minute/start/end/days combinations

    Outputs:
      - None: Asserts expected boolean outcomes
    """
    m = Filter._window_matches
    # Plain window on Monday only.
    assert m(1, 10 * 60, 9 * 60, 17 * 60, frozenset({1})) is True
    assert m(2, 10 * 60, 9 * 60, 17 * 60, frozenset({1})) is False
    # Full day.
    assert m(3, 0, 0, 0, frozenset({3})) is True
    assert m(4, 0, 0, 0, frozenset({3})) is False
    # Overnight owned by start day (Mon): Tue 03:00 matches, Tue 23:00 does not.
    assert m(1, 23 * 60, 22 * 60, 6 * 60, frozenset({1})) is True
    assert m(2, 3 * 60, 22 * 60, 6 * 60, frozenset({1})) is True
    assert m(2, 23 * 60, 22 * 60, 6 * 60, frozenset({1})) is False
    # Empty days => all days.
    assert m(7, 12 * 60, 9 * 60, 17 * 60, frozenset()) is True

# FlakyServer resolve plugin

## Overview

The `flaky_server` resolve plugin deliberately introduces failures and protocol oddities into DNS traffic for selected clients. It can:

- randomly drop queries (simulate timeouts),
- reply with SERVFAIL, NXDOMAIN, FORMERR or NOERROR-with-empty answers,
- truncate responses (TC=1) to force TCP fallback,
- fuzz response bytes and/or rewrite the question qtype.

This is useful for testing client resilience, failover logic, and monitoring.

Typical use cases:

- Exercising stub resolvers, load balancers, or middleboxes under pathological DNS behaviour.
- Verifying application retry and failover logic before exposing them to real upstream failures.
- Testing monitoring and alerting systems that should detect intermittent or partial DNS outages.

The plugin is **off by default** unless you configure BasePlugin `targets` / `targets_ignore`. If no client targets are set, FlakyServer acts as a no-op and never triggers.

## Basic configuration

```yaml path=null start=null
plugins:
  - id: flaky-lab
    type: flaky_server
    hooks:
      pre_resolve:  { priority: 15 }
      post_resolve: { priority: 15 }
    config:
      # Only affect lab clients
      targets:
        - 192.0.2.0/24

      # Simple behaviour: ~10% SERVFAIL, ~5% NXDOMAIN on any qtype
      servfail_percent: 10.0
      nxdomain_percent: 5.0
```

## Full configuration (all plugin + base options)

```yaml path=null start=null
plugins:
  - id: flaky-integration
    type: flaky_server
    hooks:
      pre_resolve:  { priority: 15 }
      post_resolve: { priority: 15 }
    config:
      # BasePlugin targeting
      targets:
        - 192.0.2.0/24
        - 2001:db8:dead:beef::/64
      targets_ignore:
        - 192.0.2.10/32
      targets_listener: insecure          # only UDP/TCP, not DoT/DoH
      targets_domains:
        - test.example
      targets_domains_mode: suffix
      target_qtypes: [ 'A', 'AAAA', 'MX' ]  # base-level qtype filter

      # BasePlugin logging
      logging:
        level: debug
        stderr: true

      # FlakyServer probabilities (percent, 0–100)
      servfail_percent: 25.0             # ~25% SERVFAIL, evaluated first
      nxdomain_percent: 10.0             # ~10% NXDOMAIN, evaluated after SERVFAIL
      formerr_percent: 2.0               # occasional FORMERR
      noerror_empty_percent: 5.0         # NOERROR with empty answer section
      timeout_percent: 3.0               # drop query completely (client sees timeout)
      truncate_percent: 1.0              # set TC=1 on some responses

      # Apply only to certain RR types within FlakyServer
      apply_to_qtypes: [ 'A', 'AAAA' ]   # '*' means all qtypes

      # Response fuzzing
      fuzz_percent: 5.0                  # chance to fuzz a matching response
      min_fuzz_bytes: 1
      max_fuzz_bytes: 8
      fuzz_actions: [ 'bit_flip', 'swap_bytes' ]

      # Occasionally rewrite the question qtype in the response
      wrong_qtype_percent: 1.0

      # Deterministic behaviour for tests
      seed: 12345
```

## Options

### Plugin-specific options

All percentage knobs are clamped into `[0.0, 100.0]` internally and expressed as
independent Bernoulli draws per query/response.

- `servfail_percent: float | null`
  - Per-request chance to short-circuit a query with SERVFAIL in `pre_resolve`.
  - Default when unset: `25.0` (25%).
- `nxdomain_percent: float | null`
  - Per-request chance to short-circuit with NXDOMAIN in `pre_resolve`.
  - Default when unset: `10.0` (10%).
- `timeout_percent: float`
  - Probability of dropping the request entirely instead of forwarding it.
  - The client experiences this as a network timeout.
- `truncate_percent: float`
  - In `post_resolve`, chance to parse the upstream response and set `TC=1`.
- `formerr_percent: float`
  - Chance to return a FORMERR reply instead of forwarding.
- `noerror_empty_percent: float`
  - Chance to return `RCODE.NOERROR` with an empty answer section.
- `apply_to_qtypes: list[str]`
  - Additional qtype filter used by FlakyServer itself. Values are dnslib qtype
    mnemonics (`"A"`, `"AAAA"`, `"TXT"`, `"*"`, ...). `"*"` means all qtypes.
- `fuzz_percent: float`
  - In `post_resolve`, chance to fuzz a response at the byte level.
- `min_fuzz_bytes: int`, `max_fuzz_bytes: int`
  - Bounds on how many bytes are randomly mutated during fuzzing.
- `fuzz_actions: list[str]`
  - Set of fuzz primitives to choose from. Supported values:
    - `"bit_flip"`: flip a random bit in a random byte.
    - `"swap_bytes"`: swap two random bytes.
- `wrong_qtype_percent: float`
  - Chance to rewrite the question section qtype in the final response to one of
    a small set of alternates (A, AAAA, TXT, MX, SRV, CNAME).
- `seed: int | null`
  - When set, a deterministic `random.Random(seed)` is used so tests can rely on
    repeatable behaviour. When omitted, `secrets.SystemRandom()` is used.

### Behaviour notes

- FlakyServer only runs when:
  - BasePlugin client targeting passes (`targets`, `targets_ignore`, etc.); **and**
  - at least one of `targets` / `targets_ignore` is configured (otherwise it is a no-op);
  - and the qtype matches both BasePlugin `target_qtypes` and
    FlakyServer `apply_to_qtypes`.
- In `pre_resolve`, decision order is:
  1. Timeouts (`timeout_percent`) – drop query.
  2. SERVFAIL (`servfail_percent`).
  3. NXDOMAIN (`nxdomain_percent`).
  4. FORMERR (`formerr_percent`).
  5. NOERROR empty (`noerror_empty_percent`).
- In `post_resolve`, decisions stack: wrong-qtype, fuzzing, then truncation; any
  mutation results in an `override` decision.

### Common BasePlugin options

FlakyServer supports all standard base options (`targets*`, `target_qtypes`,
`logging`, etc.) as shown in the full configuration example above.

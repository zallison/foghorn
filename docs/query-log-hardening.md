# Query-log hardening and sampling

This document explains how to control persistent query-log growth under high
traffic and how `logging.query_log_sampling` behaves.

## Quick start

- Full example: `example_configs/logging/query_log_hardening.yaml`
- Related README section: `README.md` → **2.5 Stats and query log**.

## Sampling configuration

Use `logging.query_log_sampling` to reduce persistent query-log volume before
rows are written to the configured stats backend.

```yaml
logging:
  query_log_sampling:
    enabled: true
    sample_rate: 0.25
```

Fields:

- `enabled` (bool, default `true`)
  - When `false`, suppresses persistent query-log writes from the stats collector.
- `sample_rate` (number, `0..1`)
  - `1.0`: write all rows.
  - `0.25`: keep about 25% of rows.
  - `0.0`: write none.
- `rate` (number, `0..1`)
  - Compatibility alias for `sample_rate`.

Legacy alias:

- `logging.query_log_sample_rate` is supported as a compatibility alias.

## Runtime behavior notes

- Sampling applies to **persistent query-log rows**. It does not disable the
  in-memory statistics counters used for runtime snapshots/log summaries.
- Sampling is evaluated before query-log dedupe.
- Dedupe can further reduce rows via `logging.query_log_dedupe`.
- For sampling to have persistent effect, you must have stats enabled and a
  configured persistence backend selected by `stats.source_backend`.

## Recommended companion controls

Sampling works best when combined with:

- `logging.query_log_retention`:
  - `max_records`
  - `days`
  - `max_bytes`
  - `prune_interval_seconds`
  - `prune_every_n_inserts`
- `logging.max_logging_queue` to bound async queue memory.
- `logging.query_log_dedupe.window_seconds` to suppress short-window repeats.

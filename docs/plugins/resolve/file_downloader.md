# FileDownloader resolve plugin

## Overview

The `file_downloader` resolve plugin is a setup-only helper that periodically
fetches domain-only lists (typically adblock/deny lists) over HTTP(S) and stores
them as local text files. Other plugins such as `filter` then read these files.

Key features:

- Supports a mix of inline URL list and `url_files` with one URL per line.
- Optional per-URL options (`hash_filenames`, `add_comment`).
- Avoids unnecessary downloads via Last-Modified and minimum-age checks.
- Optional periodic refresh via `interval_days` / `interval_seconds`.

Typical use cases:

- Keeping ad-block or tracking blocklists up to date for the `filter` plugin.
- Periodically refreshing curated allow/block lists from one or more remote sources.
- Mirroring third-party zone or policy lists to local disk for offline use.

It does **not** directly answer DNS queries.

## Basic configuration

```yaml path=null start=null
plugins:
  - id: adblock-downloader
    type: file_downloader
    hooks:
      setup: { priority: 10 }
    config:
      download_path: ./config/var/lists
      urls:
        - https://v.firebog.net/hosts/AdguardDNS.txt
        - https://v.firebog.net/hosts/Prigent-Ads.txt
```

## Full configuration (all plugin + base options)

```yaml path=null start=null
plugins:
  - id: lists-downloader-full
    type: file_downloader
    hooks:
      setup: { priority: 10 }
    config:
      # BasePlugin targeting + logging (mostly unused but supported)
      targets: [ '0.0.0.0/0' ]
      targets_listener: any
      logging:
        level: info
        stderr: true

      # Where to write list files
      download_path: ./config/var/lists

      # Inline URLs; each entry can be a string or an object with options.
      urls:
        # Simple URL using global defaults
        - https://v.firebog.net/hosts/AdguardDNS.txt

        # URL with per-entry options
        - url: https://example.com/custom-list.txt
          hash_filenames: true         # override plugin-level hash_filenames
          add_comment: true            # prepend a timestamp header

      # Additional sources that contain one URL per line ("#" comments allowed)
      url_files:
        - ./config/url-sources/community.txt
        - ./config/url-sources/partners.txt

      # Refresh interval. Prefer interval_days; interval_seconds is a legacy alias.
      interval_days: 7                 # refresh at most once every ~7 days
      # interval_seconds: 604800       # equivalent legacy form

      # Plugin-level defaults for per-URL options
      add_comment: false               # default: no header line
      hash_filenames: true             # store as base-hash.ext instead of base.ext
```

## Options

### Plugin-specific options

- `download_path: str`
  - Directory where all downloaded files are stored.
  - Default: `"./config/var/lists"`.
- `urls: list[str | object]`
  - List of source URLs. Each item may be:
    - a simple string URL, or
    - a mapping with keys:
      - `url: str` (required)
      - `hash_filenames: bool | null` – per-URL override; when `null`, falls
        back to the plugin-level `hash_filenames`.
      - `add_comment: bool | null` – per-URL override; when `true`, prepend a
        timestamped header line, otherwise no header.
- `url_files: list[str]`
  - Paths to text files containing one URL per line. Empty lines and lines
    starting with `#` are ignored.
- `interval_days: float | null`
  - Preferred way to configure the minimum interval between refreshes. Converted
    internally to seconds. `null` disables interval-based scheduling.
- `interval_seconds: int | null`
  - Legacy seconds-based equivalent; still supported but `interval_days` is
    recommended.
- `add_comment: bool | null`
  - Plugin-level default used when a URL entry does not specify its own
    `add_comment` flag. Only when the effective value is `true` does the plugin
    write the `# YYYY-MM-DD HH:MM - url` header line.
- `hash_filenames: bool`
  - Plugin-level default controlling filename layout:
    - `false` (default): derive filenames directly from the URL path/netloc
      (`AdguardDNS.txt`, `list1.txt`, `example.com`, ...).
    - `true`: include a short SHA-1 hash suffix: `<base>-<hash12><ext>`.

### Behaviour

- If the local file does not exist, the URL is always downloaded.
- If `interval_days` / `interval_seconds` is configured, very new files are
  treated as fresh and reused without a network call.
- Otherwise, the plugin uses HTTP `HEAD` and `Last-Modified` (when available)
  to decide whether a remote copy is newer than the local one.
- Each downloaded file is validated as a "domain-per-line" list; obviously
  malformed content causes setup to fail.

### Common BasePlugin options

FileDownloader technically supports `targets*`, `logging`, etc., but it only runs
in the `setup` phase and does not inspect per-request `PluginContext`. The full
example above shows how to enable per-plugin logging if desired.

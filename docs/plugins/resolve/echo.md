# Echo resolve plugin

## Overview
The `echo` resolve plugin is a lightweight diagnostic plugin that returns a TXT
answer containing the incoming query name and qtype.

It is useful for:
- quick end-to-end query path validation
- confirming plugin targeting (`targets`) behavior
- smoke-testing listener/client routing

## Basic configuration
```yaml path=null start=null
plugins:
  - id: echo-test
    type: echo
    hooks:
      pre_resolve: 100
    config:
      targets:
        ips: [0.0.0.0/0 ]
```

## Full configuration (all plugin + base options)
```yaml path=null start=null
plugins:
  - id: echo-full
    type: echo
    hooks:
      pre_resolve: 100
    config:
      targets:
        ips:
          - 192.168.0.0/16
        ignore_ips:
          - 192.168.1.100/32
        listeners: any
        domains:
          - example.com
        domains_mode: suffix
        qtypes: [ '*' ]
      logging:
        level: info
        stderr: true
```

## Options

### Plugin-specific options
Echo has no plugin-specific config model fields.

The response payload is always a TXT RR in the form:
- `"<normalized-qname> <qtype-name>"`

The response TTL defaults to `300`.

### Common BasePlugin options
Echo supports all standard resolve-plugin base options via `config.targets` and
`config.logging`.

#!/usr/bin/env python3
"""
Generate the Foghorn workflow diagram as a Mermaid flowchart (.mmd or Markdown snippet).

Inputs:
- --out: optional output file path (default: images/foghorn-workflow.mmd)
- Flow topology (nodes and edges) is defined in-code for determinism.

Outputs:
- A Mermaid flowchart definition written to the specified path.

Example:
  venv/bin/python scripts/generate_workflow_diagram.py --out images/foghorn-workflow.mmd

Notes:
- No external plotting libraries are used.
- The output can be pasted into a Markdown file inside a ```mermaid fenced block.
"""

import argparse
from typing import List, Tuple


def _html_lines(label: str) -> str:
    """
    Convert a multi-line label into HTML line-breaks for Mermaid.

    Inputs:
    - label: A possibly multi-line string separated by '\n'.

    Outputs:
    - A single string where newlines are replaced with '<br/>' for Mermaid rendering.

    Example:
    - 'Line1\nLine2' -> 'Line1<br/>Line2'
    """
    return label.replace("\n", "<br/>")


def build_mermaid(
    nodes: List[Tuple[str, str, str]], edges: List[Tuple[str, str, str]]
) -> str:
    """
    Build a Mermaid flowchart text.

    Inputs:
    - nodes: list of tuples (id, label, color_name) where color_name is a CSS color or hex.
    - edges: list of tuples (src_id, dst_id, label) where label may be empty for unlabeled edges.

    Outputs:
    - Mermaid flowchart text (string) suitable for a fenced ```mermaid block.

    Example:
    - Use the returned string inside a Markdown file:
      ```
      ```mermaid
      <returned flowchart>
      ```
      ```
    """
    lines: List[str] = []
    # Force light theme and black text with white background
    lines.append(
        "%%{init: {'theme':'base', 'themeVariables': { 'primaryTextColor': '#000000', 'textColor': '#000000', 'lineColor': '#333333', 'background': '#ffffff' }}}%%"
    )
    lines.append("flowchart TB")
    # Default class to ensure readable text color
    lines.append(
        "  classDef default fill:#ffffff,color:#000000,stroke:#333333,stroke-width:1px"
    )

    # Declare nodes
    for node_id, raw_label, _color in nodes:
        label = _html_lines(raw_label).replace('"', "&quot;")
        lines.append(f'  {node_id}["{label}"]')

    # Edges
    for src, dst, lbl in edges:
        if lbl:
            lines.append(f"  {src} -->|{lbl}| {dst}")
        else:
            lines.append(f"  {src} --> {dst}")

    # Styles
    color_map = {
        "lightblue": "#add8e6",
        "lightyellow": "#ffffe0",
        "lightgreen": "#90ee90",
        "lightcyan": "#e0ffff",
        "wheat": "#f5deb3",
        "lightsalmon": "#ffa07a",
        "lightsteelblue": "#b0c4de",
        "white": "#ffffff",
    }
    for node_id, _label, color in nodes:
        hex_color = color_map.get(color, color)
        lines.append(f"  style {node_id} fill:{hex_color},stroke:#333,stroke-width:1px")

    return "\n".join(lines) + "\n"


def main() -> None:
    """
    Parse CLI args and write the Mermaid flowchart text to a file.

    Inputs:
    - CLI: --out path to write the .mmd text (default: images/foghorn-workflow.mmd)

    Outputs:
    - The Mermaid .mmd file is written to disk at the requested location.

    Example:
    - venv/bin/python scripts/generate_workflow_diagram.py
    """
    parser = argparse.ArgumentParser(
        description="Generate Foghorn workflow Mermaid (.mmd)."
    )
    parser.add_argument(
        "--out", default="images/foghorn-workflow.mmd", help="output .mmd path"
    )
    parser.add_argument(
        "--variant",
        choices=["dev", "user", "full"],
        default="dev",
        help="diagram variant",
    )
    args = parser.parse_args()

    def nodes_edges_dev() -> (
        Tuple[List[Tuple[str, str, str]], List[Tuple[str, str, str]]]
    ):
        nodes: List[Tuple[str, str, str]] = [
            ("cli_config", "CLI/Config → main.py", "lightblue"),
            (
                "normalize",
                "normalize_upstream_config()\nload_plugins()\ninit_logging()",
                "lightyellow",
            ),
            (
                "dns_server_init",
                "DNSServer.__init__()\nThreadingUDPServer created",
                "lightgreen",
            ),
            (
                "serve_forever",
                "DNSServer.serve_forever()\nListens for UDP queries",
                "lightcyan",
            ),
            ("handler", "DNSUDPHandler.handle()\nper query", "wheat"),
            ("parse", "Parse query\n(DNSRecord)", "white"),
            ("plugin_ctx", "Instantiate\nPluginContext(client_ip)", "white"),
            (
                "pre_resolve",
                "For each plugin:\npre_resolve() → PluginDecision",
                "lightsalmon",
            ),
            ("cache_lookup", "Cache lookup\nby (qname, qtype)", "white"),
            (
                "upstream_failover",
                "send_query_with_failover()\nupstream_candidates or global",
                "lightsteelblue",
            ),
            (
                "post_resolve",
                "For each plugin:\npost_resolve() → PluginDecision",
                "lightsalmon",
            ),
            ("cache_store", "Cache response\n(if NOERROR + has answers)", "white"),
            ("send_response", "Send response\nto client", "lightblue"),
        ]
        edges: List[Tuple[str, str, str]] = [
            ("cli_config", "normalize", ""),
            ("normalize", "dns_server_init", ""),
            ("dns_server_init", "serve_forever", ""),
            ("serve_forever", "handler", "per UDP packet"),
            ("handler", "parse", ""),
            ("parse", "plugin_ctx", ""),
            ("plugin_ctx", "pre_resolve", ""),
            ("pre_resolve", "cache_lookup", ""),
            ("cache_lookup", "upstream_failover", "cache miss"),
            ("upstream_failover", "post_resolve", ""),
            ("post_resolve", "cache_store", ""),
            ("cache_store", "send_response", ""),
        ]
        return nodes, edges

    def nodes_edges_user() -> (
        Tuple[List[Tuple[str, str, str]], List[Tuple[str, str, str]]]
    ):
        nodes: List[Tuple[str, str, str]] = [
            ("start", "Client DNS Query", "lightblue"),
            ("plugins", "Policy & Plugins\n(allow/deny/modify)", "lightsalmon"),
            ("cache", "Cache\n(hit or miss)", "white"),
            ("upstream", "Forward to Upstream DNS\n(with failover)", "lightsteelblue"),
            ("response", "Response to Client", "lightblue"),
        ]
        edges: List[Tuple[str, str, str]] = [
            ("start", "plugins", ""),
            ("plugins", "cache", ""),
            ("cache", "response", "hit"),
            ("cache", "upstream", "miss"),
            ("upstream", "plugins", "post-process"),
            ("plugins", "response", ""),
        ]
        return nodes, edges

    def nodes_edges_full() -> (
        Tuple[List[Tuple[str, str, str]], List[Tuple[str, str, str]]]
    ):
        nodes: List[Tuple[str, str, str]] = [
            ("main", "main.py\nparse_args()", "lightblue"),
            ("init_logging", "init_logging()", "white"),
            ("load_cfg", "load YAML config", "white"),
            ("normalize_cfg", "normalize_upstream_config()", "lightyellow"),
            ("load_plugins", "load_plugins()\nregistry & aliases", "lightyellow"),
            ("server_init", "DNSServer.__init__()", "lightgreen"),
            ("serve", "DNSServer.serve_forever()", "lightcyan"),
            ("handle", "DNSUDPHandler.handle()", "wheat"),
            ("parse_q", "parse_dns_query()", "white"),
            (
                "ctx",
                "PluginContext(client_ip, upstream_candidates, upstream_override)",
                "white",
            ),
            (
                "pre_plugins",
                "pre_resolve() plugins:\nAccessControl, FlakyServer,\nGreylist, NewDomainFilter,\nFilter, EtcHosts,\nExamples, UpstreamRouter",
                "lightsalmon",
            ),
            ("decide", "PluginDecision\n(allow/deny/override)", "lightsalmon"),
            ("cache_get", "TTLCache.get((qname,qtype))", "white"),
            ("fail_check", "cache miss?", "white"),
            ("send_up", "send_query_with_failover()", "lightsteelblue"),
            (
                "post_plugins",
                "post_resolve() plugins:\nFilter (IP filtering),\nExamples (A/AAAA rewrite)",
                "lightsalmon",
            ),
            ("cache_set", "TTLCache.set(key, ttl, bytes)", "white"),
            ("send_resp", "send_response()", "lightblue"),
        ]
        edges: List[Tuple[str, str, str]] = [
            ("main", "init_logging", ""),
            ("init_logging", "load_cfg", ""),
            ("load_cfg", "normalize_cfg", ""),
            ("normalize_cfg", "load_plugins", ""),
            ("load_plugins", "server_init", ""),
            ("server_init", "serve", ""),
            ("serve", "handle", "per UDP packet"),
            ("handle", "parse_q", ""),
            ("parse_q", "ctx", ""),
            ("ctx", "pre_plugins", ""),
            ("pre_plugins", "decide", ""),
            ("decide", "cache_get", "allow"),
            ("decide", "send_resp", "deny/override"),
            ("cache_get", "fail_check", ""),
            ("fail_check", "send_up", "miss"),
            ("fail_check", "post_plugins", "hit"),
            ("send_up", "post_plugins", ""),
            ("post_plugins", "cache_set", "NOERROR + answers"),
            ("post_plugins", "send_resp", "no caching"),
            ("cache_set", "send_resp", ""),
        ]
        return nodes, edges

    if args.variant == "dev":
        nodes, edges = nodes_edges_dev()
    elif args.variant == "user":
        nodes, edges = nodes_edges_user()
    else:
        nodes, edges = nodes_edges_full()

    mermaid = build_mermaid(nodes, edges)
    with open(args.out, "w", encoding="utf-8") as f:
        f.write(mermaid)
    print(f"Generated: {args.out} ({args.variant})")


if __name__ == "__main__":
    main()

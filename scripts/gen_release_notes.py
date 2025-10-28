#!/usr/bin/env python3
"""
Very brief description:
Generate Markdown release notes from git history and prepare a tag annotation message.

Inputs:
- --tag: str, the tag name (e.g., v0.1.0)
- --title: str, the title line for the tag annotation (e.g., V0.1 RC)
- --head: str, the HEAD commit SHA to end the range
- --notes-out: str, output path for the release notes Markdown (without the title line)
- --tagmsg-out: str, output path for the full tag message (title + blank line + notes)
- --repo-name: str, optional, repository name to display in header (default: foghorn)
- --since: str, optional, starting ref/commit; if omitted, first commit in repo is used

Outputs:
- Writes two files:
  1) notes-out: Markdown release notes suitable for release pages
  2) tagmsg-out: The tag annotation body including the provided title

Example usage:
  venv/bin/python scripts/gen_release_notes.py \
    --tag v0.1.0 --title "V0.1 RC" --head 722f27c9 \
    --notes-out release-notes/v0.1.0.md \
    --tagmsg-out release-notes/v0.1.0.tagmsg \
    --repo-name foghorn
"""

import argparse
import datetime as _dt
import os
import subprocess
from pathlib import Path
from typing import Dict, List, Tuple

def _run(cmd: List[str]) -> str:
    """
    Very brief description:
    Run a command and return stdout as text.

    Inputs:
    - cmd: List[str], command and arguments

    Outputs:
    - str, stdout with trailing newline stripped
    """
    out = subprocess.check_output(cmd)
    return out.decode("utf-8").rstrip("\n")

def _first_commit() -> str:
    """
    Very brief description:
    Return the first commit SHA in the repository.

    Inputs:
    - None

    Outputs:
    - str, the first commit SHA
    """
    return _run(["git", "rev-list", "--max-parents=0", "HEAD"]).splitlines()[0]

def _get_commits(since: str, head: str) -> List[Dict[str, str]]:
    """
    Very brief description:
    Collect commit metadata from git log.

    Inputs:
    - since: str, starting ref/commit (inclusive)
    - head: str, ending ref/commit (inclusive)

    Outputs:
    - List[Dict[str, str]], each with keys: sha, short, date, subject
    """
    # Try using since^..head first; if it fails, fall back to since..head plus since itself
    fmt = "%H%x09%h%x09%ad%x09%s"
    try:
        rng = f"{since}^..{head}"
        raw = _run([
            "git", "log", "--reverse", "--no-merges", "--date=short",
            f"--pretty=format:{fmt}", rng
        ])
    except subprocess.CalledProcessError:
        # If since is the first commit, since^ doesn't exist; fetch since and then since..head
        raw_since = _run([
            "git", "log", "--no-merges", "--date=short",
            f"--pretty=format:{fmt}", "-1", since
        ])
        raw_rest = _run([
            "git", "log", "--reverse", "--no-merges", "--date=short",
            f"--pretty=format:{fmt}", f"{since}..{head}"
        ])
        raw = raw_since
        if raw_rest:
            raw += "\n" + raw_rest
    commits = []
    for line in raw.splitlines():
        parts = line.split("\t", 3)
        if len(parts) != 4:
            # Fallback: skip malformed lines
            continue
        sha, short, date, subject = parts
        commits.append({"sha": sha, "short": short, "date": date, "subject": subject})
    return commits

def _categorize(commits: List[Dict[str, str]]) -> Dict[str, List[Dict[str, str]]]:
    """
    Very brief description:
    Group commits by common Conventional Commit types, with a fallback bucket.

    Inputs:
    - commits: List[Dict], commit dicts with 'subject'

    Outputs:
    - Dict[str, List[Dict]], mapping section name to commits
    """
    sections = {
        "Features": [],
        "Fixes": [],
        "Documentation": [],
        "Performance": [],
        "Refactoring": [],
        "Tests": [],
        "Build": [],
        "CI": [],
        "Chore": [],
        "Reverts": [],
        "Other Changes": [],
    }
    for c in commits:
        s = c["subject"]
        low = s.lower()
        placed = True
        if low.startswith("feat"):
            sections["Features"].append(c)
        elif low.startswith("fix"):
            sections["Fixes"].append(c)
        elif low.startswith("docs"):
            sections["Documentation"].append(c)
        elif low.startswith("perf"):
            sections["Performance"].append(c)
        elif low.startswith("refactor"):
            sections["Refactoring"].append(c)
        elif low.startswith("test"):
            sections["Tests"].append(c)
        elif low.startswith("build"):
            sections["Build"].append(c)
        elif low.startswith("ci"):
            sections["CI"].append(c)
        elif low.startswith("chore"):
            sections["Chore"].append(c)
        elif low.startswith("revert"):
            sections["Reverts"].append(c)
        else:
            placed = False
        if not placed:
            sections["Other Changes"].append(c)
    # Drop empty sections for cleanliness
    return {k: v for k, v in sections.items() if v}
    
def _format_notes(repo_name: str, tag: str, date_str: str, categorized: Dict[str, List[Dict[str, str]]]) -> str:
    """
    Very brief description:
    Format Markdown release notes from categorized commits.

    Inputs:
    - repo_name: str, project name for the header
    - tag: str, tag name
    - date_str: str, release date in YYYY-MM-DD
    - categorized: Dict[str, List[Dict]], grouped commits

    Outputs:
    - str, Markdown content
    """
    lines = []
    lines.append(f"{repo_name} {tag} ({date_str})")
    lines.append("")
    for section, items in categorized.items():
        lines.append(f"## {section}")
        for c in items:
            lines.append(f"- {c['subject']} ({c['short']}, {c['date']})")
        lines.append("")
    return "\n".join(lines).rstrip() + "\n"

def main() -> None:
    """
    Very brief description:
    Entrypoint to generate release notes and a tag message file.

    Inputs:
    - Parses CLI arguments as described in module docstring.

    Outputs:
    - Writes two files to the specified destinations.
    """
    ap = argparse.ArgumentParser()
    ap.add_argument("--tag", required=True)
    ap.add_argument("--title", required=True)
    ap.add_argument("--head", required=True)
    ap.add_argument("--notes-out", required=True)
    ap.add_argument("--tagmsg-out", required=True)
    ap.add_argument("--repo-name", default="foghorn")
    ap.add_argument("--since", default=None)
    args = ap.parse_args()

    since = args.since or _first_commit()
    commits = _get_commits(since, args.head)
    date_str = _dt.date.today().isoformat()
    categorized = _categorize(commits)
    notes = _format_notes(args.repo_name, args.tag, date_str, categorized)

    notes_path = Path(args.notes_out)
    notes_path.parent.mkdir(parents=True, exist_ok=True)
    notes_path.write_text(notes, encoding="utf-8")

    tagmsg_path = Path(args.tagmsg_out)
    tagmsg_body = f"{args.title}\n\n{notes}"
    tagmsg_path.write_text(tagmsg_body, encoding="utf-8")

if __name__ == "__main__":
    main()

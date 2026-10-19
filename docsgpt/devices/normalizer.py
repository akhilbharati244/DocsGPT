"""Normalize a command segment to its sticky-approval pattern.

Rule: head + first sub-token (when present), wildcard the rest.
  ``git checkout main -- file.txt``     -> ``git checkout *``
  ``npm install foo bar``               -> ``npm install *``
  ``ls -la /tmp``                       -> ``ls *``
  ``cat /etc/passwd``                   -> ``cat *``

Compound commands are normalized segment-by-segment and rejoined with
`` && ``, so a sticky only matches a command with the same normalized
segment sequence:
  ``ls /tmp && whoami``                 -> ``ls * && whoami``
"""

from __future__ import annotations

import os
import re
import shlex
from typing import Optional

from docsgpt.devices.splitter import split_command


# Commands whose first arg is a sub-command (so the pattern is "cmd subcmd *").
_TWO_WORD_HEADS = frozenset(
    {
        "git", "npm", "pnpm", "yarn", "pip", "uv", "poetry", "cargo",
        "docker", "kubectl", "brew", "apt", "apt-get", "dnf", "yum",
        "go", "rustup", "rustc", "make", "gradle", "mvn",
        "systemctl", "service",
    }
)

_ENV_ASSIGNMENT_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*=.*")
_SHELL_INTERPRETERS = frozenset(
    {"sh", "bash", "zsh", "dash", "ksh", "ash", "eval", "exec"}
)


def _has_unsafe_shell_syntax(text: str) -> bool:
    """Return True if ``text`` has shell substitutions, redirections, or subshells."""
    in_single = False
    in_double = False
    escaped = False
    length = len(text)

    for idx, ch in enumerate(text):
        if escaped:
            escaped = False
            continue
        if ch == "\\" and not in_single:
            escaped = True
            continue
        if ch == "'" and not in_double:
            in_single = not in_single
            continue
        if ch == '"' and not in_single:
            in_double = not in_double
            continue

        if not in_single:
            if ch == "`":
                return True
            if ch == "$" and idx + 1 < length and text[idx + 1] in ("(", "{"):
                return True

        if not in_single and not in_double:
            if ch in ("<", ">", "(", ")"):
                return True

    return in_single or in_double or escaped


def normalize_segment(segment: str) -> str:
    """Reduce a segment to its sticky-pattern form.

    Args:
        segment: A single shell command segment (no compound connectors).

    Returns:
        Pattern like ``git checkout *``, ``ls *``, or just ``cat`` if the
        original had no args. Empty string for empty or unsafe input.
    """
    if not segment or not isinstance(segment, str) or not segment.strip():
        return ""
    stripped = segment.strip()
    if _has_unsafe_shell_syntax(stripped):
        return ""

    try:
        tokens = shlex.split(stripped, posix=True)
    except ValueError:
        return ""
    if not tokens:
        return ""

    head = tokens[0]
    if _ENV_ASSIGNMENT_RE.match(head):
        return ""
    base_head = os.path.basename(head.lstrip("\\"))
    if base_head in _SHELL_INTERPRETERS:
        return ""

    if head in _TWO_WORD_HEADS and len(tokens) >= 2:
        subcmd = tokens[1]
        if len(tokens) > 2:
            return f"{head} {subcmd} *"
        return f"{head} {subcmd}"

    if len(tokens) > 1:
        return f"{head} *"
    return head


def normalize_command(command: str) -> Optional[str]:
    """Normalize an entire command into its joined sticky pattern.

    Every segment is normalized and the results are joined with `` && ``,
    so a compound command's sticky only matches a command with the same
    normalized segment sequence (approving ``ls /tmp && whoami`` won't
    auto-approve ``ls /tmp && rm /tmp/x``). Empty segments are skipped;
    returns ``None`` if there are no non-empty segments or if any segment
    contains unsafe shell syntax.
    """
    if not command or not isinstance(command, str):
        return None
    if _has_unsafe_shell_syntax(command):
        return None
    segments = split_command(command)
    if not segments:
        return None
    patterns = [normalize_segment(segment) for segment in segments]
    if any(not p for p in patterns):
        return None
    return " && ".join(patterns)

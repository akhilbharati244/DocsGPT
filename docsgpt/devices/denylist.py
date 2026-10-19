"""Hard denylist — always triggers a forced prompt, even under ``never``."""

from __future__ import annotations

import os
import re
import shlex
from typing import List, Optional, Tuple

from docsgpt.devices.splitter import split_command, strip_wrappers


# Label/reason for the rm-root wipe, shared by the regex rule and the
# token-based helper so both report identically.
_RM_ROOT_LABEL = "rm -rf /"
_RM_TILDE_LABEL = "rm -rf ~"
_RM_HOME_LABEL = "rm -rf $HOME"

# Filesystem-root targets that, with recursive+force, mean a full wipe.
_RM_ROOT_TARGETS = frozenset({"/", "/*", "//", "//*", "/.", "/.."})
_RM_TILDE_TARGETS = frozenset({"~", "~/", "~/*", "~/.", "~/.."})
_RM_HOME_TARGETS = frozenset(
    {"$HOME", "$HOME/", "$HOME/*", "${HOME}", "${HOME}/", "${HOME}/*"}
)

_ENV_ASSIGNMENT_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*=.*")
_SUDO_ARG_FLAGS = frozenset(
    {"-u", "-g", "-C", "-D", "-R", "-T", "-U", "-h", "-p", "-r", "-t"}
)
_ENV_ARG_FLAGS = frozenset({"-u", "-C", "-S", "--unset", "--chdir", "--split-string"})
_SHELL_INTERPRETERS = frozenset({"sh", "bash", "zsh", "dash", "ksh", "ash"})
_SUBSHELL_SUBST_RE = re.compile(
    r"\$\(([^)]+)\)|`([^`]+)`|<\(([^)]+)\)|>\(([^)]+)\)"
)

# Each entry: (label, compiled regex). Regex is matched against each
# segment's whole text (case-insensitive, after whitespace normalization).
_PATTERNS: List[Tuple[str, re.Pattern]] = [
    (
        _RM_ROOT_LABEL,
        re.compile(
            r"\brm\s+(?:-\S+\s+)*"
            r"(?:-[a-zA-Z]*r[a-zA-Z]*f|-[a-zA-Z]*f[a-zA-Z]*r"
            r"|--recursive\s+(?:-\S+\s+)*--force|--force\s+(?:-\S+\s+)*--recursive)"
            r"\s+(?:-\S+\s+)*/\*?\s*(?:$|\s)"
        ),
    ),
    (
        "rm -rf ~",
        re.compile(
            r"\brm\s+(-[a-zA-Z]*r[a-zA-Z]*f|-[a-zA-Z]*f[a-zA-Z]*r|-rf|-fr)\s+~"
        ),
    ),
    (
        "rm -rf $HOME",
        re.compile(
            r"\brm\s+(-[a-zA-Z]*r[a-zA-Z]*f|-[a-zA-Z]*f[a-zA-Z]*r|-rf|-fr)\s+\$HOME\b"
        ),
    ),
    (
        "fork bomb",
        re.compile(r":\(\)\s*\{\s*:\s*\|\s*:\s*&\s*\}\s*;\s*:"),
    ),
    (
        "dd to block device",
        re.compile(
            r"\bdd\s+.*\bif=/dev/(zero|random|urandom).*\bof=/dev/(sd|nvme|hd|disk|mmcblk)",
            re.DOTALL,
        ),
    ),
    (
        "mkfs",
        re.compile(r"\bmkfs(\.[a-zA-Z0-9]+)?\b"),
    ),
    (
        "shutdown",
        re.compile(r"\bshutdown\b"),
    ),
    (
        "halt",
        re.compile(r"\bhalt\b"),
    ),
    (
        "poweroff",
        re.compile(r"\bpoweroff\b"),
    ),
    (
        "init 0/6",
        re.compile(r"\binit\s+(0|6)\b"),
    ),
    (
        "git push --force",
        re.compile(
            r"\bgit\s+push\b.*(--force(?!-with-lease)|--mirror|\s-f(?:\s|$))"
        ),
    ),
]


def _unwrap_tokens(tokens: List[str]) -> Tuple[List[str], List[str]]:
    """Strip command wrappers, env assignments, and paths from ``tokens``."""
    inner_commands: List[str] = []
    i = 0
    n = len(tokens)
    while i < n:
        tok = tokens[i]
        if _ENV_ASSIGNMENT_RE.match(tok):
            i += 1
            continue
        cmd = os.path.basename(tok.lstrip("\\"))
        if cmd in ("sudo", "doas"):
            i += 1
            while i < n and tokens[i].startswith("-"):
                flag = tokens[i]
                i += 1
                if flag == "--":
                    break
                if flag in _SUDO_ARG_FLAGS and i < n:
                    i += 1
            continue
        if cmd == "env":
            i += 1
            while i < n:
                flag = tokens[i]
                if flag == "--":
                    i += 1
                    break
                if flag in _ENV_ARG_FLAGS:
                    i += 2
                    continue
                if flag.startswith("-") or _ENV_ASSIGNMENT_RE.match(flag):
                    i += 1
                    continue
                break
            continue
        if cmd == "command":
            j = i + 1
            lookup_only = False
            while j < n and tokens[j].startswith("-"):
                flag = tokens[j]
                if flag == "--":
                    j += 1
                    break
                if "v" in flag[1:] or "V" in flag[1:]:
                    lookup_only = True
                    break
                j += 1
            if lookup_only:
                break
            i = j
            continue
        if cmd in ("builtin", "nohup", "xargs", "exec"):
            i += 1
            while i < n and tokens[i].startswith("-"):
                flag = tokens[i]
                i += 1
                if flag == "--":
                    break
            continue
        if cmd == "eval":
            if i + 1 < n:
                inner_commands.append(" ".join(tokens[i + 1 :]))
            i += 1
            break
        if cmd == "timeout":
            i += 1
            while i < n and tokens[i].startswith("-"):
                flag = tokens[i]
                i += 1
                if flag == "--":
                    break
                if flag in ("-k", "-s") and i < n:
                    i += 1
                if i < n and re.match(r"^\d+(\.\d+)?[smhd]?$
", tokens[i]):
                    i += 1
            continue
        if cmd == "nice":
            i += 1
            while i < n and tokens[i].startswith("-"):
                flag = tokens[i]
                i += 1
                if flag == "--":
                    break
                if flag == "-n" and i < n and re.match(r"^-?\d+$", tokens[i]):
                    i += 1
            continue
        if cmd == "stdbuf":
            i += 1
            while i < n and tokens[i].startswith("-"):
                flag = tokens[i]
                i += 1
                if flag == "--":
                    break
                if flag in ("-i", "-o", "-e") and i < n:
                    i += 1
            continue
        if cmd in _SHELL_INTERPRETERS:
            j = i + 1
            while j < n and tokens[j].startswith("-"):
                flag = tokens[j]
                if not flag.startswith("--") and "c" in flag[1:]:
                    if j + 1 < n:
                        inner_commands.append(tokens[j + 1])
                    break
                j += 1
            unwrapped = [cmd, *tokens[i + 1 :]]
            return unwrapped, inner_commands
        return [], inner_commands
    return [], inner_commands


def _check_rm_wipe_tokens(tokens: List[str]) -> Optional[str]:
    """Return the denylist label if ``tokens`` is a recursive+force wipe of /, ~, or $HOME."""
    if not tokens or os.path.basename(tokens[0].lstrip("\\")) != "rm":
        return None

    recursive = False
    force = False
    targets: List[str] = []
    after_double_dash = False
    for tok in tokens[1:]:
        if after_double_dash:
            targets.append(tok)
            continue
        if tok == "--":
            after_double_dash = True
            continue
        if tok in ("--recursive", "-R"):
            recursive = True
        elif tok == "--force":
            force = True
        elif tok == "--no-preserve-root":
            continue
        elif tok.startswith("--"):
            continue
        elif tok.startswith("-") and len(tok) > 1:
            letters = tok[1:]
            if "r" in letters or "R" in letters:
                recursive = True
            if "f" in letters:
                force = True
        else:
            targets.append(tok)

    if not (recursive and force):
        return None
    for target in targets:
        if target in _RM_ROOT_TARGETS:
            return _RM_ROOT_LABEL
        if target in _RM_TILDE_TARGETS:
            return _RM_TILDE_LABEL
        if target in _RM_HOME_TARGETS:
            return _RM_HOME_LABEL
    return None


def _is_rm_root_wipe(segment: str) -> bool:
    """True if ``segment`` is ``rm`` with recursive+force targeting root."""
    try:
        tokens = shlex.split(segment, posix=True)
    except ValueError:
        return False
    unwrapped, _ = _unwrap_tokens(tokens)
    return (
        _check_rm_wipe_tokens(unwrapped) == _RM_ROOT_LABEL
        or _check_rm_wipe_tokens(tokens) == _RM_ROOT_LABEL
    )


def check_denylist(command: str, _depth: int = 0) -> Optional[str]:
    """Return the matched pattern label if ``command`` hits the hard denylist."""
    if not command or _depth > 3:
        return None

    for segment in split_command(command):
        cleaned = segment.strip()
        while cleaned.startswith("(") and cleaned.endswith(")"):
            cleaned = cleaned[1:-1].strip()

        unwrapped_text = strip_wrappers(cleaned)
        try:
            raw_tokens = shlex.split(cleaned, posix=True)
        except ValueError:
            raw_tokens = []

        unwrapped_tokens, inner_commands = (
            _unwrap_tokens(raw_tokens) if raw_tokens else ([], [])
        )

        for candidate_tokens in (unwrapped_tokens, raw_tokens):
            rm_label = _check_rm_wipe_tokens(candidate_tokens)
            if rm_label:
                return rm_label

        if _is_rm_root_wipe(unwrapped_text) or _is_rm_root_wipe(cleaned):
            return _RM_ROOT_LABEL

        candidate_texts = [cleaned]
        if unwrapped_tokens:
            candidate_texts.append(" ".join(unwrapped_tokens))
        if unwrapped_text and unwrapped_text not in candidate_texts:
            candidate_texts.append(unwrapped_text)

        for text_candidate in candidate_texts:
            for label, pattern in _PATTERNS:
                if pattern.search(text_candidate):
                    return label

        for inner in inner_commands:
            inner_match = check_denylist(inner, _depth=_depth + 1)
            if inner_match:
                return inner_match

        for match in _SUBSHELL_SUBST_RE.finditer(command):
            sub_cmd = next((g for g in match.groups() if g), None)
            if sub_cmd:
                sub_match = check_denylist(sub_cmd, _depth=_depth + 1)
                if sub_match:
                    return sub_match

    return None

"""PoC safety guard.

AegisGemma only emits verification steps. Anything that could destroy data,
wipe a disk, take a host offline, or fork-bomb a machine is stripped before
the PoC ever reaches the UI. The guard is applied to every PoC regardless of
whether it came from the model or from the heuristic engine.
"""

from __future__ import annotations

import re

DESTRUCTIVE_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"(?i)\brm\s+(-[a-z]*\s+)*-?[a-z]*r[a-z]*f\b[^\n]*"), "[BLOCKED_DESTRUCTIVE_COMMAND]"),
    (re.compile(r"(?i)\brm\s+-[a-z]*f[a-z]*\s+/(\s|$)"), "[BLOCKED_DESTRUCTIVE_COMMAND]"),
    (re.compile(r"(?i)\bdrop\s+(table|database|schema)\b"), "[BLOCKED_DESTRUCTIVE_COMMAND]"),
    (re.compile(r"(?i)\btruncate\s+table\b"), "[BLOCKED_DESTRUCTIVE_COMMAND]"),
    (re.compile(r"(?i)\bdelete\s+from\s+\w+\s*;?\s*$"), "[BLOCKED_DESTRUCTIVE_COMMAND]"),
    (re.compile(r"(?i)\bmkfs(\.\w+)?\b"), "[BLOCKED_DESTRUCTIVE_COMMAND]"),
    (re.compile(r"(?i)\bdd\s+if=.*of=/dev/"), "[BLOCKED_DESTRUCTIVE_COMMAND]"),
    (re.compile(r"(?i)\b(shutdown|reboot|halt|poweroff)\b"), "[BLOCKED_DESTRUCTIVE_COMMAND]"),
    (re.compile(r"(?i)\bchmod\s+777\s+/(\s|$)"), "[BLOCKED_DESTRUCTIVE_COMMAND]"),
    (re.compile(r"(?i)\b:\(\)\s*\{\s*:\|\:&\s*\}\s*;:"), "[BLOCKED_FORK_BOMB]"),
    (re.compile(r"(?i)\bcurl\b[^\n]*\|\s*(ba)?sh\b"), "[BLOCKED_REMOTE_CODE_EXECUTION]"),
    (re.compile(r"(?i)\bwget\b[^\n]*\|\s*(ba)?sh\b"), "[BLOCKED_REMOTE_CODE_EXECUTION]"),
    (re.compile(r"(?i)\bnc\b[^\n]*\s+-e\s+/bin/"), "[BLOCKED_REMOTE_CODE_EXECUTION]"),
    (re.compile(r"(?i)\bos\.remove\s*\(\s*[\"']/(etc|usr|bin|var|boot|home)"), "[BLOCKED_DESTRUCTIVE_COMMAND]"),
    (re.compile(r"(?i)\bshutil\.rmtree\s*\(\s*[\"']/(etc|usr|bin|var|boot|home)"), "[BLOCKED_DESTRUCTIVE_COMMAND]"),
]


def sanitize_poc(text: str) -> str:
    """Strip destructive commands from a proof-of-concept payload."""
    if not text:
        return text
    cleaned = text
    for pattern, replacement in DESTRUCTIVE_PATTERNS:
        cleaned = pattern.sub(replacement, cleaned)
    return cleaned


def is_safe_poc(text: str) -> bool:
    """True when the payload contains no destructive command patterns."""
    return sanitize_poc(text) == text

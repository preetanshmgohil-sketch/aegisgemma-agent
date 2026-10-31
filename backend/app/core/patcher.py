"""Automated remediation patch generator.

Produces real, appliable unified diffs for the high-confidence mechanical
fixes (shell=True, eval, innerHTML, hardcoded credentials). Cases that need
human judgement (SQL construction, access control) get guidance only — a
patch is never invented where correctness cannot be guaranteed.
"""

from __future__ import annotations

import difflib
import re

from .security_engine import ScanFinding, rule_for_category

# (rule, pattern, replacement, rationale)
TRANSFORMS: list[tuple[str, re.Pattern[str], str, str]] = [
    (
        "command_injection",
        re.compile(r"shell\s*=\s*True"),
        "shell=False",
        "Disable shell interpretation so arguments cannot be re-parsed as commands.",
    ),
    (
        "code_injection",
        re.compile(r"(?<![.\w])eval\s*\("),
        "ast.literal_eval(",
        "Replace dynamic evaluation with literal parsing; no code can be executed.",
    ),
    (
        "xss",
        re.compile(r"\.innerHTML\s*="),
        ".textContent =",
        "Assign text instead of HTML so the value is escaped by the browser.",
    ),
    (
        "xss",
        re.compile(r"\.outerHTML\s*="),
        ".textContent =",
        "Assign text instead of HTML so the value is escaped by the browser.",
    ),
]

ENV_LOOKUP_RE = re.compile(
    r"(?i)\b(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*=\s*[\"'][^\"'\n]{8,}[\"']"
)

REQUIRED_IMPORT = {"code_injection": "import ast", "hardcoded_secret": "import os"}

KNOWN_RULES = {rule for rule, *_ in TRANSFORMS} | set(REQUIRED_IMPORT)


def generate_patch(finding: ScanFinding, file_content: str) -> tuple[str, str] | None:
    """Return (unified_diff, rationale) for a finding, or None if not automatable."""
    lines = file_content.splitlines()
    if finding.line < 1 or finding.line > len(lines):
        return None
    original_line = lines[finding.line - 1]
    patched_line = original_line
    rationale = ""

    rule = finding.rule if finding.rule in KNOWN_RULES else rule_for_category(finding.category)
    if rule is None:
        return None

    if rule == "hardcoded_secret":
        match = ENV_LOOKUP_RE.search(original_line)
        if not match:
            return None
        name = match.group("name")
        patched_line = ENV_LOOKUP_RE.sub(
            f'{name} = os.environ.get("{name}")', original_line, count=1
        )
        rationale = (
            "Read the credential from the environment instead of embedding it in source."
        )
    else:
        for transform_rule, pattern, replacement, why in TRANSFORMS:
            if transform_rule != rule:
                continue
            patched_line, count = pattern.subn(replacement, original_line, count=1)
            if count == 0:
                continue
            rationale = why
            break
        if not rationale:
            return None

    if patched_line == original_line:
        return None

    patched_lines = list(lines)
    patched_lines[finding.line - 1] = patched_line

    needed_import = REQUIRED_IMPORT.get(rule)
    if needed_import and needed_import not in file_content:
        patched_lines.insert(0, needed_import)

    diff = _unified_diff(finding.file, lines, patched_lines)
    return diff, rationale


def _unified_diff(path: str, original: list[str], patched: list[str]) -> str:
    diff_lines = difflib.unified_diff(
        original,
        patched,
        fromfile=f"a/{path}",
        tofile=f"b/{path}",
        lineterm="",
        n=3,
    )
    return "\n".join(diff_lines) + "\n"

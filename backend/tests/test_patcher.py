"""Tests for the automated remediation patch generator."""

from app.core.patcher import generate_patch
from app.core.security_engine import ScanFinding


def _finding(rule: str, line: int = 1) -> ScanFinding:
    return ScanFinding(
        id="AEGIS-001",
        title="Test",
        category=rule,
        rule=rule,
        severity="HIGH",
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        cvss_score=9.8,
        cwe_id="CWE-78",
        owasp_category="A03:2021 - Injection",
        file="app.py",
        line=line,
        snippet="",
        description="",
        remediation="",
    )


class TestGeneratePatch:
    def test_shell_true_is_disabled(self):
        content = "import subprocess\nsubprocess.run(cmd, shell=True)\n"
        result = generate_patch(_finding("Command Injection", 2), content)
        assert result is not None
        diff, rationale = result
        added = [ln for ln in diff.splitlines() if ln.startswith("+") and not ln.startswith("+++")]
        removed = [ln for ln in diff.splitlines() if ln.startswith("-") and not ln.startswith("---")]
        assert any("shell=False" in ln for ln in added)
        assert any("shell=True" in ln for ln in removed)
        assert "Disable shell interpretation" in rationale

    def test_eval_becomes_literal_eval_with_import(self):
        content = "value = eval(payload)\n"
        result = generate_patch(_finding("Code Injection", 1), content)
        assert result is not None
        diff, _ = result
        assert "ast.literal_eval" in diff
        assert "import ast" in diff

    def test_inner_html_becomes_text_content(self):
        content = "el.innerHTML = userInput;\n"
        result = generate_patch(_finding("XSS (Cross-Site Scripting)", 1), content)
        assert result is not None
        diff, _ = result
        assert "textContent" in diff

    def test_hardcoded_secret_becomes_env_lookup(self):
        content = 'API_KEY = "abcd1234efgh5678"\n'
        result = generate_patch(_finding("Hardcoded Secrets", 1), content)
        assert result is not None
        diff, _ = result
        added = [ln for ln in diff.splitlines() if ln.startswith("+") and not ln.startswith("+++")]
        assert any("os.environ.get" in ln for ln in added)
        # The added code must never carry the secret forward.
        assert all("abcd1234efgh5678" not in ln for ln in added)

    def test_non_automatable_category_returns_none(self):
        content = 'cursor.execute("SELECT " + x)\n'
        assert generate_patch(_finding("SQL Injection", 1), content) is None

    def test_out_of_range_line_returns_none(self):
        assert generate_patch(_finding("Command Injection", 99), "x = 1\n") is None

    def test_diff_is_valid_unified_format(self):
        content = "import subprocess\nsubprocess.run(cmd, shell=True)\n"
        diff, _ = generate_patch(_finding("Command Injection", 2), content)
        assert diff.startswith("--- a/app.py")
        assert "+++ b/app.py" in diff
        assert "@@" in diff

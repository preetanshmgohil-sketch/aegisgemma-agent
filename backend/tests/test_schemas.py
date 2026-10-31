"""Pydantic schema conformance tests for the audit report contract."""

import pytest
from pydantic import ValidationError

from app.schemas.audit_schema import (
    AuditReport,
    CvssVectorModel,
    Finding,
    PoC,
    RemediationPatch,
    Severity,
    TargetSummary,
)


class TestSeverity:
    def test_severity_is_a_closed_enum(self):
        assert {s.value for s in Severity} == {
            "NONE",
            "LOW",
            "MEDIUM",
            "HIGH",
            "CRITICAL",
        }

    def test_invalid_severity_rejected(self):
        with pytest.raises(ValueError):
            Severity("SEVERE")

    def test_model_rejects_unknown_severity_string(self):
        with pytest.raises(ValidationError):
            Finding(
                id="F-1",
                title="Bad severity",
                severity="SEVERE",
                cvss=CvssVectorModel(
                    vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
                ),
                cwe_id="CWE-78",
                owasp_category="A03:2021 - Injection",
                location={"file": "a.py", "line": 3},
                description="bad severity",
            )

    def test_severity_is_derived_from_score(self):
        assert Severity.from_score(9.8) is Severity.CRITICAL
        assert Severity.from_score(0.0) is Severity.NONE
        assert Severity.from_score(5.3) is Severity.MEDIUM


class TestCvssVectorModel:
    def test_vector_must_follow_cvss_31_format(self):
        with pytest.raises(ValidationError):
            CvssVectorModel(vector="CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")

    def test_accepts_valid_vector(self):
        m = CvssVectorModel(vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
        assert m.vector.startswith("CVSS:3.1/")


class TestFinding:
    def test_minimal_valid_finding(self):
        f = Finding(
            id="F-1",
            title="Command injection",
            severity=Severity.CRITICAL,
            cvss=CvssVectorModel(
                vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", score=9.8
            ),
            cwe_id="CWE-78",
            owasp_category="A03:2021 - Injection",
            location={"file": "a.py", "line": 3},
            description="User input reaches os.system.",
        )
        assert f.id == "F-1"
        assert f.severity is Severity.CRITICAL

    def test_severity_and_score_must_agree(self):
        with pytest.raises(ValidationError):
            Finding(
                id="F-1",
                title="Bad score",
                severity=Severity.LOW,
                cvss=CvssVectorModel(
                    vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", score=9.8
                ),
                cwe_id="CWE-78",
                owasp_category="A03:2021 - Injection",
                location={"file": "a.py", "line": 3},
                description="mismatch",
            )

    def test_score_is_recomputed_from_the_vector(self):
        f = Finding(
            id="F-1",
            title="Score mismatch",
            severity=Severity.HIGH,
            cvss=CvssVectorModel(
                vector="CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:L", score=7.7
            ),
            cwe_id="CWE-78",
            owasp_category="A03:2021 - Injection",
            location={"file": "a.py", "line": 3},
            description="recomputed",
        )
        assert f.cvss.score == 7.7

    def test_remediation_diff_must_be_unified_format(self):
        with pytest.raises(ValidationError):
            RemediationPatch(
                file="a.py",
                diff="not a diff",
                rationale="because",
            )

    def test_remediation_accepts_unified_diff(self):
        patch = RemediationPatch(
            file="a.py",
            diff="--- a/a.py\n+++ b/a.py\n@@ -1 +1 @@\n-os.system(cmd)\n+subprocess.run([cmd])\n",
            rationale="Avoid the shell.",
        )
        assert patch.file == "a.py"

    def test_poc_requires_non_destructive_marker(self):
        poc = PoC(
            kind="curl",
            title="Read a resource you own",
            command='curl -s "https://example.test/api/me"',
            destructive=False,
            expected_observation="200 response for your own account",
        )
        assert poc.destructive is False


class TestAuditReport:
    def _report(self, **overrides):
        base = dict(
            target="demo",
            risk_index=42,
            summary="Some issues.",
            findings=[],
            attack_surface=[],
            recommendations=["Fix it."],
        )
        base.update(overrides)
        return AuditReport(**base)

    def test_risk_index_bounds(self):
        with pytest.raises(ValidationError):
            self._report(risk_index=101)
        with pytest.raises(ValidationError):
            self._report(risk_index=-1)

    def test_engine_status_defaults_to_ok(self):
        assert self._report().engine_status == "ok"

    def test_target_summary_roundtrip(self):
        summary = TargetSummary(file_count=3, languages={"Python": 2, "Go": 1})
        assert summary.model_dump()["file_count"] == 3

    def test_report_exposes_json_schema_for_gemma_structured_output(self):
        schema = AuditReport.model_json_schema()
        assert schema["title"] == "AuditReport"
        assert "findings" in schema["properties"]

"""Audit orchestration tests: pipeline stages, schema conformance, PoC safety."""

import asyncio

import pytest

from app.core.gemma_client import GemmaClient, GemmaResponse
from app.core.orchestrator import AuditOrchestrator
from app.schemas.audit_schema import AuditReport
from app.core.security_engine import TargetFile


class FakeGemma(GemmaClient):
    """Deterministic stand-in for the real Gemma 4 client."""

    def __init__(self):
        super().__init__(api_key="fake", model="fake-model")
        self.calls = []

    async def complete_json(self, prompt: str, schema: dict) -> GemmaResponse:
        self.calls.append(prompt)
        return GemmaResponse(
            text="""{
                "summary": "One command injection issue found.",
                "risk_index": 78,
                "findings": [],
                "attack_surface": [],
                "recommendations": ["Parameterise shell calls."]
            }""",
            thoughts="Looking at shell invocations.",
            usage={"input_tokens": 10, "output_tokens": 5},
        )


class TestOrchestrator:
    @pytest.mark.asyncio
    async def test_runs_all_four_pipeline_stages(self):
        client = FakeGemma()
        orch = AuditOrchestrator(gemma_client=client)
        events = []
        report = await orch.run(
            [TargetFile(path="a.py", content="import os\nos.system(cmd)\n", size=20)],
            "target",
            on_event=lambda e: events.append(e),
        )
        stages = [e.stage for e in events if e.kind == "stage"]
        assert stages == [
            "AST Extraction",
            "Threat Vector Mapping",
            "PoC Validation",
            "Patch Generation",
        ]
        assert report.target == "target"
        assert report.risk_index == 78

    @pytest.mark.asyncio
    async def test_emits_completion_event_with_report(self):
        client = FakeGemma()
        orch = AuditOrchestrator(gemma_client=client)
        events = []
        await orch.run(
            [TargetFile(path="a.py", content="x = 1\n", size=5)],
            "demo",
            on_event=lambda e: events.append(e),
        )
        assert events[-1].kind == "complete"
        assert events[-1].stage == "Report Ready"

    @pytest.mark.asyncio
    async def test_report_validates_against_pydantic_schema(self):
        client = FakeGemma()
        orch = AuditOrchestrator(gemma_client=client)
        report = await orch.run(
            [TargetFile(path="a.py", content="x = 1\n", size=5)],
            "demo",
        )
        assert isinstance(report, AuditReport)
        revalidated = AuditReport.model_validate(report.model_dump())
        assert revalidated.risk_index == 78

    @pytest.mark.asyncio
    async def test_heuristic_findings_are_merged_into_report(self):
        client = FakeGemma()
        orch = AuditOrchestrator(gemma_client=client)
        report = await orch.run(
            [TargetFile(path="a.py", content="import os\nos.system(cmd)\n", size=20)],
            "demo",
        )
        assert any(f.category == "Command Injection" for f in report.findings)

    @pytest.mark.asyncio
    async def test_pipeline_survives_gemma_failure(self):
        class BrokenGemma(GemmaClient):
            def __init__(self):
                super().__init__(api_key="x", model="m")

            async def complete_json(self, prompt: str, schema: dict):
                raise RuntimeError("provider exploded")

        orch = AuditOrchestrator(gemma_client=BrokenGemma())
        report = await orch.run(
            [TargetFile(path="a.py", content="import os\nos.system(cmd)\n", size=20)],
            "demo",
        )
        assert report.findings  # heuristic findings still delivered
        assert report.model_dump()["engine_status"] == "degraded"

    @pytest.mark.asyncio
    async def test_empty_target_returns_empty_report_not_crash(self):
        client = FakeGemma()
        orch = AuditOrchestrator(gemma_client=client)
        report = await orch.run([], "empty")
        assert report.findings == []
        assert report.risk_index == 0


class TestPoCSafety:
    @pytest.mark.asyncio
    async def test_generated_poc_never_contains_destructive_commands(self):
        from app.core.poc_guard import sanitize_poc

        dangerous = [
            "rm -rf /",
            "DROP TABLE users;",
            "mkfs.ext4 /dev/sda",
            "shutdown -h now",
            ":(){ :|:& };:",
        ]
        for payload in dangerous:
            cleaned = sanitize_poc(payload)
            assert "rm -rf" not in cleaned
            assert "DROP TABLE" not in cleaned
            assert "mkfs" not in cleaned
            assert "shutdown" not in cleaned

    @pytest.mark.asyncio
    async def test_safe_poc_is_preserved(self):
        from app.core.poc_guard import sanitize_poc

        safe = 'curl -s "https://example.test/api/users/1" -H "Authorization: Bearer $TOKEN"'
        assert sanitize_poc(safe) == safe

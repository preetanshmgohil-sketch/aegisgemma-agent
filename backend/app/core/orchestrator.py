"""Audit orchestration pipeline.

Four stages, streamed to the UI as they complete:

    [AST Extraction] -> [Threat Vector Mapping] -> [PoC Validation] -> [Patch Generation]

The deterministic scanner always runs. The Gemma 4 pass enriches the report
with reasoning, prioritisation and remediation prose; if the provider is
missing or fails, the audit still completes with `engine_status="degraded"`.
"""

from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass, field
from typing import Any, Awaitable, Callable, Iterable

from ..schemas.audit_schema import (
    AuditReport,
    AttackSurfaceNode,
    CvssVectorModel,
    Finding,
    Location,
    PoC,
    RemediationPatch,
    Severity,
    TargetSummary,
    audit_report_schema,
    gemma_instruction,
)
from .cvss import calculate_base_score
from .gemma_client import GemmaClient, GemmaResponse
from .patcher import generate_patch
from .poc_guard import sanitize_poc
from .security_engine import ScanFinding, SecurityEngine, TargetFile

STAGES = [
    "AST Extraction",
    "Threat Vector Mapping",
    "PoC Validation",
    "Patch Generation",
]

EventCallback = Callable[["AuditEvent"], Awaitable[None] | None]


@dataclass
class AuditEvent:
    """A single streaming event emitted during an audit."""

    kind: str  # "stage" | "finding" | "thought" | "complete" | "error"
    stage: str
    message: str
    progress: int = 0
    data: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "kind": self.kind,
            "stage": self.stage,
            "message": self.message,
            "progress": self.progress,
            "data": self.data,
        }


class AuditOrchestrator:
    """Runs the four-stage audit pipeline."""

    def __init__(
        self,
        gemma_client: GemmaClient | None = None,
        engine: SecurityEngine | None = None,
    ) -> None:
        self.gemma = gemma_client or GemmaClient()
        self.engine = engine or SecurityEngine()

    async def run(
        self,
        files: Iterable[TargetFile],
        target: str,
        on_event: EventCallback | None = None,
    ) -> AuditReport:
        files = list(files)
        started = time.time()

        async def emit(event: AuditEvent) -> None:
            if on_event is None:
                return
            result = on_event(event)
            if asyncio.iscoroutine(result):
                await result

        if not files:
            await emit(
                AuditEvent(
                    kind="stage",
                    stage=STAGES[0],
                    message="No files supplied — nothing to audit.",
                    progress=100,
                )
            )
            empty_report = AuditReport(
                target=target,
                risk_index=0,
                summary=f"No files were supplied for '{target}', so there is nothing to audit.",
                findings=[],
                attack_surface=[],
                recommendations=["Upload a source tree, archive, or OpenAPI specification."],
                engine_status="ok",
                model=self.gemma.model,
            )
            await emit(
                AuditEvent(
                    kind="complete",
                    stage="Report Ready",
                    message="Audit complete — risk index 0/100.",
                    progress=100,
                    data={"report": empty_report.model_dump()},
                )
            )
            return empty_report

        # --- Stage 1: AST Extraction -------------------------------------
        await emit(
            AuditEvent(
                kind="stage",
                stage=STAGES[0],
                message=f"Ingested {len(files)} file(s); parsing structure.",
                progress=10,
            )
        )
        summary = self.engine.summarize(files)
        scan_findings = self.engine.scan(files)
        await emit(
            AuditEvent(
                kind="thought",
                stage=STAGES[0],
                message=(
                    f"Parsed {summary.file_count} files "
                    f"({summary.total_lines} lines, "
                    f"{len(summary.languages)} language(s)). "
                    f"Pattern layer surfaced {len(scan_findings)} candidate issue(s)."
                ),
                progress=25,
                data={"summary": summary.__dict__},
            )
        )

        # --- Stage 2: Threat Vector Mapping ------------------------------
        await emit(
            AuditEvent(
                kind="stage",
                stage=STAGES[1],
                message="Mapping findings to OWASP categories and CVSS v3.1 vectors.",
                progress=35,
            )
        )
        model_payload: dict[str, Any] = {}
        model_thoughts = ""
        model_error: str | None = None
        try:
            response = await self.gemma.complete_json(
                self._build_prompt(files, target, scan_findings),
                audit_report_schema(),
            )
            model_thoughts = response.thoughts
            model_payload = response.json
            if model_thoughts:
                await emit(
                    AuditEvent(
                        kind="thought",
                        stage=STAGES[1],
                        message=model_thoughts.strip(),
                        progress=50,
                        data={"usage": response.usage, "model": response.model},
                    )
                )
        except Exception as exc:  # provider missing/failed -> degraded mode
            model_error = f"{type(exc).__name__}: {exc}"
            await emit(
                AuditEvent(
                    kind="thought",
                    stage=STAGES[1],
                    message=(
                        "AI reasoning unavailable — continuing with the deterministic "
                        f"analysis layer only ({model_error})."
                    ),
                    progress=50,
                    data={"error": model_error},
                )
            )

        findings = self._merge_findings(scan_findings, model_payload.get("findings") or [])
        for finding in findings:
            await emit(
                AuditEvent(
                    kind="finding",
                    stage=STAGES[1],
                    message=f"{finding.severity.value if hasattr(finding.severity, 'value') else finding.severity}: {finding.title} ({finding.location.file}:{finding.location.line})",
                    progress=55,
                    data={"finding": finding.model_dump()},
                )
            )

        # --- Stage 3: PoC Validation -------------------------------------
        await emit(
            AuditEvent(
                kind="stage",
                stage=STAGES[2],
                message="Generating and safety-checking proof-of-concept verification steps.",
                progress=65,
            )
        )
        for finding in findings:
            poc = self._build_poc(finding)
            if poc is not None:
                finding.poc = poc
        await emit(
            AuditEvent(
                kind="thought",
                stage=STAGES[2],
                message=(
                    f"Validated {sum(1 for f in findings if f.poc)} non-destructive "
                    "proof-of-concept(s); destructive payloads are stripped by the safety guard."
                ),
                progress=75,
            )
        )

        # --- Stage 4: Patch Generation -----------------------------------
        await emit(
            AuditEvent(
                kind="stage",
                stage=STAGES[3],
                message="Generating unified diff remediation patches.",
                progress=85,
            )
        )
        file_map = {tf.path: tf.content for tf in files}
        for finding in findings:
            source = file_map.get(finding.location.file)
            if source is None:
                continue
            patch = self._build_patch(finding, source)
            if patch is not None:
                finding.patch = patch
        await emit(
            AuditEvent(
                kind="thought",
                stage=STAGES[3],
                message=(
                    f"Generated {sum(1 for f in findings if f.patch)} appliable unified diff(s)."
                ),
                progress=92,
            )
        )

        report = self._build_report(
            target=target,
            summary=summary,
            findings=findings,
            model_payload=model_payload,
            model_thoughts=model_thoughts,
            model_error=model_error,
            elapsed=time.time() - started,
        )

        await emit(
            AuditEvent(
                kind="complete",
                stage="Report Ready",
                message=f"Audit complete — risk index {report.risk_index}/100.",
                progress=100,
                data={"report": report.model_dump()},
            )
        )
        return report

    # -- helpers ------------------------------------------------------------

    def _build_prompt(
        self,
        files: list[TargetFile],
        target: str,
        scan_findings: list[ScanFinding],
    ) -> str:
        payload = self._build_payload(files, scan_findings)
        target_type = self._infer_target_type(files)
        return gemma_instruction(target, payload, target_type)

    @staticmethod
    def _infer_target_type(files: list[TargetFile]) -> str:
        names = {tf.path.lower() for tf in files}
        if any("openapi" in n or "swagger" in n for n in names):
            return "OpenAPI/Swagger specification"
        if any(n.endswith((".yaml", ".yml", ".k8s")) for n in names):
            return "Kubernetes / infrastructure configuration"
        if any(n.endswith((".tf", ".tfvars")) for n in names):
            return "Terraform infrastructure"
        if any(n == "dockerfile" or n.endswith(".dockerfile") for n in names):
            return "Docker build definition"
        return "source code repository"

    @staticmethod
    def _build_payload(files: list[TargetFile], scan_findings: list[ScanFinding]) -> str:
        blocks: list[str] = []
        for tf in files[:120]:
            snippet = tf.content[:8000]
            if len(tf.content) > 8000:
                snippet += "\n... [truncated]"
            blocks.append(f"### FILE: {tf.path}\n```\n{snippet}\n```")
        detector_hits = "\n".join(
            f"- {f.rule} @ {f.file}:{f.line} — {f.description}" for f in scan_findings
        )
        detector_block = (
            f"\n\n## STATIC ANALYSIS PRE-PASS (deterministic detector output)\n{detector_hits}"
            if detector_hits
            else ""
        )
        return "\n\n".join(blocks) + detector_block

    def _merge_findings(
        self,
        scan_findings: list[ScanFinding],
        model_findings: list[dict[str, Any]],
    ) -> list[Finding]:
        merged: list[Finding] = []
        seen: set[tuple[str, str, int]] = set()

        for raw in model_findings:
            finding = self._finding_from_model(raw, len(merged))
            if finding is None:
                continue
            key = (finding.title.lower(), finding.location.file, finding.location.line)
            seen.add(key)
            merged.append(finding)

        for scan in scan_findings:
            key = (scan.title.lower(), scan.file, scan.line)
            if key in seen:
                continue
            merged.append(self._finding_from_scan(scan, len(merged)))
            seen.add(key)

        order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "NONE": 4}
        merged.sort(key=lambda f: (order.get(f.severity, 5), f.location.file, f.location.line))
        for index, finding in enumerate(merged, start=1):
            finding.id = f"AEGIS-{index:03d}"
        return merged

    def _finding_from_model(self, raw: dict[str, Any], index: int) -> Finding | None:
        try:
            vector = str(raw.get("cvss", {}).get("vector") or raw.get("cvss_vector") or "")
            if not vector:
                return None
            computed = calculate_base_score(vector)
            severity = Severity.from_score(computed)
            location_raw = raw.get("location") or {}
            if isinstance(location_raw, str):
                location = Location(file=location_raw, line=1)
            else:
                location = Location(
                    file=str(location_raw.get("file") or "unknown"),
                    line=int(location_raw.get("line") or 1),
                )
            poc_raw = raw.get("poc")
            poc = None
            if isinstance(poc_raw, dict):
                poc = PoC(
                    kind=poc_raw.get("kind", "manual"),
                    title=poc_raw.get("title", "Verification step"),
                    command=sanitize_poc(str(poc_raw.get("command", ""))),
                    destructive=False,
                    expected_observation=str(
                        poc_raw.get("expected_observation", "Unexpected behaviour observed")
                    ),
                )
            patch_raw = raw.get("patch")
            patch = None
            if isinstance(patch_raw, dict) and patch_raw.get("diff"):
                try:
                    patch = RemediationPatch(
                        file=str(patch_raw.get("file") or location.file),
                        diff=str(patch_raw["diff"]),
                        rationale=str(patch_raw.get("rationale", "")),
                    )
                except Exception:
                    patch = None
            return Finding(
                id=f"MODEL-{index + 1:03d}",
                title=str(raw.get("title") or "Untitled finding"),
                category=str(raw.get("category") or "AI-identified"),
                severity=severity,
                cvss=CvssVectorModel(vector=vector, score=computed),
                cwe_id=str(raw.get("cwe_id") or "CWE-0") if str(raw.get("cwe_id", "")).startswith("CWE-") else "CWE-0",
                owasp_category=str(raw.get("owasp_category") or "Unmapped"),
                location=location,
                description=str(raw.get("description") or ""),
                evidence=str(raw.get("evidence") or ""),
                exploit_scenario=str(raw.get("exploit_scenario") or ""),
                remediation=str(raw.get("remediation") or ""),
                poc=poc,
                patch=patch,
            )
        except Exception:
            return None

    def _finding_from_scan(self, scan: ScanFinding, index: int) -> Finding:
        return Finding(
            id=scan.id,
            title=scan.title,
            category=scan.category,
            severity=scan.severity,
            cvss=CvssVectorModel(vector=scan.cvss_vector, score=scan.cvss_score),
            cwe_id=scan.cwe_id,
            owasp_category=scan.owasp_category,
            location=Location(file=scan.file, line=scan.line),
            description=scan.description,
            evidence=scan.snippet,
            remediation=scan.remediation,
        )

    def _build_poc(self, finding: Finding) -> PoC | None:
        if finding.poc is not None:
            return finding.poc
        template = POC_TEMPLATES.get(finding.category)
        if template is None:
            return None
        kind, title, command, expected = template
        command = sanitize_poc(command.replace("{file}", finding.location.file))
        if not command.strip():
            return None
        return PoC(
            kind=kind,
            title=title,
            command=command,
            destructive=False,
            expected_observation=expected,
        )

    @staticmethod
    def _build_patch(finding: Finding, source: str) -> RemediationPatch | None:
        if finding.patch is not None:
            return finding.patch
        scan = ScanFinding(
            id=finding.id,
            title=finding.title,
            category=finding.category,
            rule=finding.category,
            severity=finding.severity,
            cvss_vector=finding.cvss.vector,
            cvss_score=finding.cvss.score,
            cwe_id=finding.cwe_id,
            owasp_category=finding.owasp_category,
            file=finding.location.file,
            line=finding.location.line,
            snippet=finding.evidence,
            description=finding.description,
            remediation=finding.remediation,
        )
        result = generate_patch(scan, source)
        if result is None:
            return None
        diff, rationale = result
        try:
            return RemediationPatch(
                file=finding.location.file, diff=diff, rationale=rationale
            )
        except Exception:
            return None

    def _build_report(
        self,
        target: str,
        summary: Any,
        findings: list[Finding],
        model_payload: dict[str, Any],
        model_thoughts: str,
        model_error: str | None,
        elapsed: float,
    ) -> AuditReport:
        risk_index = self._risk_index(findings, model_payload)
        summary_text = str(model_payload.get("summary") or "").strip()
        if not summary_text:
            summary_text = self._fallback_summary(findings, target)
        recommendations = [
            str(r) for r in (model_payload.get("recommendations") or []) if str(r).strip()
        ]
        if not recommendations:
            recommendations = self._fallback_recommendations(findings)
        attack_surface = self._parse_attack_surface(model_payload.get("attack_surface") or [])
        return AuditReport(
            target=target,
            risk_index=risk_index,
            summary=summary_text,
            findings=findings,
            attack_surface=attack_surface,
            recommendations=recommendations,
            target_summary=TargetSummary(
                file_count=summary.file_count,
                languages=summary.languages,
                total_lines=summary.total_lines,
                entrypoints=summary.entrypoints,
                dependencies=summary.dependencies,
            ),
            engine_status="degraded" if model_error else "ok",
            model=self.gemma.model,
            reasoning_summary=(model_thoughts.strip() or None),
        )

    @staticmethod
    def _risk_index(findings: list[Finding], model_payload: dict[str, Any]) -> int:
        raw = model_payload.get("risk_index")
        if isinstance(raw, (int, float)):
            return int(max(0, min(100, round(raw))))
        if not findings:
            return 0
        weights = {"CRITICAL": 22, "HIGH": 12, "MEDIUM": 5, "LOW": 2, "NONE": 0}
        return int(min(100, sum(weights.get(f.severity, 0) for f in findings)))

    @staticmethod
    def _fallback_summary(findings: list[Finding], target: str) -> str:
        if not findings:
            return f"No vulnerabilities were identified in '{target}' by the static analysis layer."
        counts: dict[str, int] = {}
        for finding in findings:
            counts[finding.severity] = counts.get(finding.severity, 0) + 1
        breakdown = ", ".join(f"{count} {sev.lower()}" for sev, count in counts.items())
        return (
            f"{len(findings)} finding(s) in '{target}': {breakdown}. "
            "Scores follow CVSS v3.1; proof-of-concept steps are verification-only."
        )

    @staticmethod
    def _fallback_recommendations(findings: list[Finding]) -> list[str]:
        seen: list[str] = []
        for finding in findings:
            if finding.remediation and finding.remediation not in seen:
                seen.append(finding.remediation)
        return seen[:8] or ["Continue regular review; no findings require remediation."]

    @staticmethod
    def _parse_attack_surface(nodes: list[dict[str, Any]]) -> list[AttackSurfaceNode]:
        out: list[AttackSurfaceNode] = []
        for raw in nodes[:24]:
            if not isinstance(raw, dict):
                continue
            severity = raw.get("severity")
            if severity not in {"NONE", "LOW", "MEDIUM", "HIGH", "CRITICAL"}:
                severity = None
            try:
                out.append(
                    AttackSurfaceNode(
                        id=str(raw.get("id") or f"node-{len(out) + 1}"),
                        label=str(raw.get("label") or "node"),
                        kind=raw.get("kind") if raw.get("kind") in {
                            "entrypoint",
                            "service",
                            "data",
                            "dependency",
                            "identity",
                            "config",
                        } else "service",
                        severity=severity,
                        children=AuditOrchestrator._parse_attack_surface(
                            raw.get("children") or []
                        ),
                    )
                )
            except Exception:
                continue
        return out


POC_TEMPLATES: dict[str, tuple[str, str, str, str]] = {
    "Command Injection": (
        "python",
        "Observe argument handling without executing anything destructive",
        "import subprocess\n"
        "# Reproduce with a harmless marker instead of a real payload:\n"
        "subprocess.run([\"echo\", \"AEGIS_MARKER\"], shell=False)",
        "The application should echo only the literal marker and never spawn a shell.",
    ),
    "SQL Injection": (
        "payload",
        "Boolean probe against a disposable record id",
        "GET /api/items?id=1%20AND%201=1 -- comment (use a record you own)",
        "The response should be identical to /api/items?id=1; a difference indicates injection.",
    ),
    "Code Injection": (
        "payload",
        "Literal-only probe for dynamic evaluation",
        "payload = \"1+1\"  # must be parsed, never executed",
        "The endpoint should return 2 as a literal and reject any executable expression.",
    ),
    "XSS": (
        "payload",
        "Non-executing marker to confirm HTML context",
        "<aegis-marker>probe</aegis-marker>",
        "The marker should appear escaped as text, not as live markup.",
    ),
    "Broken Access Control": (
        "curl",
        "Read-only access check with your own token",
        'curl -s -i "https://TARGET/api/users/YOUR_OWN_ID" -H "Authorization: Bearer YOUR_TOKEN"',
        "Your own record returns 200; another user's record must return 403/404.",
    ),
    "Hardcoded Secrets": (
        "manual",
        "Confirm the credential is served from configuration",
        "grep -R \"<secret-name>\" ./config  # expect no literal value in source",
        "The value should only exist in the environment/secret manager, never in the repository.",
    ),
    "API Exposure": (
        "curl",
        "Unauthenticated read-only probe",
        'curl -s -i "https://TARGET/api/health"',
        "Sensitive endpoints should answer 401 without credentials.",
    ),
}

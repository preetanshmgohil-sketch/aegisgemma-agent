"""Heuristic static-analysis engine.

Runs before (and independently of) the LLM pass so AegisGemma still produces a
useful, evidence-backed report when no AI provider key is configured, and so
the model receives pre-normalised AST/pattern context to reason over.

Detected categories: Command Injection, SQL Injection, Code Injection, XSS,
Broken Access Control (BOLA/IDOR), Hardcoded Secrets, API Exposure,
Container Security, Kubernetes Misconfiguration, Terraform Misconfiguration.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable

from .cvss import calculate_base_score, severity_from_score

MAX_FILE_BYTES = 512 * 1024
MAX_FILES = 400

SKIP_DIR_PARTS = {
    ".git",
    ".hg",
    ".svn",
    "node_modules",
    "__pycache__",
    ".venv",
    "venv",
    "env",
    ".tox",
    ".mypy_cache",
    ".pytest_cache",
    "dist",
    "build",
    "out",
    "coverage",
    ".next",
    ".cache",
}

SKIP_FILENAMES = {
    "package-lock.json",
    "yarn.lock",
    "pnpm-lock.yaml",
    "poetry.lock",
    "pipfile.lock",
    "cargo.lock",
    "composer.lock",
    "go.sum",
}

LANGUAGE_BY_SUFFIX = {
    ".py": "Python",
    ".ts": "TypeScript",
    ".tsx": "TypeScript",
    ".js": "JavaScript",
    ".jsx": "JavaScript",
    ".mjs": "JavaScript",
    ".cjs": "JavaScript",
    ".go": "Go",
    ".java": "Java",
    ".rb": "Ruby",
    ".php": "PHP",
    ".rs": "Rust",
    ".c": "C",
    ".h": "C",
    ".cpp": "C++",
    ".cc": "C++",
    ".cs": "C#",
    ".sh": "Shell",
    ".bash": "Shell",
    ".yaml": "YAML",
    ".yml": "YAML",
    ".json": "JSON",
    ".md": "Markdown",
    ".tf": "Terraform",
    ".tfvars": "Terraform",
    ".sql": "SQL",
    ".html": "HTML",
    ".css": "CSS",
    ".dockerfile": "Dockerfile",
    ".k8s": "Kubernetes",
}

INFRA_SUFFIXES = {".yaml", ".yml", ".k8s", ".tf", ".tfvars", ".json", ".dockerfile"}


@dataclass
class TargetFile:
    """One ingested source file."""

    path: str
    content: str
    size: int = 0
    language: str | None = None

    def __post_init__(self) -> None:
        if not self.size:
            self.size = len(self.content)
        if self.language is None:
            self.language = language_for(self.path)


@dataclass
class ScanFinding:
    """A finding produced by the deterministic pattern layer."""

    id: str
    title: str
    category: str
    rule: str
    severity: str
    cvss_vector: str
    cvss_score: float
    cwe_id: str
    owasp_category: str
    file: str
    line: int
    snippet: str
    description: str
    remediation: str


@dataclass
class ProjectSummary:
    file_count: int
    languages: dict[str, int] = field(default_factory=dict)
    total_lines: int = 0
    entrypoints: list[str] = field(default_factory=list)
    dependencies: list[str] = field(default_factory=list)


def language_for(path: str) -> str:
    name = Path(path).name.lower()
    suffix = Path(path).suffix.lower()
    if name == "dockerfile" or suffix == ".dockerfile":
        return "Dockerfile"
    if suffix == ".k8s":
        return "Kubernetes"
    return LANGUAGE_BY_SUFFIX.get(suffix, "Other")


# --- rule definitions -------------------------------------------------------

# (vector, CWE, OWASP, remediation) per rule id.
RULES: dict[str, dict[str, str]] = {
    "command_injection": {
        "category": "Command Injection",
        "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "cwe": "CWE-78",
        "owasp": "A03:2021 - Injection",
        "remediation": "Pass arguments as a list with shell=False, or use a strict allow-list of permitted commands.",
    },
    "sql_injection": {
        "category": "SQL Injection",
        "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "cwe": "CWE-89",
        "owasp": "A03:2021 - Injection",
        "remediation": "Use parameterised queries / prepared statements instead of string interpolation.",
    },
    "code_injection": {
        "category": "Code Injection",
        "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "cwe": "CWE-94",
        "owasp": "A03:2021 - Injection",
        "remediation": "Replace eval/exec with explicit parsers (ast.literal_eval, json.loads, a dispatch table).",
    },
    "xss": {
        "category": "XSS",
        "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
        "cwe": "CWE-79",
        "owasp": "A03:2021 - Injection",
        "remediation": "Render untrusted data as text, or sanitise it with a vetted HTML sanitiser before assignment.",
    },
    "broken_access_control": {
        "category": "Broken Access Control",
        "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
        "cwe": "CWE-639",
        "owasp": "A01:2021 - Broken Access Control",
        "remediation": "Require an authenticated principal and authorise the object against that principal before returning it.",
    },
    "hardcoded_secret": {
        "category": "Hardcoded Secrets",
        "vector": "CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:H/I:N/A:N",
        "cwe": "CWE-798",
        "owasp": "A07:2021 - Identification and Authentication Failures",
        "remediation": "Load the secret from an environment variable or a secret manager and rotate the exposed value.",
    },
    "api_exposure": {
        "category": "API Exposure",
        "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
        "cwe": "CWE-306",
        "owasp": "A01:2021 - Broken Access Control",
        "remediation": "Declare a bearer/OAuth security scheme and require it on every sensitive operation.",
    },
    "container_security": {
        "category": "Container Security",
        "vector": "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
        "cwe": "CWE-250",
        "owasp": "A05:2021 - Security Misconfiguration",
        "remediation": "Drop root privileges: use USER with a non-root account and a read-only filesystem.",
    },
    "kubernetes_misconfig": {
        "category": "Kubernetes Misconfiguration",
        "vector": "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H",
        "cwe": "CWE-250",
        "owasp": "A05:2021 - Security Misconfiguration",
        "remediation": "Remove privileged: true, set runAsNonRoot: true, drop ALL capabilities and restrict host access.",
    },
    "terraform_misconfig": {
        "category": "Terraform Misconfiguration",
        "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
        "cwe": "CWE-732",
        "owasp": "A05:2021 - Security Misconfiguration",
        "remediation": "Use private buckets with explicit, least-privilege access policies and block public ACLs.",
    },
}

PLACEHOLDER_MARKERS = (
    "your",
    "changeme",
    "change-me",
    "example",
    "placeholder",
    "dummy",
    "sample",
    "fake",
    "todo",
    "xxx",
    "<",
    "none",
    "null",
    "test-key",
    "replaceme",
)

# Human-readable category -> internal rule id. Used by the remediation
# patcher, which works off the report's category rather than the scanner's
# internal rule key.
CATEGORY_TO_RULE = {
    "command injection": "command_injection",
    "sql injection": "sql_injection",
    "code injection": "code_injection",
    "xss": "xss",
    "cross-site scripting": "xss",
    "broken access control": "broken_access_control",
    "hardcoded secrets": "hardcoded_secret",
    "hardcoded secret": "hardcoded_secret",
    "api exposure": "api_exposure",
    "container security": "container_security",
    "kubernetes misconfiguration": "kubernetes_misconfig",
    "terraform misconfiguration": "terraform_misconfig",
}


def rule_for_category(category: str) -> str | None:
    """Resolve an internal rule id from a category label."""
    if not category:
        return None
    base = category.split(" (")[0].strip().lower()
    return CATEGORY_TO_RULE.get(base)

AWS_KEY_RE = re.compile(r"AKIA[0-9A-Z]{16}")
GENERIC_SECRET_RE = re.compile(
    r"(?i)\b(password|passwd|pwd|secret|api[_-]?key|apikey|auth[_-]?token|"
    r"access[_-]?token|private[_-]?key|client[_-]?secret|credential[s]?)\b"
    r"\s*[:=]\s*[\"']([^\"'\n]{8,})[\"']"
)
# Unquoted YAML/Terraform style secret: `password: <value>` with a strong key
# name and a long, space-free value.
UNQUOTED_SECRET_RE = re.compile(
    r"(?i)\b(password|passwd|secret|api[_-]?key|apikey|auth[_-]?token|"
    r"access[_-]?token|private[_-]?key|client[_-]?secret)\b\s*[:=]\s*"
    r"([^\s\"'\n]{12,})"
)
PRIVATE_KEY_RE = re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")

COMMAND_RE = re.compile(r"(?i)\b(os\.system|os\.popen|commands\.getoutput|shell_exec)\s*\(")
SUBPROCESS_SHELL_RE = re.compile(r"(?i)subprocess\.(run|Popen|call|check_output)\s*\([^)]*shell\s*=\s*True")
EVAL_RE = re.compile(r"(?i)(?<![.\w])(eval|exec)\s*\(")
SQL_KEYWORDS = ("select", "insert", "update", "delete", "drop", "union")
EXEC_RE = re.compile(r"(?i)\b(execute|executemany|executescript|raw|query)\s*\(")
XSS_RE = re.compile(r"(?i)(\.innerHTML\s*=|\.outerHTML\s*=|document\.write\s*\(|dangerouslySetInnerHTML)")

AUTH_HINT_RE = re.compile(
    r"(?i)(Depends\s*\(|current_user|require_auth|login_required|authenticate|"
    r"@login_required|permission|authorize|jwt|oauth|api_key|apikey|token)"
)


def _redact(text: str) -> str:
    text = AWS_KEY_RE.sub("[REDACTED_AWS_KEY]", text)
    text = PRIVATE_KEY_RE.sub("[REDACTED_PRIVATE_KEY]", text)
    text = GENERIC_SECRET_RE.sub(
        lambda m: f'{m.group(1)} = "[REDACTED_SECRET]"', text
    )
    return text


def _is_skipped(path: str) -> bool:
    parts = {p.lower() for p in Path(path).parts}
    if parts & SKIP_DIR_PARTS:
        return True
    name = Path(path).name.lower()
    if name in SKIP_FILENAMES:
        return True
    if name.endswith(".min.js") or name.endswith(".min.css"):
        return True
    return False


def _is_binary(content: str) -> bool:
    return "\x00" in content[:4096]


class SecurityEngine:
    """Deterministic, dependency-free static analysis pass."""

    def __init__(self) -> None:
        self._counter = 0

    # -- public API ---------------------------------------------------------

    def scan(self, files: Iterable[TargetFile]) -> list[ScanFinding]:
        findings: list[ScanFinding] = []
        self._counter = 0
        for tf in files:
            if _is_skipped(tf.path):
                continue
            if tf.size > MAX_FILE_BYTES or _is_binary(tf.content):
                continue
            findings.extend(self._scan_file(tf))
        findings.sort(key=lambda f: (-f.cvss_score, f.file, f.line))
        return findings

    def summarize(self, files: Iterable[TargetFile]) -> ProjectSummary:
        files = list(files)
        languages: dict[str, int] = {}
        total_lines = 0
        entrypoints: list[str] = []
        dependencies: list[str] = []
        for tf in files:
            if _is_skipped(tf.path):
                continue
            lang = tf.language or language_for(tf.path)
            languages[lang] = languages.get(lang, 0) + 1
            total_lines += tf.content.count("\n") + 1
            if re.search(r"(?i)(def main|@app\.|@router\.|app\.listen|func main)", tf.content):
                entrypoints.append(tf.path)
            if tf.path.lower().endswith(("requirements.txt", "package.json", "pyproject.toml", "go.mod")):
                dependencies.append(tf.path)
        return ProjectSummary(
            file_count=len(files),
            languages=dict(sorted(languages.items(), key=lambda kv: -kv[1])),
            total_lines=total_lines,
            entrypoints=entrypoints[:40],
            dependencies=dependencies,
        )

    # -- internals ----------------------------------------------------------

    def _make(
        self,
        rule: str,
        title: str,
        tf: TargetFile,
        line_no: int,
        snippet: str,
        description: str,
    ) -> ScanFinding:
        meta = RULES[rule]
        score = calculate_base_score(meta["vector"])
        self._counter += 1
        return ScanFinding(
            id=f"AEGIS-{self._counter:03d}",
            title=title,
            category=RULES[rule].get("category", title),
            rule=rule,
            severity=severity_from_score(score),
            cvss_vector=meta["vector"],
            cvss_score=score,
            cwe_id=meta["cwe"],
            owasp_category=meta["owasp"],
            file=tf.path,
            line=line_no,
            snippet=_redact(snippet.strip()),
            description=description,
            remediation=meta["remediation"],
        )

    def _scan_file(self, tf: TargetFile) -> list[ScanFinding]:
        out: list[ScanFinding] = []
        name = Path(tf.path).name.lower()
        suffix = Path(tf.path).suffix.lower()
        is_openapi = name.startswith("openapi") or name.startswith("swagger")
        is_docker = name == "dockerfile" or suffix == ".dockerfile"

        for idx, raw_line in enumerate(tf.content.splitlines(), start=1):
            line = raw_line.strip()
            if not line or line.startswith(("#", "//")):
                continue

            if COMMAND_RE.search(line) or SUBPROCESS_SHELL_RE.search(line):
                out.append(
                    self._make(
                        "command_injection",
                        "Command Injection",
                        tf,
                        idx,
                        raw_line,
                        "A command string reaches a shell interpreter with attacker-influenced data.",
                    )
                )
                continue

            if self._looks_like_sql_interpolation(line):
                out.append(
                    self._make(
                        "sql_injection",
                        "SQL Injection",
                        tf,
                        idx,
                        raw_line,
                        "SQL is built by string interpolation instead of bound parameters.",
                    )
                )
                continue

            if EVAL_RE.search(line):
                out.append(
                    self._make(
                        "code_injection",
                        "Code Injection",
                        tf,
                        idx,
                        raw_line,
                        "Dynamic evaluation of a runtime string permits arbitrary code execution.",
                    )
                )
                continue

            if XSS_RE.search(line):
                out.append(
                    self._make(
                        "xss",
                        "XSS (Cross-Site Scripting)",
                        tf,
                        idx,
                        raw_line,
                        "Untrusted data is written into a browser HTML sink without escaping.",
                    )
                )
                continue

            secret_hit = self._secret_in_line(line)
            if secret_hit:
                out.append(
                    self._make(
                        "hardcoded_secret",
                        "Hardcoded Secrets",
                        tf,
                        idx,
                        raw_line,
                        "A credential literal is embedded in source and will ship with the artefact.",
                    )
                )
                continue

            if is_docker and re.match(r"(?i)^\s*USER\s+root", line):
                out.append(
                    self._make(
                        "container_security",
                        "Container Security",
                        tf,
                        idx,
                        raw_line,
                        "The image explicitly runs as root, widening the blast radius of a container escape.",
                    )
                )
                continue

            if suffix in {".yaml", ".yml", ".k8s"} or name.endswith(".k8s.yaml"):
                if re.search(r"(?i)privileged\s*:\s*true", line) or re.search(
                    r"(?i)runAsUser\s*:\s*0\b", line
                ):
                    out.append(
                        self._make(
                            "kubernetes_misconfig",
                            "Kubernetes Misconfiguration",
                            tf,
                            idx,
                            raw_line,
                            "The workload requests privileged/root execution.",
                        )
                    )
                    continue

            if suffix in {".tf", ".tfvars"}:
                if re.search(r"(?i)acl\s*=\s*[\"'](public-read|public-read-write)[\"']", line) or re.search(
                    r"[\"']0\.0\.0\.0/0[\"']", line
                ):
                    out.append(
                        self._make(
                            "terraform_misconfig",
                            "Terraform Misconfiguration",
                            tf,
                            idx,
                            raw_line,
                            "Infrastructure is provisioned with world-readable or world-writable access.",
                        )
                    )
                    continue

        if is_openapi:
            out.extend(self._scan_openapi(tf))
        out.extend(self._scan_routes(tf))
        out.extend(self._scan_env_secrets(tf))
        return out

    def _scan_env_secrets(self, tf: TargetFile) -> list[ScanFinding]:
        """Flag Kubernetes/Docker env vars whose value is a literal credential.

        The secret name lives on one line and the value on the next, so a
        line-by-line regex cannot see it.
        """
        if not tf.path.endswith((".yaml", ".yml", ".k8s", ".tf", ".tfvars")):
            return []
        lines = tf.content.splitlines()
        out: list[ScanFinding] = []
        for idx, raw_line in enumerate(lines[:-1]):
            name_match = re.match(
                r"(?i)\s*-?\s*name\s*:\s*[\"']?([A-Za-z0-9_.-]*(?:PASSWORD|SECRET|TOKEN|API_KEY|ACCESS_KEY)[A-Za-z0-9_.-]*)[\"']?",
                raw_line,
            )
            if not name_match:
                continue
            value_line = lines[idx + 1]
            value_match = re.match(
                r"\s*(?:-?\s*)?value\s*:\s*[\"']?([^\"'\n]{8,})[\"']?\s*$", value_line
            )
            if not value_match:
                continue
            value = value_match.group(1).strip()
            if self._is_placeholder(value.lower()) or "$" in value or "{{" in value:
                continue
            redacted_value_line = value_line.replace(value, "[REDACTED_SECRET]")
            out.append(
                self._make(
                    "hardcoded_secret",
                    "Hardcoded Secrets",
                    tf,
                    idx + 2,
                    redacted_value_line,
                    f"Environment variable {name_match.group(1)} carries a literal credential.",
                )
            )
        return out

    def _scan_routes(self, tf: TargetFile) -> list[ScanFinding]:
        """Flag HTTP routes that expose data without an authentication guard."""
        if not tf.path.endswith((".py", ".js", ".ts", ".tsx", ".go", ".rb")):
            return []
        lines = tf.content.splitlines()
        out: list[ScanFinding] = []
        for idx, raw_line in enumerate(lines):
            stripped = raw_line.strip()
            is_route = bool(
                re.match(r"@(app|router|blueprint|bp)\.(get|post|put|patch|delete|route)\s*\(", stripped)
                or re.match(r"@(Get|Post|Put|Patch|Delete)\s*\(", stripped)
                or re.match(r"(app|router)\.(get|post|put|patch|delete)\s*\(", stripped)
            )
            if not is_route:
                continue
            window = "\n".join(lines[idx : idx + 8])
            if AUTH_HINT_RE.search(window):
                continue
            # A route decorator followed by a function signature with an
            # explicit auth parameter also counts as guarded.
            out.append(
                self._make(
                    "broken_access_control",
                    "Broken Access Control",
                    tf,
                    idx + 1,
                    raw_line,
                    "HTTP route is reachable without an authentication or authorisation check.",
                )
            )
        return out

    def _looks_like_sql_interpolation(self, line: str) -> bool:
        if not EXEC_RE.search(line):
            return False
        lowered = line.lower()
        if not any(kw in lowered for kw in SQL_KEYWORDS):
            return False
        if "?" in line and ", (" in line:
            return False
        if re.search(r"%s\b", line) and ", (" in line:
            return False
        interpolating = (
            re.search(r"[\"']\s*\+", line)
            or re.search(r"\+\s*[\"']", line)
            or re.search(r"[\"']\s*%\s*[\w(]", line)
            or re.search(r"\bf[\"']", line)
            or ".format(" in line
            or "${" in line
            or "`${" in line
        )
        return bool(interpolating)

    def _secret_in_line(self, line: str) -> bool:
        if AWS_KEY_RE.search(line) or PRIVATE_KEY_RE.search(line):
            return True
        m = GENERIC_SECRET_RE.search(line)
        if m:
            value = m.group(2).lower()
            if not self._is_placeholder(value):
                return True
        m2 = UNQUOTED_SECRET_RE.search(line)
        if m2:
            value = m2.group(2).lower()
            if not self._is_placeholder(value) and "$" not in value and "{" not in value:
                return True
        return False

    @staticmethod
    def _is_placeholder(value: str) -> bool:
        if len(value) < 8:
            return True
        return any(marker in value for marker in PLACEHOLDER_MARKERS)

    def _scan_openapi(self, tf: TargetFile) -> list[ScanFinding]:
        spec = self._load_spec(tf.content)
        if spec is None:
            return []
        out: list[ScanFinding] = []
        security = spec.get("security")
        schemes = (spec.get("components") or {}).get("securitySchemes") or {}
        if not security and not schemes:
            out.append(
                self._make(
                    "api_exposure",
                    "API Exposure (missing authentication)",
                    tf,
                    1,
                    "openapi: no security scheme declared",
                    "The specification declares no security scheme, so every operation is unauthenticated.",
                )
            )
            return out
        for name, scheme in schemes.items():
            stype = (scheme or {}).get("type")
            scheme_name = (scheme or {}).get("scheme")
            weak = stype != "http" or (stype == "http" and scheme_name != "bearer")
            if stype in {"apiKey", "basic"}:
                weak = True
            if stype == "http" and scheme_name == "bearer":
                weak = False
            if weak:
                out.append(
                    self._make(
                        "api_exposure",
                        f"API Exposure (weak security scheme: {name})",
                        tf,
                        1,
                        f"securityScheme {name}: type={stype} scheme={scheme_name}",
                        "The API authenticates with a weak or replayable credential type.",
                    )
                )
        return out

    @staticmethod
    def _load_spec(content: str) -> dict | None:
        text = content.strip()
        try:
            if text.startswith("{"):
                data = json.loads(text)
                return data if isinstance(data, dict) else None
        except json.JSONDecodeError:
            return None
        try:
            import yaml  # type: ignore

            data = yaml.safe_load(text)
            return data if isinstance(data, dict) else None
        except Exception:
            return None

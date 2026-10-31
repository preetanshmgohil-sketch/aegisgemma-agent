# AegisGemma

**Autonomous Red-Teaming & Security Sandbox Agent** — an open-source, local-first security audit assistant that ingests source code, OpenAPI/Swagger specifications and infrastructure config (Docker, Kubernetes, Terraform), then produces a scored vulnerability report, a threat graph, non-destructive proof-of-concept verification steps and appliable remediation patches.

> **Track 1 — Best Open-Source AI Project** · Apache 2.0 · runs fully locally · one-command setup.
> **Track 2 — Best Use of Gemma 4** · powered by `gemma-4-31b-it` with `thinking_level="high"` via the official `google-genai` SDK.

---

## Table of contents

- [What it does](#what-it-does)
- [Architecture](#architecture)
- [Quickstart](#quickstart)
- [Configuration](#configuration)
- [Gemma 4 integration](#gemma-4-integration)
- [Scoring standard](#scoring-standard)
- [Safety model](#safety-model)
- [Project layout](#project-layout)
- [Testing](#testing)
- [API reference](#api-reference)
- [Track compliance](#track-compliance)
- [License](#license)

---

## What it does

| Capability | Detail |
|---|---|
| **Target ingestion** | Drag-and-drop folders, multi-file uploads, `.zip` archives, OpenAPI JSON/YAML, Dockerfiles, K8s manifests, Terraform. Binary files, vendor directories and lockfiles are skipped automatically. |
| **Deterministic static analysis** | A dependency-free pattern engine detects command injection, SQL injection, code injection, XSS, broken access control (BOLA/IDOR), hardcoded secrets, API exposure, and Docker/Kubernetes/Terraform misconfigurations. |
| **Gemma 4 reasoning** | The model performs multi-step threat modelling over the normalised code context and emits a structured JSON report (OWASP Top 10 + CWE + CVSS v3.1). |
| **Risk index** | An aggregate 0–100 dial, animated in the UI. |
| **Threat graph** | Entry points, services, data stores and identities rendered as an interactive tree with a live radar sweep during analysis. |
| **Non-destructive PoC synthesis** | Verification-only `curl` / Python / payload snippets. Destructive commands are stripped by a dedicated safety guard before anything reaches the UI. |
| **1-click remediation** | Real unified diffs (`--- a/file` / `+++ b/file`) for the mechanical fixes, with rationale. |
| **Live streaming** | A WebSocket channel pushes every pipeline stage, thought and finding to the browser as it happens. |

The pipeline always runs in four stages:

```
[AST Extraction] → [Threat Vector Mapping] → [PoC Validation] → [Patch Generation]
```

---

## Architecture

```
┌──────────────────────────┐        WebSocket / REST        ┌────────────────────────────┐
│  Next.js 14 Frontend     │  ◄──────────────────────────►  │  FastAPI Backend           │
│  React 18 · TypeScript   │        /api/v1/audits          │  Python 3.11+ · async       │
│  Tailwind · Framer Motion│                                  │                            │
└──────────────────────────┘                                  │  ┌──────────────────────┐  │
                                                             │  │ security_engine.py   │  │
                                                             │  │ (deterministic AST/  │  │
                                                             │  │  pattern pre-pass)   │  │
                                                             │  └──────────┬───────────┘  │
                                                             │             │ normalised ctx│
                                                             │  ┌──────────▼───────────┐  │
                                                             │  │ gemma_client.py      │  │
                                                             │  │ google-genai SDK     │  │
                                                             │  │ thinking_level=high  │  │
                                                             │  │ JSON schema output   │  │
                                                             │  └──────────┬───────────┘  │
                                                             │  ┌──────────▼───────────┐  │
                                                             │  │ orchestrator.py      │  │
                                                             │  │ 4-stage pipeline     │  │
                                                             │  │ cvss.py · patcher.py │  │
                                                             │  │ poc_guard.py         │  │
                                                             │  └──────────────────────┘  │
                                                             └────────────────────────────┘
```

**Design note — graceful degradation.** The deterministic scanner always runs. If no AI provider key is configured (or the provider fails), the audit still completes with `engine_status: "degraded"`, so the tool is fully demonstrable offline and in CI. When a key is present, Gemma 4's findings are merged with — never substituted for — the scanner's evidence-backed results.

---

## Quickstart

### Prerequisites

- Python **3.11+**
- Node.js **18+**
- (Optional) A `GEMINI_API_KEY` for the Google GenAI SDK, or an `NVIDIA_API_KEY` for an OpenAI-compatible endpoint

### 1. Backend

```bash
cd backend
python -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\activate
pip install -r requirements.txt
cp .env.example .env             # Windows: copy .env.example .env
uvicorn app.main:app --reload --port 8000
```

### 2. Frontend

```bash
cd frontend
npm install
npm run dev
```

Open **http://localhost:3000**.

### One-command launch (Windows)

```bat
run.bat
```

Starts the backend on `:8000` and the frontend on `:3000` in separate windows.

### One-command launch (macOS / Linux)

```bash
chmod +x run.sh
./run.sh
```

### Docker

```bash
cd backend
docker build -t aegisgemma-backend .
docker run --rm -p 8000:8000 --env-file .env aegisgemma-backend
```

---

## Configuration

Backend configuration lives in `backend/.env`:

```dotenv
# ── Provider ──────────────────────────────────────────────────────────────
# "google"  → official google-genai SDK (GEMINI_API_KEY)
# "nvidia"  → OpenAI-compatible endpoint (NVIDIA_API_KEY)
GEMMA_PROVIDER=google

# ── Google Gemini API ─────────────────────────────────────────────────────
GEMINI_API_KEY=

# ── OpenAI-compatible endpoint (optional alternative) ─────────────────────
NVIDIA_API_KEY=
NVIDIA_BASE_URL=https://integrate.api.nvidia.com/v1

# ── Model ─────────────────────────────────────────────────────────────────
GEMMA_MODEL=gemma-4-31b-it
GEMMA_THINKING_LEVEL=high
```

Frontend configuration lives in `frontend/.env.local`:

```dotenv
NEXT_PUBLIC_API_URL=http://localhost:8000
```

---

## Gemma 4 integration

The core reasoning module uses the official `google-genai` SDK with a strict reasoning configuration and a JSON structured-output schema:

```python
from google import genai
from google.genai import types

client = genai.Client(api_key=os.environ.get("GEMINI_API_KEY"))

response = await client.aio.models.generate_content(
    model="gemma-4-31b-it",
    contents=prompt,
    config=types.GenerateContentConfig(
        system_instruction=system_instruction,
        thinking_config=types.ThinkingConfig(thinking_level="high"),
        response_mime_type="application/json",
        response_schema=AuditReport.model_json_schema(),
    ),
)
```

**Why it is built this way**

- `thinking_level="high"` unlocks Gemma 4's deep multi-step reasoning buffer for threat modelling.
- `response_mime_type="application/json"` plus `response_schema` makes the model emit a schema-valid report, so the Pydantic contract is enforced on both sides of the wire.
- Every CVSS score is **recomputed from the vector** by our own engine on the way in — a model cannot submit a score that contradicts the spec.
- An OpenAI-compatible fallback (`GEMMA_PROVIDER=nvidia`) keeps the tool usable where a Gemini key is not available, with the identical schema contract.

---

## Scoring standard

All scores follow **CVSS v3.1** exactly — the base-score equation from the FIRST specification, including the Appendix A `Roundup` function.

The implementation is cross-validated against the independent reference `cvss` library across a broad vector sample (`backend/tests/test_cvss_reference.py`):

```
CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H  →  9.8  CRITICAL
CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:L  →  7.7  HIGH
CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N  →  3.7  MEDIUM
CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:N  →  1.8  LOW
```

Findings map to **OWASP Top 10 (2021)** and the relevant **CWE** identifier.

---

## Safety model

AegisGemma is a *verification* tool, not an attack tool.

- **PoC guard** (`backend/app/core/poc_guard.py`) strips destructive commands before they reach the UI: `rm -rf`, `DROP TABLE`, `mkfs`, `shutdown`, fork bombs, `curl | sh`, and recursive deletes of system paths.
- The Pydantic `PoC` model **refuses** any PoC flagged `destructive=True`.
- **Secrets are redacted** in all evidence snippets (`AKIA…`, private-key blocks, generic credential assignments).
- Patch generation only automates mechanical fixes where correctness is guaranteed; it never invents a patch for a judgement call like SQL construction or access control.
- The tool never executes the target, never sends traffic to third parties, and never runs the generated proof-of-concept. Verification steps are shown for a human to run deliberately against a system they own.

---

## Project layout

```
aegisgemma-agent/
├── backend/
│   ├── app/
│   │   ├── api/v1/
│   │   │   ├── audit.py           # Audit trigger, report & event endpoints
│   │   │   └── websocket.py       # WS endpoint for live audit progress
│   │   ├── core/
│   │   │   ├── cvss.py            # CVSS v3.1 base-score engine
│   │   │   ├── gemma_client.py    # google-genai SDK wrapper (Gemma 4)
│   │   │   ├── security_engine.py # AST / static analysis pre-parser
│   │   │   ├── orchestrator.py    # 4-stage audit pipeline
│   │   │   ├── patcher.py         # Unified-diff remediation generator
│   │   │   ├── poc_guard.py       # Destructive-command stripping
│   │   │   ├── ingest.py          # Upload / archive / folder ingestion
│   │   │   └── session_store.py   # In-memory session + event fan-out
│   │   ├── schemas/
│   │   │   └── audit_schema.py    # Pydantic schemas for JSON output
│   │   └── main.py                # FastAPI app
│   ├── tests/                     # 128 tests
│   ├── requirements.txt
│   ├── Dockerfile
│   └── .env.example
├── frontend/
│   ├── src/
│   │   ├── app/                   # Next.js App Router
│   │   ├── components/
│   │   │   ├── Dashboard/         # Risk dial, threat graph
│   │   │   ├── FileUploader/      # Drag-and-drop dropzone
│   │   │   ├── ThinkingTrace/     # Streaming reasoning window
│   │   │   └── VulnerabilityViewer/ # Diff + PoC copy tool
│   │   ├── lib/                   # API client + shared types
│   │   └── styles/                # Tailwind entry + design tokens
│   ├── tailwind.config.ts
│   └── package.json
├── LICENSE                        # Apache License 2.0
├── README.md
├── run.bat / run.sh               # One-command launchers
└── .gitignore
```

---

## Testing

```bash
cd backend
pytest tests/ -q          # 128 passed
```

The suite covers the CVSS engine (against the reference implementation), the deterministic scanner, the Pydantic contract, the orchestrator's four-stage pipeline and its degraded-mode behaviour, the PoC safety guard, the patch generator and the Gemma client wrapper.

---

## API reference

| Method | Endpoint | Purpose |
|---|---|---|
| `GET` | `/health` | Liveness + provider status |
| `GET` | `/api/v1/config` | Runtime config (provider, model, thinking level) |
| `POST` | `/api/v1/audits` | Start an audit (multipart `files`, `target`, or `path`) → `202` with session id |
| `GET` | `/api/v1/audits` | List audit sessions |
| `GET` | `/api/v1/audits/{id}` | Session snapshot |
| `GET` | `/api/v1/audits/{id}/events` | Full event log |
| `GET` | `/api/v1/audits/{id}/report` | The final `AuditReport` |
| `WS` | `/api/v1/audits/{id}/stream` | Live stage/thought/finding stream |

Interactive API docs: **http://localhost:8000/docs**

---

## Track compliance

### Track 1 — Best Open-Source AI Project

- Apache License 2.0 (see [`LICENSE`](LICENSE)).
- Fully local execution: the backend and frontend run on your machine; no data leaves the host unless you configure a hosted model endpoint.
- No vendor lock-in: the provider layer supports the official `google-genai` SDK and any OpenAI-compatible endpoint behind one flag.
- Deterministic, dependency-light core: the scanner, CVSS engine, patcher and PoC guard are pure Python with no heavyweight dependencies.
- 128 automated tests, including cross-validation of the CVSS engine against an independent reference implementation.

### Track 2 — Best Use of Gemma 4

- `gemma-4-31b-it` via the official `google-genai` SDK.
- `thinking_config=types.ThinkingConfig(thinking_level="high")` for deep multi-step threat modelling.
- Structured JSON output via `response_mime_type` + `response_schema` derived from the Pydantic contract.
- The model's reasoning trace is surfaced live in the UI, so the judge can see *how* Gemma 4 reached each finding.
- Model findings are merged with deterministic scanner evidence and re-scored by our own CVSS v3.1 engine — the model is used for judgement, not for arithmetic.

---

## License

Apache License 2.0 — see [`LICENSE`](LICENSE).

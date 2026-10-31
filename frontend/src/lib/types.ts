/**
 * Shared API types — mirrors backend/app/schemas/audit_schema.py.
 */

export type Severity = "NONE" | "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";

export interface Cvss {
  vector: string;
  score: number;
}

export interface Location {
  file: string;
  line: number;
  column?: number | null;
  function?: string | null;
}

export interface PoC {
  kind: "curl" | "python" | "payload" | "manual" | "bash";
  title: string;
  command: string;
  destructive: boolean;
  expected_observation: string;
}

export interface RemediationPatch {
  file: string;
  diff: string;
  rationale: string;
  applied: boolean;
}

export interface Finding {
  id: string;
  title: string;
  category: string;
  severity: Severity;
  cvss: Cvss;
  cwe_id: string;
  owasp_category: string;
  location: Location;
  description: string;
  evidence: string;
  exploit_scenario: string;
  remediation: string;
  poc: PoC | null;
  patch: RemediationPatch | null;
}

export interface AttackSurfaceNode {
  id: string;
  label: string;
  kind: "entrypoint" | "service" | "data" | "dependency" | "identity" | "config";
  severity: Severity | null;
  children: AttackSurfaceNode[];
}

export interface TargetSummary {
  file_count: number;
  languages: Record<string, number>;
  total_lines: number;
  entrypoints: string[];
  dependencies: string[];
}

export interface AuditReport {
  target: string;
  risk_index: number;
  summary: string;
  findings: Finding[];
  attack_surface: AttackSurfaceNode[];
  recommendations: string[];
  target_summary: TargetSummary | null;
  engine_status: "ok" | "degraded";
  model: string | null;
  reasoning_summary: string | null;
}

export interface AuditEvent {
  kind: "stage" | "thought" | "finding" | "complete" | "error" | "heartbeat";
  stage: string;
  message: string;
  progress: number;
  data: Record<string, unknown>;
}

export interface RuntimeConfig {
  provider: string;
  model: string;
  thinking_level: string;
  ai_available: boolean;
  specs: string[];
}

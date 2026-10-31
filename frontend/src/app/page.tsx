"use client";

import { useCallback, useEffect, useRef, useState } from "react";
import { motion, AnimatePresence } from "framer-motion";
import { Activity, Cpu, Radar, ShieldAlert } from "lucide-react";

import { Dropzone } from "@/components/FileUploader/Dropzone";
import { ThinkingTrace } from "@/components/ThinkingTrace/ThinkingTrace";
import { RiskDial } from "@/components/Dashboard/RiskDial";
import { ThreatGraph } from "@/components/Dashboard/ThreatGraph";
import { VulnerabilityViewer } from "@/components/VulnerabilityViewer/VulnerabilityViewer";
import { fetchConfig, fetchReport, openAuditStream, startAudit } from "@/lib/api";
import type { AuditEvent, AuditReport, RuntimeConfig } from "@/lib/types";

export default function Home() {
  const [events, setEvents] = useState<AuditEvent[]>([]);
  const [report, setReport] = useState<AuditReport | null>(null);
  const [running, setRunning] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [config, setConfig] = useState<RuntimeConfig | null>(null);
  const [target, setTarget] = useState("uploaded-target");
  const socketRef = useRef<WebSocket | null>(null);

  useEffect(() => {
    fetchConfig().then(setConfig).catch(() => setConfig(null));
    return () => socketRef.current?.close();
  }, []);

  const handleFiles = useCallback(
    async (files: File[]) => {
      if (files.length === 0) return;
      setError(null);
      setEvents([]);
      setReport(null);
      setRunning(true);

      try {
        const session = await startAudit(files, target);
        let settled = false;

        const settle = (next: AuditReport | null) => {
          if (settled) return;
          settled = true;
          setRunning(false);
          if (next) setReport(next);
        };

        const socket = openAuditStream(session.id, (event) => {
          setEvents((current) => [...current, event]);
          if (event.kind === "complete") {
            const payload = event.data.report as AuditReport | undefined;
            settle(payload ?? null);
          }
          if (event.kind === "error") settle(null);
        });
        socketRef.current = socket;

        // The socket can close before the terminal frame lands (or the audit
        // can finish before we subscribe). Always reconcile against the REST
        // report endpoint so the results panel is never left hanging.
        socket.onclose = () => {
          fetchReport(session.id)
            .then((report) => settle(report))
            .catch(() => settle(null));
        };
        socket.onerror = () => {
          fetchReport(session.id)
            .then((report) => settle(report))
            .catch(() => settle(null));
        };
      } catch (err) {
        setError(err instanceof Error ? err.message : "Audit request failed");
        setRunning(false);
      }
    },
    [target],
  );

  const severityCounts = (report?.findings ?? []).reduce<Record<string, number>>(
    (acc, finding) => {
      acc[finding.severity] = (acc[finding.severity] ?? 0) + 1;
      return acc;
    },
    {},
  );

  return (
    <main className="mx-auto w-full max-w-[1280px] px-6 py-8">
      {/* Header */}
      <header className="mb-8 flex flex-wrap items-center justify-between gap-4">
        <div className="flex items-center gap-3.5">
          <div className="relative rounded-xl border border-emerald-dim/40 bg-slate-900/80 p-2.5">
            <ShieldAlert size={22} className="text-emerald-glow" strokeWidth={1.6} />
            <span
              aria-hidden
              className="absolute inset-0 rounded-xl"
              style={{ boxShadow: "0 0 22px -6px rgba(0,255,157,0.6)" }}
            />
          </div>
          <div>
            <h1 className="text-xl font-semibold tracking-tight text-slate-50">
              AegisGemma
            </h1>
            <p className="text-sm text-slate-500">
              Autonomous red-teaming & security sandbox agent
            </p>
          </div>
        </div>

        <div className="flex flex-wrap items-center gap-2">
          <span className="flex items-center gap-1.5 rounded-lg border border-slate-700 bg-slate-900/70 px-3 py-1.5 font-mono text-2xs text-slate-400">
            <Cpu size={12} className="text-emerald-dim" />
            {config?.model ?? "gemma-4-31b-it"}
          </span>
          <span className="flex items-center gap-1.5 rounded-lg border border-slate-700 bg-slate-900/70 px-3 py-1.5 font-mono text-2xs text-slate-400">
            <Radar size={12} className="text-emerald-dim" />
            thinking: {config?.thinking_level ?? "high"}
          </span>
          <span
            className={`flex items-center gap-1.5 rounded-lg border px-3 py-1.5 font-mono text-2xs ${
              config?.ai_available
                ? "border-emerald-dim/40 bg-emerald-glow/10 text-emerald-glow"
                : "border-amber-glow/35 bg-amber-glow/10 text-amber-glow"
            }`}
          >
            <Activity size={12} />
            {config?.ai_available ? "AI ONLINE" : "STATIC ANALYSIS MODE"}
          </span>
        </div>
      </header>

      {/* Ingestion */}
      <div className="mb-6 grid gap-4 lg:grid-cols-[1.15fr_1fr]">
        <section className="panel p-6">
          <div className="mb-4 flex items-center justify-between gap-3">
            <div>
              <h2 className="text-sm font-medium text-slate-200">Target ingestion</h2>
              <p className="mt-0.5 text-xs text-slate-500">
                Point AegisGemma at code, an API contract, or infrastructure config.
              </p>
            </div>
            <input
              value={target}
              onChange={(event) => setTarget(event.target.value)}
              aria-label="Target name"
              className="w-44 rounded-lg border border-slate-700 bg-slate-900/70 px-3 py-1.5 font-mono text-xs text-slate-200 outline-none transition-colors focus:border-emerald-dim/70"
            />
          </div>
          <Dropzone onFiles={handleFiles} disabled={running} />
          {error && (
            <p className="mt-3 rounded-lg border border-crimson-glow/30 bg-crimson-glow/10 px-3 py-2 text-xs text-crimson-glow">
              {error}
            </p>
          )}
        </section>

        <ThinkingTrace events={events} active={running} />
      </div>

      {/* Results */}
      <AnimatePresence mode="wait">
        {report ? (
          <motion.div
            key="results"
            initial={{ opacity: 0, y: 16 }}
            animate={{ opacity: 1, y: 0 }}
            exit={{ opacity: 0 }}
            transition={{ duration: 0.35, ease: [0.16, 1, 0.3, 1] }}
            className="space-y-4"
          >
            <div className="grid gap-4 lg:grid-cols-[320px_1fr]">
              <section className="panel p-6">
                <RiskDial score={report.risk_index} />
                <p className="mt-5 text-sm leading-relaxed text-slate-400">
                  {report.summary}
                </p>

                <div className="mt-5 space-y-1.5">
                  {Object.entries(severityCounts).map(([severity, count]) => (
                    <div
                      key={severity}
                      className="flex items-center justify-between rounded-lg border border-slate-700/60 bg-slate-900/50 px-3 py-1.5"
                    >
                      <span
                        className={`rounded border px-1.5 py-0.5 font-mono text-2xs severity-${severity}`}
                      >
                        {severity}
                      </span>
                      <span className="font-mono text-xs text-slate-400">{count}</span>
                    </div>
                  ))}
                </div>

                {report.target_summary && (
                  <dl className="mt-5 grid grid-cols-2 gap-2 border-t border-slate-700/60 pt-4 font-mono text-2xs">
                    <div>
                      <dt className="text-slate-600">Files</dt>
                      <dd className="mt-0.5 text-slate-300">
                        {report.target_summary.file_count}
                      </dd>
                    </div>
                    <div>
                      <dt className="text-slate-600">Lines</dt>
                      <dd className="mt-0.5 text-slate-300">
                        {report.target_summary.total_lines}
                      </dd>
                    </div>
                    <div className="col-span-2">
                      <dt className="text-slate-600">Languages</dt>
                      <dd className="mt-0.5 text-slate-300">
                        {Object.entries(report.target_summary.languages)
                          .map(([lang, count]) => `${lang} (${count})`)
                          .join(", ") || "—"}
                      </dd>
                    </div>
                  </dl>
                )}

                {report.engine_status === "degraded" && (
                  <p className="mt-4 rounded-lg border border-amber-glow/30 bg-amber-glow/10 px-3 py-2 text-2xs text-amber-glow">
                    AI provider unavailable — report generated from the deterministic
                    analysis layer.
                  </p>
                )}
              </section>

              <div className="space-y-4">
                <ThreatGraph
                  nodes={report.attack_surface}
                  findings={report.findings}
                  scanning={running}
                />

                {report.recommendations.length > 0 && (
                  <section className="panel p-5">
                    <h2 className="eyebrow mb-3">Remediation priorities</h2>
                    <ol className="space-y-2">
                      {report.recommendations.map((rec, index) => (
                        <li key={index} className="flex gap-3 text-sm text-slate-300">
                          <span className="shrink-0 font-mono text-2xs text-emerald-dim">
                            {String(index + 1).padStart(2, "0")}
                          </span>
                          <span>{rec}</span>
                        </li>
                      ))}
                    </ol>
                  </section>
                )}
              </div>
            </div>

            <VulnerabilityViewer findings={report.findings} />
          </motion.div>
        ) : (
          <motion.div
            key="empty"
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            exit={{ opacity: 0 }}
            className="panel px-6 py-16 text-center"
          >
            <div className="mx-auto flex w-fit items-center gap-2 font-mono text-2xs uppercase tracking-[0.22em] text-slate-600">
              <span className="size-1.5 animate-blink rounded-full bg-emerald-dim" />
              {running ? "Audit in progress" : "Awaiting target"}
            </div>
            <p className="mx-auto mt-4 max-w-[52ch] text-sm leading-relaxed text-slate-500">
              {running
                ? "AegisGemma is ingesting the target, mapping threat vectors and validating proof-of-concept steps."
                : "Upload a target to generate a CVSS v3.1 scored vulnerability report, a threat graph, non-destructive proof-of-concept steps and unified-diff remediation patches."}
            </p>
          </motion.div>
        )}
      </AnimatePresence>
    </main>
  );
}

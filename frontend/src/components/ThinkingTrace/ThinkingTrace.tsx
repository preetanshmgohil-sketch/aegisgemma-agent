"use client";

import { useEffect, useRef } from "react";
import { AnimatePresence, motion } from "framer-motion";
import { ChevronRight, Terminal } from "lucide-react";
import type { AuditEvent } from "@/lib/types";

const STAGES = [
  "AST Extraction",
  "Threat Vector Mapping",
  "PoC Validation",
  "Patch Generation",
];

interface ThinkingTraceProps {
  events: AuditEvent[];
  active: boolean;
}

export function ThinkingTrace({ events, active }: ThinkingTraceProps) {
  const scrollRef = useRef<HTMLDivElement>(null);
  const stageIndex = Math.max(
    0,
    STAGES.findIndex((stage) => events.some((e) => e.stage === stage && e.kind === "stage")),
  );

  useEffect(() => {
    const node = scrollRef.current;
    if (node) node.scrollTop = node.scrollHeight;
  }, [events.length]);

  const lines = events.filter(
    (event) => event.kind === "thought" || event.kind === "stage" || event.kind === "error",
  );

  return (
    <section className="panel overflow-hidden">
      <header className="flex items-center justify-between border-b border-slate-700/60 px-5 py-3.5">
        <div className="flex items-center gap-2.5">
          <Terminal size={15} className="text-emerald-dim" />
          <h2 className="text-sm font-medium text-slate-200">Reasoning trace</h2>
          {active && (
            <span className="flex items-center gap-1.5 font-mono text-2xs text-emerald-dim">
              <span className="size-1.5 animate-blink rounded-full bg-emerald-glow" />
              LIVE
            </span>
          )}
        </div>
        <span className="font-mono text-2xs text-slate-600">
          {lines.length} event{lines.length === 1 ? "" : "s"}
        </span>
      </header>

      {/* Pipeline stage rail */}
      <div className="border-b border-slate-700/60 bg-slate-900/40 px-5 py-3">
        <ol className="flex flex-wrap items-center gap-x-1 gap-y-2">
          {STAGES.map((stage, index) => {
            const done = events.some((e) => e.stage === stage && e.kind === "stage");
            const current = active && index === stageIndex && !done ? false : done;
            return (
              <li key={stage} className="flex items-center gap-1">
                <span
                  className={`flex items-center gap-1.5 rounded-md px-2 py-1 font-mono text-2xs transition-colors duration-200 ${
                    current
                      ? "bg-emerald-glow/12 text-emerald-glow"
                      : "text-slate-600"
                  }`}
                >
                  <span
                    className={`size-1.5 rounded-full ${
                      current ? "bg-emerald-glow" : "bg-slate-700"
                    }`}
                  />
                  {stage}
                </span>
                {index < STAGES.length - 1 && (
                  <ChevronRight size={11} className="text-slate-700" />
                )}
              </li>
            );
          })}
        </ol>
      </div>

      <div
        ref={scrollRef}
        className="relative h-72 overflow-y-auto bg-[#070a11]/90 px-5 py-4"
      >
        {/* Scanline glow overlay */}
        <div
          aria-hidden
          className="pointer-events-none absolute inset-x-0 top-0 h-16 bg-gradient-to-b from-emerald-glow/[0.055] to-transparent"
          style={{ animation: "scanline 3.4s linear infinite" }}
        />

        <div className="relative space-y-2.5">
          <AnimatePresence initial={false}>
            {lines.map((event, index) => (
              <motion.div
                key={`${event.stage}-${index}-${event.message.slice(0, 12)}`}
                initial={{ opacity: 0, x: -8 }}
                animate={{ opacity: 1, x: 0 }}
                transition={{ duration: 0.22, ease: [0.16, 1, 0.3, 1] }}
                className="flex gap-2.5"
              >
                <span
                  className={`mt-[3px] font-mono text-2xs ${
                    event.kind === "error"
                      ? "text-crimson-glow"
                      : event.kind === "stage"
                        ? "text-emerald-glow"
                        : "text-slate-600"
                  }`}
                >
                  {event.kind === "stage" ? "▸" : event.kind === "error" ? "✕" : "·"}
                </span>
                <div className="min-w-0">
                  {event.kind === "stage" && (
                    <p className="font-mono text-2xs uppercase tracking-widest text-emerald-glow">
                      {event.stage}
                    </p>
                  )}
                  <p
                    className={`whitespace-pre-wrap break-words font-mono text-xs leading-relaxed ${
                      event.kind === "stage" ? "text-slate-400" : "text-slate-400"
                    }`}
                  >
                    {event.message}
                  </p>
                </div>
              </motion.div>
            ))}
          </AnimatePresence>

          {lines.length === 0 && (
            <p className="font-mono text-xs text-slate-600">
              Waiting for the audit pipeline to start…
            </p>
          )}
        </div>
      </div>
    </section>
  );
}

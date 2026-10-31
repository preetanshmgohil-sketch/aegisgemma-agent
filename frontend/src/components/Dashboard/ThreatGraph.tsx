"use client";

import { motion } from "framer-motion";
import type { AttackSurfaceNode, Finding, Severity } from "@/lib/types";

interface ThreatGraphProps {
  nodes: AttackSurfaceNode[];
  findings: Finding[];
  scanning: boolean;
}

const KIND_COLOR: Record<string, string> = {
  entrypoint: "#00ff9d",
  service: "#7dd3fc",
  data: "#ffb020",
  dependency: "#c084fc",
  identity: "#ff3366",
  config: "#94a3b8",
};

function severityColor(severity: Severity | null) {
  switch (severity) {
    case "CRITICAL":
    case "HIGH":
      return "#ff3366";
    case "MEDIUM":
      return "#ffb020";
    case "LOW":
      return "#00ff9d";
    default:
      return "#3a4860";
  }
}

function Node({
  node,
  depth,
  scanning,
}: {
  node: AttackSurfaceNode;
  depth: number;
  scanning: boolean;
}) {
  const color = severityColor(node.severity) ?? KIND_COLOR[node.kind] ?? "#3a4860";

  return (
    <div style={{ marginLeft: depth === 0 ? 0 : 20 }}>
      <motion.div
        initial={{ opacity: 0, x: -10 }}
        animate={{ opacity: 1, x: 0 }}
        transition={{ duration: 0.28, ease: [0.16, 1, 0.3, 1] }}
        className="group relative flex items-center gap-2.5 rounded-lg border border-slate-700/70 bg-slate-900/70 px-3 py-2"
        style={{ borderLeftColor: color, borderLeftWidth: 2 }}
      >
        {scanning && (
          <span
            aria-hidden
            className="absolute inset-0 rounded-lg opacity-0"
            style={{
              boxShadow: `0 0 0 1px ${color}`,
              animation: "pulse-ring 2.4s cubic-bezier(0.16,1,0.3,1) infinite",
            }}
          />
        )}
        <span
          className="size-2 shrink-0 rounded-full"
          style={{ backgroundColor: color, boxShadow: `0 0 8px ${color}` }}
        />
        <span className="truncate text-xs text-slate-200">{node.label}</span>
        <span className="ml-auto shrink-0 font-mono text-2xs uppercase tracking-wider text-slate-600">
          {node.kind}
        </span>
      </motion.div>

      {node.children.length > 0 && (
        <div className="mt-1.5 space-y-1.5 border-l border-slate-700/60 pl-2.5">
          {node.children.map((child) => (
            <Node key={child.id} node={child} depth={depth + 1} scanning={scanning} />
          ))}
        </div>
      )}
    </div>
  );
}

export function ThreatGraph({ nodes, findings, scanning }: ThreatGraphProps) {
  // Fall back to a graph derived from the findings so the panel is never
  // empty when the model does not return an explicit attack surface.
  const derived: AttackSurfaceNode[] =
    nodes.length > 0
      ? nodes
      : [
          {
            id: "root",
            label: "Attack surface",
            kind: "service",
            severity: null,
            children: Array.from(new Set(findings.map((f) => f.location.file))).map(
              (file, index) => ({
                id: `file-${index}`,
                label: file,
                kind: "config" as const,
                severity:
                  (findings.find((f) => f.location.file === file)?.severity ?? null) as
                    | Severity
                    | null,
                children: [],
              }),
            ),
          },
        ];

  return (
    <section className="panel relative overflow-hidden">
      {scanning && (
        <div aria-hidden className="pointer-events-none absolute inset-0">
          <div
            className="absolute -left-1/4 top-0 h-full w-1/2"
            style={{
              background:
                "conic-gradient(from 0deg, transparent 0deg, rgba(0,255,157,0.07) 70deg, transparent 140deg)",
              animation: "radar-sweep 3.6s linear infinite",
            }}
          />
        </div>
      )}

      <header className="relative flex items-center justify-between border-b border-slate-700/60 px-5 py-3.5">
        <h2 className="text-sm font-medium text-slate-200">Attack surface</h2>
        <span className="font-mono text-2xs text-slate-600">
          {derived.length} root node{derived.length === 1 ? "" : "s"}
        </span>
      </header>

      <div className="relative space-y-2 p-5">
        {derived.map((node) => (
          <Node key={node.id} node={node} depth={0} scanning={scanning} />
        ))}
        {derived.length === 1 && derived[0].children.length === 0 && (
          <p className="py-6 text-center font-mono text-xs text-slate-600">
            No attack surface detected yet.
          </p>
        )}
      </div>
    </section>
  );
}

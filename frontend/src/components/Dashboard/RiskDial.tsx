"use client";

import { motion } from "framer-motion";

interface RiskDialProps {
  score: number;
  label?: string;
}

function toneFor(score: number) {
  if (score >= 9) return { stroke: "#ff3366", glow: "rgba(255,51,102,0.45)", text: "text-crimson-glow" };
  if (score >= 7) return { stroke: "#ff6b3d", glow: "rgba(255,107,61,0.4)", text: "text-crimson-glow" };
  if (score >= 4) return { stroke: "#ffb020", glow: "rgba(255,176,32,0.38)", text: "text-amber-glow" };
  if (score > 0) return { stroke: "#00ff9d", glow: "rgba(0,255,157,0.4)", text: "text-emerald-glow" };
  return { stroke: "#3a4860", glow: "rgba(58,72,96,0.3)", text: "text-slate-500" };
}

export function RiskDial({ score, label = "Aggregate risk index" }: RiskDialProps) {
  const radius = 78;
  const circumference = 2 * Math.PI * radius;
  const progress = Math.max(0, Math.min(100, score)) / 100;
  const offset = circumference * (1 - progress);
  const tone = toneFor(score);

  return (
    <div className="flex flex-col items-center">
      <div className="relative">
        {/* Pulsing outer ring */}
        {score > 0 && (
          <motion.div
            className="absolute inset-0 rounded-full"
            style={{ boxShadow: `0 0 42px -8px ${tone.glow}` }}
            animate={{ opacity: [0.35, 0.7, 0.35] }}
            transition={{ duration: 2.6, repeat: Infinity, ease: "easeInOut" }}
          />
        )}

        <svg width="200" height="200" viewBox="0 0 200 200" className="relative">
          <circle
            cx="100"
            cy="100"
            r={radius}
            fill="none"
            stroke="#141d2e"
            strokeWidth="12"
          />
          <circle
            cx="100"
            cy="100"
            r={radius}
            fill="none"
            stroke="#1c2739"
            strokeWidth="12"
            strokeDasharray="2 8"
            strokeLinecap="round"
          />
          <motion.circle
            cx="100"
            cy="100"
            r={radius}
            fill="none"
            stroke={tone.stroke}
            strokeWidth="12"
            strokeLinecap="round"
            strokeDasharray={circumference}
            initial={{ strokeDashoffset: circumference }}
            animate={{ strokeDashoffset: offset }}
            transition={{ duration: 1.1, ease: [0.16, 1, 0.3, 1] }}
            transform="rotate(-90 100 100)"
            style={{ filter: `drop-shadow(0 0 8px ${tone.glow})` }}
          />
          <text
            x="100"
            y="100"
            textAnchor="middle"
            dominantBaseline="central"
            className={`font-mono text-4xl font-semibold ${tone.text}`}
            style={{ fontFamily: "var(--font-mono)" }}
          >
            {score}
          </text>
          <text
            x="100"
            y="128"
            textAnchor="middle"
            className="font-mono text-2xs uppercase tracking-[0.2em] text-slate-500"
            style={{ fontFamily: "var(--font-mono)" }}
          >
            / 100
          </text>
        </svg>
      </div>

      <p className="eyebrow mt-4">{label}</p>
    </div>
  );
}

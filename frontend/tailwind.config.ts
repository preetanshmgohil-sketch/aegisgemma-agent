import type { Config } from "tailwindcss";

const config: Config = {
  content: [
    "./src/pages/**/*.{js,ts,jsx,tsx,mdx}",
    "./src/components/**/*.{js,ts,jsx,tsx,mdx}",
    "./src/app/**/*.{js,ts,jsx,tsx,mdx}",
  ],
  theme: {
    extend: {
      colors: {
        // Cyber-ops palette from the AegisGemma spec.
        void: "#090d16",
        slate: {
          950: "#070a11",
          900: "#0b111c",
          850: "#0f1624",
          800: "#141d2e",
          700: "#1c2739",
          600: "#28344a",
          500: "#3a4860",
        },
        emerald: {
          glow: "#00ff9d",
          dim: "#0bbf78",
        },
        crimson: {
          glow: "#ff3366",
          dim: "#c72852",
        },
        amber: {
          glow: "#ffb020",
        },
      },
      fontFamily: {
        sans: ["var(--font-sans)", "ui-sans-serif", "system-ui", "sans-serif"],
        mono: ["var(--font-mono)", "ui-monospace", "SFMono-Regular", "monospace"],
      },
      fontSize: {
        "2xs": ["0.6875rem", { lineHeight: "1rem" }],
      },
      spacing: {
        "4.5": "1.125rem",
        "13": "3.25rem",
        "18": "4.5rem",
      },
      borderRadius: {
        "4xl": "2rem",
      },
      boxShadow: {
        "glow-emerald": "0 0 0 1px rgba(0,255,157,0.35), 0 0 24px -6px rgba(0,255,157,0.45)",
        "glow-crimson": "0 0 0 1px rgba(255,51,102,0.35), 0 0 24px -6px rgba(255,51,102,0.45)",
        "panel": "0 24px 64px -32px rgba(0,0,0,0.9)",
      },
      keyframes: {
        "radar-sweep": {
          "0%": { transform: "rotate(0deg)" },
          "100%": { transform: "rotate(360deg)" },
        },
        "scanline": {
          "0%": { transform: "translateY(-100%)" },
          "100%": { transform: "translateY(400%)" },
        },
        "pulse-ring": {
          "0%": { opacity: "0.5", transform: "scale(0.9)" },
          "70%": { opacity: "0", transform: "scale(1.6)" },
          "100%": { opacity: "0", transform: "scale(1.6)" },
        },
        "border-trace": {
          "0%": { transform: "translateX(-100%)" },
          "100%": { transform: "translateX(100%)" },
        },
        "blink": {
          "0%, 45%": { opacity: "1" },
          "50%, 95%": { opacity: "0.15" },
          "100%": { opacity: "1" },
        },
      },
      animation: {
        "radar-sweep": "radar-sweep 3.6s linear infinite",
        "scanline": "scanline 3.2s linear infinite",
        "pulse-ring": "pulse-ring 2.4s cubic-bezier(0.16,1,0.3,1) infinite",
        "border-trace": "border-trace 1.8s cubic-bezier(0.16,1,0.3,1) infinite",
        blink: "blink 1.1s steps(1) infinite",
      },
    },
  },
  plugins: [],
};

export default config;

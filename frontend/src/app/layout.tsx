import type { Metadata } from "next";
import "@/styles/globals.css";

export const metadata: Metadata = {
  title: "AegisGemma — Autonomous Security Audit Agent",
  description:
    "Open-source red-teaming and security sandbox agent powered by Gemma 4 reasoning. Static analysis, threat modeling, non-destructive PoC synthesis and remediation patches.",
};

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <html lang="en">
      <body className="min-h-screen">{children}</body>
    </html>
  );
}

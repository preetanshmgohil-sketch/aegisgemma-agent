import type { AuditEvent, AuditReport, RuntimeConfig } from "./types";

export const API_URL =
  process.env.NEXT_PUBLIC_API_URL?.replace(/\/$/, "") ?? "http://localhost:8000";

export interface StartAuditResponse {
  id: string;
  status: string;
  target: string;
  file_count: number;
  ws_url: string;
}

/** Human-readable message for a network-level failure. */
export const BACKEND_UNREACHABLE =
  "Cannot reach the AegisGemma backend at " +
  `${API_URL}. Start it with: cd backend && uvicorn app.main:app --port 8000`;

/** POST the selected files and kick off an audit. */
export async function startAudit(
  files: File[],
  target: string,
): Promise<StartAuditResponse> {
  const form = new FormData();
  form.append("target", target);
  for (const file of files) {
    form.append("files", file, file.name);
  }

  let response: Response;
  try {
    response = await fetch(`${API_URL}/api/v1/audits`, {
      method: "POST",
      body: form,
    });
  } catch {
    throw new Error(BACKEND_UNREACHABLE);
  }

  if (!response.ok) {
    const detail = await response.text();
    throw new Error(detail || `Audit request failed (${response.status})`);
  }
  return (await response.json()) as StartAuditResponse;
}

/** Fetch the finished report for a session. */
export async function fetchReport(id: string): Promise<AuditReport> {
  const response = await fetch(`${API_URL}/api/v1/audits/${id}/report`);
  if (!response.ok) {
    throw new Error(`Could not load report (${response.status})`);
  }
  return (await response.json()) as AuditReport;
}

/** Fetch backend runtime configuration (provider, model, thinking level). */
export async function fetchConfig(): Promise<RuntimeConfig | null> {
  try {
    const response = await fetch(`${API_URL}/api/v1/config`);
    if (!response.ok) return null;
    return (await response.json()) as RuntimeConfig;
  } catch {
    return null;
  }
}

/** Open the live event stream for a session. */
export function openAuditStream(
  id: string,
  onEvent: (event: AuditEvent) => void,
  onClose?: () => void,
): WebSocket {
  const wsUrl = `${API_URL.replace(/^http/, "ws")}/api/v1/audits/${id}/stream`;
  const socket = new WebSocket(wsUrl);
  socket.onmessage = (message) => {
    try {
      onEvent(JSON.parse(message.data) as AuditEvent);
    } catch {
      // Ignore malformed frames rather than tearing down the stream.
    }
  };
  socket.onclose = () => onClose?.();
  socket.onerror = () => onClose?.();
  return socket;
}

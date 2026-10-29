// Console API client. Same origin; the session cookie is HttpOnly, the CSRF token lives in memory only.

let csrf = "";

export class ApiError extends Error {
  constructor(public status: number, message: string) {
    super(message);
  }
}

async function call<T>(method: string, path: string, body?: unknown): Promise<T> {
  const headers: Record<string, string> = {};
  if (body !== undefined) headers["Content-Type"] = "application/json";
  if (method !== "GET") headers["X-CSRF-Token"] = csrf;
  const r = await fetch(path, {
    method,
    headers,
    credentials: "same-origin",
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  const data = await r.json().catch(() => ({}));
  if (!r.ok) {
    const d = (data as { detail?: unknown; error?: unknown }).detail ?? (data as { error?: unknown }).error;
    throw new ApiError(r.status, typeof d === "string" ? d : `HTTP ${r.status}`);
  }
  return data as T;
}

export async function login(token: string): Promise<void> {
  csrf = (await call<{ csrf: string }>("POST", "/api/session", { token })).csrf;
}

export async function resume(): Promise<boolean> {
  try {
    csrf = (await call<{ csrf: string }>("GET", "/api/session")).csrf;
    return true;
  } catch {
    return false;
  }
}

export async function logout(): Promise<void> {
  await call("DELETE", "/api/session").catch(() => undefined);
  csrf = "";
}

// ---------- types (mirror console/server.py) ----------
export type Mode = "vuln" | "hardened";

export interface TargetStatus {
  target: "a" | "b";
  name: string;
  db: string;
  url: string;
  proxy: string;
  mode: Mode;
  files: { inventory: string | null; plan: string | null; apply_report: string | null };
  summary: {
    pii_columns?: number;
    columns?: number;
    recall_content_only?: number;
    precision_content_only?: number;
    dump_found?: number;
    dump_sampled?: number;
    controls_tested?: number;
    controls_total?: number;
  };
  next_step: "scan" | "plan" | "apply" | null;
}

export interface RedcheckResult {
  file: string;
  valid: boolean;
  target?: string;
  mode?: string;
  scoreboard?: Record<string, number>;
  findings?: number;
  failed?: number;
  modified_at?: string;
}

export interface Status {
  targets: TargetStatus[];
  services: Record<string, boolean>;
  operation: { op: string; target?: string | null; source?: string; pid?: number; since?: string } | null;
  redcheck: { available: boolean; results: RedcheckResult[] };
  generated_at: string;
}

export const getStatus = () => call<Status>("GET", "/api/status");

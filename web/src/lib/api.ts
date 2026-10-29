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

// ---------- out/ files ----------
export type Target = "a" | "b";

export interface Finding {
  table: string;
  column: string;
  detected_class: string;
  pii_type: string;
  confidence: number;
  why: string[];
  sample_masked: string;
}

export interface Protect {
  tp: number;
  fp: number;
  fn: number;
  precision: number;
  recall: number;
  f1: number;
}

export interface ModeMetrics {
  columns_scored: number;
  protect: Protect;
  class_accuracy: number;
  confusion: Record<string, Record<string, number>>;
  mismatches: { table: string; column: string; reference: string; detected: string }[];
  traps_caught: Record<string, boolean | null>;
}

export interface Inventory {
  target: string;
  source: string;
  generated_at: string;
  rows_sampled: Record<string, number>;
  findings: Finding[];
  metrics?: { reference: string; with_column_names: ModeMetrics; content_only: ModeMetrics };
  notes?: string[];
}

export interface PlanColumn {
  table: string;
  column: string;
  field: string;
  detected_class: string;
  pii_type: string;
  controls: string[];
  reason: string;
  limitations: string[];
  needs_human_review: boolean;
  review_note: string | null;
  visible_to: Record<string, string> | null;
}

export interface Plan {
  target: string;
  generated_at: string;
  access_matrix: { problems: string[] };
  controls_catalog: Record<string, { what: string; limits: string[] }>;
  columns: PlanColumn[];
  by_control: Record<string, string[]>;
  needs_human_review: string[];
}

export interface ApplyReport {
  target: string;
  database: string;
  applied_at: string;
  mode: string;
  controls: { control: string; status: string; evidence: string }[];
  steps: { step: string; [k: string]: unknown }[];
  verification: Record<string, unknown>;
  needs_human_review: string[];
  rerun?: { at: string; result: string };
}

export const getOut = <T,>(kind: "inventory" | "plan" | "apply_report" | "rollback" | "evidence", t: Target) =>
  call<T>("GET", `/api/out/${kind}_${t}`);

// ---------- access matrix ----------
export interface Matrix {
  roles: Record<string, string>;
  levels: Record<string, string>;
  fields: Record<string, Record<string, string>>;
  problems: string[];
}

export const getMatrix = () => call<Matrix>("GET", "/api/matrix");
export const putMatrix = (fields: Matrix["fields"]) =>
  call<{ changed: string[]; needs: string }>("PUT", "/api/matrix", { fields });

// ---------- jobs ----------
export type Op = "scan" | "plan" | "apply" | "rollback" | "reset" | "evidence";

export interface JobEvent {
  t?: number;
  step: string;
  state?: string;
  [k: string]: unknown;
}

export interface Job {
  id: string;
  op: Op;
  target: Target | null;
  state: "running" | "done" | "failed";
  error: string | null;
  result: Record<string, unknown> | null;
  events: JobEvent[];
}

export const startJob = (op: Op, target: Target | null, confirm?: string) =>
  call<Job>("POST", "/api/jobs", { op, target, confirm });
export const getJob = (id: string) => call<Job>("GET", `/api/jobs/${id}`);

/** Stream progress events (SSE) of a job; resolves when the job ends. EventSource sends the session cookie. */
export function watchJob(id: string, onEvent: (e: JobEvent) => void): Promise<void> {
  return new Promise((resolve) => {
    const es = new EventSource(`/api/jobs/${id}/events`);
    es.onmessage = (m) => {
      const e = JSON.parse(m.data) as JobEvent;
      onEvent(e);
      if (e.step === "end") {
        es.close();
        resolve();
      }
    };
    es.onerror = () => {
      es.close();
      resolve();
    };
  });
}

// ---------- evidence (out/evidence_<t>.json, written by `shield evidence`) ----------
export type CellKind = "none" | "PLAINTEXT" | "envelope" | "masked" | "token" | "other" | "error" | "no-row";

export interface Evidence {
  target: string;
  database: string;
  generated_at: string;
  fields: string[];
  a_dump_without_keys: {
    label: string;
    row: string;
    columns: { field: string; table: string; column: string; stored_column: string; row_id: number; kind: CellKind; stored: string | null; leak: boolean; original_masked: string | null }[];
    apply_report_sample: { sample_values?: number; found_in_dump?: number };
  };
  b_dump_with_keys: {
    label: string;
    shield_keys_rows: number;
    sample: { key_id: string; name: string; purpose: string; wrapped: string }[];
    attempt?: { column: string; wrapped_dek_as_key?: string; kms_with_wrong_token?: string; kms_authorised?: string; error?: string };
    residual_risk_written: string[];
  };
  c_legitimate_users: {
    label: string;
    via: string;
    member_id_for_self_role: number;
    roles: Record<string, { readable: number; plaintext_cells: number; cells: Record<string, { kind: CellKind; value: string | null }> }>;
  };
  plaintext_cells_total: number;
}

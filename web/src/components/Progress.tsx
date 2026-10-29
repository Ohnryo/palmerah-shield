import { Check, Loader2, X } from "lucide-react";
import type { JobEvent } from "../lib/api";

const NAMES: Record<string, string> = {
  classify: "Klasifikasi kolom",
  backup: "Backup terenkripsi",
  migrate: "Migrasi kolom",
  views_and_roles: "VIEW dan role per peran",
  verify: "Verifikasi",
  restore_backup: "Pulihkan dari backup",
  cleanup: "Bersihkan sisa apply",
  seed: "Muat data seed",
};

function detail(e: JobEvent): string {
  const { step, t, state, ...rest } = e;
  void step; void t; void state;
  return Object.entries(rest).map(([k, v]) => `${k}=${String(v)}`).join(" · ");
}

/** Live step list from SSE events (step names and counts only; the core never sends data values). */
export function Progress({ events, running, error }: { events: JobEvent[]; running: boolean; error: string }) {
  if (!events.length && !running && !error) return null;
  const steps = events.filter((e) => e.step !== "end");
  return (
    <div className="mt-4 rounded-lg border border-border bg-surface-2 p-3 text-sm" role="status" aria-live="polite">
      <ol className="space-y-1">
        {steps.map((e, i) => {
          const last = i === steps.length - 1;
          return (
            <li key={i} className="flex items-center gap-2">
              {last && running ? <Loader2 className="size-4 animate-spin text-warn" aria-hidden /> : <Check className="size-4 text-safe" aria-hidden />}
              <span className="font-medium">{NAMES[e.step] ?? e.step}</span>
              <span className="truncate font-mono text-xs text-muted">{detail(e)}</span>
            </li>
          );
        })}
        {running && !steps.length && (
          <li className="flex items-center gap-2 text-muted"><Loader2 className="size-4 animate-spin" aria-hidden />Memulai…</li>
        )}
      </ol>
      {error && (
        <p role="alert" className="mt-2 flex items-start gap-2 text-leak"><X className="mt-0.5 size-4 shrink-0" aria-hidden />{error}</p>
      )}
    </div>
  );
}

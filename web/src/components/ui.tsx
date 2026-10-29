import type { ReactNode } from "react";

export function Card({ title, icon, children, actions, className = "" }: {
  title?: ReactNode;
  icon?: ReactNode;
  children: ReactNode;
  actions?: ReactNode;
  className?: string;
}) {
  return (
    <section className={`rounded-xl border border-border bg-surface p-5 ${className}`}>
      {title && (
        <header className="mb-4 flex items-center justify-between gap-3">
          <h2 className="flex items-center gap-2 text-base font-semibold">
            {icon}
            {title}
          </h2>
          {actions}
        </header>
      )}
      {children}
    </section>
  );
}

export type Tone = "leak" | "safe" | "warn" | "planned" | "neutral";

const TONES: Record<Tone, string> = {
  leak: "bg-leak-bg text-leak border-leak/40",
  safe: "bg-safe-bg text-safe border-safe/40",
  warn: "bg-warn-bg text-warn border-warn/40",
  planned: "bg-planned-bg text-planned border-planned/40",
  neutral: "bg-surface-2 text-muted border-border",
};

export function Badge({ tone, children }: { tone: Tone; children: ReactNode }) {
  return (
    <span className={`inline-flex items-center gap-1 rounded-md border px-2 py-0.5 text-xs font-semibold uppercase tracking-wide ${TONES[tone]}`}>
      {children}
    </span>
  );
}

/** Evidence labels from the contract. */
export function Evidence({ status }: { status: "IMPLEMENTED" | "TESTED" | "PLANNED" }) {
  const tone: Tone = status === "TESTED" ? "safe" : status === "IMPLEMENTED" ? "warn" : "planned";
  return <Badge tone={tone}>[{status}]</Badge>;
}

export function Stat({ label, value, sub, tone = "neutral" }: { label: string; value: ReactNode; sub?: ReactNode; tone?: Tone }) {
  const color = { leak: "text-leak", safe: "text-safe", warn: "text-warn", planned: "text-planned", neutral: "text-text" }[tone];
  return (
    <div className="rounded-lg bg-surface-2 p-3">
      <div className="text-xs text-muted">{label}</div>
      <div className={`mt-1 text-2xl font-bold tabular-nums ${color}`}>{value}</div>
      {sub && <div className="mt-0.5 text-xs text-muted">{sub}</div>}
    </div>
  );
}

export function Empty({ children }: { children: ReactNode }) {
  return <div className="rounded-lg border border-dashed border-border p-6 text-center text-sm text-muted">{children}</div>;
}

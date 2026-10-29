import { useSearchParams } from "react-router";
import type { Target } from "../lib/api";

/** Target A / B selector kept in the URL (?t=a|b) so a page can be linked and survives reload. */
export function useTarget(): [Target, (t: Target) => void] {
  const [params, setParams] = useSearchParams();
  const t = params.get("t") === "b" ? "b" : "a";
  return [t, (n) => setParams({ t: n }, { replace: true })];
}

export function TargetTabs({ value, onChange }: { value: Target; onChange: (t: Target) => void }) {
  const items: { t: Target; label: string }[] = [
    { t: "a", label: "Website A · web-legacy (MySQL)" },
    { t: "b", label: "Website B · web-modern (PostgreSQL)" },
  ];
  return (
    <div role="tablist" aria-label="Target" className="inline-flex rounded-lg border border-border bg-surface p-1">
      {items.map((i) => (
        <button
          key={i.t}
          role="tab"
          type="button"
          aria-selected={value === i.t}
          onClick={() => onChange(i.t)}
          className={`rounded-md px-3 py-1.5 text-sm ${value === i.t ? "bg-surface-2 font-semibold text-text" : "text-muted hover:text-text"}`}
        >
          {i.label}
        </button>
      ))}
    </div>
  );
}

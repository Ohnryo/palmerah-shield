import { Fragment, useEffect, useMemo, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { ClipboardList, Loader2, Save } from "lucide-react";
import { ApiError, getMatrix, getOut, putMatrix, type Matrix, type Plan as PlanData } from "../lib/api";
import { useJob } from "../lib/useJob";
import { Badge, Card, Empty, type Tone } from "../components/ui";
import { TargetTabs, useTarget } from "../components/TargetTabs";
import { Progress } from "../components/Progress";
import { CLASS_LABEL, classTone } from "./Scan";

const CONTROL_TONE: Record<string, Tone> = { "encrypt-AEAD": "safe", tokenize: "safe", "blind-index": "safe", mask: "warn", "view-only": "neutral", drop: "leak" };

export function Plan() {
  const [target, setTarget] = useTarget();
  const job = useJob();
  const q = useQuery({
    queryKey: ["out", "plan", target],
    queryFn: () => getOut<PlanData>("plan", target),
    retry: (n, e) => !(e instanceof ApiError && e.status === 404) && n < 2,
  });
  const plan = q.data;
  const missing = q.error instanceof ApiError && q.error.status === 404;
  return (
    <div className="mx-auto max-w-7xl space-y-6">
      <header className="flex flex-wrap items-end justify-between gap-3">
        <div>
          <h1 className="text-2xl font-bold">Rencana</h1>
          <p className="text-sm text-muted">Kontrol per kolom dengan alasan dan batasnya, dan siapa boleh melihat apa. Belum mengubah database.</p>
        </div>
        <TargetTabs value={target} onChange={setTarget} />
      </header>

      <Card>
        <button
          type="button"
          disabled={job.running}
          onClick={() => job.run("plan", target)}
          className="inline-flex items-center gap-2 rounded-lg bg-accent px-4 py-2 text-sm font-semibold text-bg disabled:opacity-50"
        >
          {job.running ? <Loader2 className="size-4 animate-spin" aria-hidden /> : <ClipboardList className="size-4" aria-hidden />}
          {plan ? "Buat ulang rencana" : "Buat rencana"} website {target.toUpperCase()}
        </button>
        <span className="ml-3 text-xs text-muted">memakai hasil scan terakhir; bila belum ada, scan dijalankan dulu</span>
        <Progress events={job.events} running={job.running} error={job.error} />
      </Card>

      {q.isPending && <p className="text-muted">Memuat rencana…</p>}
      {missing && <Empty>Belum ada rencana untuk website {target.toUpperCase()}.</Empty>}
      {q.isError && !missing && <p role="alert" className="text-leak">{q.error.message}</p>}
      {plan && <PlanView plan={plan} />}
      <MatrixEditor />
    </div>
  );
}

function PlanView({ plan }: { plan: PlanData }) {
  const [open, setOpen] = useState<string | null>(null);
  const cols = plan.columns.filter((c) => c.controls.length > 0);
  const counts = Object.entries(plan.by_control).filter(([, v]) => v.length > 0);
  return (
    <>
      <Card title="Ringkasan kontrol">
        <ul className="flex flex-wrap gap-3">
          {counts.map(([k, v]) => (
            <li key={k} className="rounded-lg bg-surface-2 px-4 py-2">
              <Badge tone={CONTROL_TONE[k] ?? "neutral"}>{k}</Badge>
              <div className="mt-1 text-2xl font-bold tabular-nums">{v.length} <span className="text-sm font-normal text-muted">kolom</span></div>
            </li>
          ))}
        </ul>
        {plan.access_matrix.problems.length > 0 && (
          <p role="alert" className="mt-3 text-sm text-leak">Matriks akses bermasalah: {plan.access_matrix.problems.join("; ")}</p>
        )}
      </Card>

      <Card title={`Kontrol per kolom (${cols.length})`} actions={<span className="text-xs text-muted">klik baris untuk alasan dan batas</span>}>
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-border text-left text-xs text-muted">
                {["Kolom", "Kelas", "Kontrol", "Review"].map((h) => <th key={h} scope="col" className="px-2 py-2 font-medium">{h}</th>)}
              </tr>
            </thead>
            <tbody>
              {cols.map((c) => {
                const id = `${c.table}.${c.column}`;
                const isOpen = open === id;
                return (
                  <Fragment key={id}>
                    <tr className="cursor-pointer border-b border-border/60 hover:bg-surface-2" onClick={() => setOpen(isOpen ? null : id)}>
                      <td className="px-2 py-2 font-mono text-xs">
                        <button type="button" aria-expanded={isOpen} className="text-left" onClick={(e) => { e.stopPropagation(); setOpen(isOpen ? null : id); }}>
                          {c.table}.<strong>{c.column}</strong>
                        </button>
                      </td>
                      <td className="px-2 py-2"><Badge tone={classTone(c.detected_class)}>{CLASS_LABEL[c.detected_class] ?? c.detected_class}</Badge></td>
                      <td className="px-2 py-2"><div className="flex flex-wrap gap-1">{c.controls.map((k) => <Badge key={k} tone={CONTROL_TONE[k] ?? "neutral"}>{k}</Badge>)}</div></td>
                      <td className="px-2 py-2">{c.needs_human_review && <Badge tone="warn">needs human review</Badge>}</td>
                    </tr>
                    {isOpen && (
                      <tr className="border-b border-border/60 bg-surface-2">
                        <td colSpan={4} className="px-4 py-3 text-sm">
                          <p><strong>Alasan:</strong> {c.reason}</p>
                          {c.limitations.length > 0 && (
                            <>
                              <p className="mt-2 font-semibold">Batas (yang tidak dilindungi kontrol ini):</p>
                              <ul className="list-disc pl-5 text-muted">{c.limitations.map((l) => <li key={l}>{l}</li>)}</ul>
                            </>
                          )}
                          {c.review_note && <p className="mt-2 text-warn">{c.review_note}</p>}
                          {c.visible_to && (
                            <p className="mt-2 text-xs text-muted">
                              Terlihat: {Object.entries(c.visible_to).filter(([, v]) => v !== "none").map(([r, v]) => `${r}:${v}`).join(" · ") || "tidak oleh peran mana pun"}
                            </p>
                          )}
                        </td>
                      </tr>
                    )}
                  </Fragment>
                );
              })}
            </tbody>
          </table>
        </div>
      </Card>

      {plan.needs_human_review.length > 0 && (
        <Card title="Perlu keputusan manusia" actions={<Badge tone="warn">{plan.needs_human_review.length}</Badge>}>
          <ul className="list-disc space-y-1 pl-5 text-sm">{plan.needs_human_review.map((n) => <li key={n}>{n}</li>)}</ul>
        </Card>
      )}
    </>
  );
}

const LEVEL_TONE: Record<string, string> = {
  full: "text-safe", masked: "text-warn", self: "text-accent", none: "text-muted",
};

function MatrixEditor() {
  const qc = useQueryClient();
  const q = useQuery({ queryKey: ["matrix"], queryFn: getMatrix, staleTime: Infinity, refetchOnWindowFocus: false });
  const [draft, setDraft] = useState<Matrix["fields"]>({});
  useEffect(() => { if (q.data) setDraft(q.data.fields); }, [q.data]);
  const roles = q.data ? Object.keys(q.data.roles) : [];
  const dirty = useMemo(() => Object.keys(draft).filter((f) => JSON.stringify(draft[f]) !== JSON.stringify(q.data?.fields[f])), [draft, q.data]);
  const save = useMutation({
    mutationFn: () => putMatrix(Object.fromEntries(dirty.map((f) => [f, draft[f]]))),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["matrix"] }),
  });
  if (q.isPending) return null;
  if (q.isError) return <p role="alert" className="text-leak">{q.error.message}</p>;
  return (
    <Card title="Matriks akses (peran × field)" actions={
      <button type="button" disabled={!dirty.length || save.isPending} onClick={() => save.mutate()}
        className="inline-flex items-center gap-2 rounded-lg bg-accent px-3 py-1.5 text-sm font-semibold text-bg disabled:opacity-40">
        <Save className="size-4" aria-hidden />Simpan{dirty.length ? ` (${dirty.length} field)` : ""}
      </button>}>
      <p className="mb-3 text-xs text-muted">
        Berkas <code className="font-mono">access_matrix.json</code> dimiliki tim. Perubahan baru berlaku sesudah <strong>rencana dan terapkan diulang</strong> (VIEW per peran dibuat ulang). <code className="font-mono">public</code> hanya boleh full atau none.
      </p>
      {save.isError && <p role="alert" className="mb-2 text-sm text-leak">{save.error.message}</p>}
      {save.isSuccess && <p role="status" className="mb-2 text-sm text-safe">Tersimpan. {save.data.needs}</p>}
      <div className="overflow-x-auto">
        <table className="w-full text-sm">
          <thead>
            <tr className="border-b border-border text-left text-xs text-muted">
              <th scope="col" className="px-2 py-2 font-medium">Field</th>
              {roles.map((r) => <th key={r} scope="col" title={q.data.roles[r]} className="px-1 py-2 text-center font-medium">{r}</th>)}
            </tr>
          </thead>
          <tbody>
            {Object.keys(draft).map((f) => (
              <tr key={f} className={`border-b border-border/60 ${dirty.includes(f) ? "bg-warn-bg" : ""}`}>
                <th scope="row" className="px-2 py-1 text-left font-mono text-xs font-medium">{f}</th>
                {roles.map((r) => (
                  <td key={r} className="px-1 py-1 text-center">
                    <select
                      aria-label={`${f} untuk ${r}`}
                      value={draft[f][r]}
                      onChange={(e) => setDraft({ ...draft, [f]: { ...draft[f], [r]: e.target.value } })}
                      className={`rounded border border-border bg-surface-2 px-1 py-0.5 text-xs font-semibold ${LEVEL_TONE[draft[f][r]]}`}
                    >
                      {Object.keys(q.data.levels).filter((l) => r === "public" ? l === "none" || l === "full" : true).map((l) => <option key={l} value={l}>{l}</option>)}
                    </select>
                  </td>
                ))}
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </Card>
  );
}

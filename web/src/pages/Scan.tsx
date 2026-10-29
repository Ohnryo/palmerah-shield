import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { AlertTriangle, Loader2, ScanSearch } from "lucide-react";
import { ApiError, getOut, type Finding, type Inventory, type ModeMetrics } from "../lib/api";
import { useJob } from "../lib/useJob";
import { Badge, Card, Empty, Stat, type Tone } from "../components/ui";
import { TargetTabs, useTarget } from "../components/TargetTabs";
import { Progress } from "../components/Progress";

export const CLASS_LABEL: Record<string, string> = {
  SANGAT_TINGGI: "Sangat tinggi",
  TINGGI_KONTAK: "Tinggi · kontak",
  TINGGI_SOSIAL: "Tinggi · sosial",
  QUASI_ID: "Quasi-ID",
  INTERNAL: "Internal",
  PUBLIK: "Publik",
  KREDENSIAL: "Kredensial",
  NON_PII: "Bukan PII",
};

export function classTone(c: string): Tone {
  if (c === "SANGAT_TINGGI") return "leak";
  if (c.startsWith("TINGGI") || c === "KREDENSIAL") return "warn";
  if (c === "QUASI_ID") return "planned";
  return "neutral";
}

const ORDER = Object.keys(CLASS_LABEL);

export function Scan() {
  const [target, setTarget] = useTarget();
  const job = useJob();
  const q = useQuery({
    queryKey: ["out", "inventory", target],
    queryFn: () => getOut<Inventory>("inventory", target),
    retry: (n, e) => !(e instanceof ApiError && e.status === 404) && n < 2,
  });
  const inv = q.data;
  const missing = q.error instanceof ApiError && q.error.status === 404;

  return (
    <div className="mx-auto max-w-7xl space-y-6">
      <header className="flex flex-wrap items-end justify-between gap-3">
        <div>
          <h1 className="text-2xl font-bold">Scan</h1>
          <p className="text-sm text-muted">Mencari PII berdasarkan isi kolom, lalu membandingkannya dengan klasifikasi acuan kontrak.</p>
        </div>
        <TargetTabs value={target} onChange={setTarget} />
      </header>

      <Card>
        <div className="flex flex-wrap items-center gap-3">
          <button
            type="button"
            disabled={job.running}
            onClick={() => job.run("scan", target)}
            className="inline-flex items-center gap-2 rounded-lg bg-accent px-4 py-2 text-sm font-semibold text-bg disabled:opacity-50"
          >
            {job.running ? <Loader2 className="size-4 animate-spin" aria-hidden /> : <ScanSearch className="size-4" aria-hidden />}
            {inv ? "Scan ulang" : "Jalankan scan"} website {target.toUpperCase()}
          </button>
          {inv && <span className="text-xs text-muted">hasil terakhir {new Date(inv.generated_at).toLocaleString("id-ID")} · sumber {inv.source}</span>}
        </div>
        <Progress events={job.events} running={job.running} error={job.error} />
        <p className="mt-3 text-xs text-muted">Unggah dump <code className="font-mono">.sql</code> lewat konsol: <strong>[PLANNED]</strong>; sementara pakai <code className="font-mono">shield scan --dump FILE</code>.</p>
      </Card>

      {q.isPending && <p className="text-muted">Memuat hasil…</p>}
      {missing && <Empty>Belum ada hasil scan untuk website {target.toUpperCase()}. Jalankan scan di atas.</Empty>}
      {q.isError && !missing && <p role="alert" className="text-leak">{q.error.message}</p>}
      {inv && <Result inv={inv} />}
    </div>
  );
}

function Result({ inv }: { inv: Inventory }) {
  const traps = inv.metrics?.content_only.traps_caught ?? {};
  return (
    <>
      {inv.metrics && <Metrics m={inv.metrics} />}
      {Object.keys(traps).length > 0 && <Traps inv={inv} traps={traps} />}
      <Findings findings={inv.findings} />
      {inv.metrics && <Confusion m={inv.metrics.content_only} />}
      {inv.notes && inv.notes.length > 0 && (
        <ul className="list-disc space-y-1 pl-5 text-xs text-muted">
          {inv.notes.map((n) => <li key={n}>{n}</li>)}
        </ul>
      )}
    </>
  );
}

function Metrics({ m }: { m: NonNullable<Inventory["metrics"]> }) {
  const rows: [string, ModeMetrics][] = [
    ["Nama kolom dipakai", m.with_column_names],
    ["Nama kolom diabaikan (hanya isi)", m.content_only],
  ];
  return (
    <Card title="Presisi dan recall terhadap acuan kontrak" actions={<span className="text-xs text-muted">acuan: {m.reference} · keputusan "harus dilindungi"</span>}>
      <div className="grid gap-4 lg:grid-cols-2">
        {rows.map(([label, x]) => (
          <div key={label}>
            <h3 className="mb-2 text-sm font-semibold">{label}</h3>
            <div className="grid grid-cols-2 gap-3 sm:grid-cols-4">
              <Stat label="Presisi" value={x.protect.precision.toFixed(2)} tone={x.protect.precision >= 0.95 ? "safe" : "warn"} />
              <Stat label="Recall" value={x.protect.recall.toFixed(2)} tone={x.protect.recall >= 0.95 ? "safe" : "warn"} />
              <Stat label="F1" value={x.protect.f1.toFixed(2)} />
              <Stat label="Akurasi kelas" value={x.class_accuracy.toFixed(2)} sub={`${x.columns_scored} kolom`} />
            </div>
            <p className="mt-2 text-xs text-muted">TP {x.protect.tp} · FP {x.protect.fp} · FN {x.protect.fn}</p>
          </div>
        ))}
      </div>
    </Card>
  );
}

function Traps({ inv, traps }: { inv: Inventory; traps: Record<string, boolean | null> }) {
  return (
    <Card title="Jebakan detektor" icon={<AlertTriangle className="size-5 text-warn" aria-hidden />}
      actions={<span className="text-xs text-muted">nama kolom menyesatkan, isi sensitif — tertangkap tanpa memakai nama kolom</span>}>
      <ul className="grid gap-3 lg:grid-cols-2">
        {Object.entries(traps).map(([k, caught]) => {
          const [table, column] = k.split(".");
          const f = inv.findings.find((x) => x.table === table && x.column === column);
          return (
            <li key={k} className="rounded-lg border border-border bg-surface-2 p-3">
              <div className="mb-1 flex items-center justify-between gap-2">
                <code className="font-mono text-sm">{k}</code>
                <Badge tone={caught ? "safe" : "leak"}>{caught ? "tertangkap" : "lolos"}</Badge>
              </div>
              {f && (
                <>
                  <p className="text-sm">Terdeteksi sebagai <strong>{f.pii_type}</strong> ({CLASS_LABEL[f.detected_class]}), yakin {(f.confidence * 100).toFixed(0)}%</p>
                  <p className="mt-1 font-mono text-xs text-muted">contoh: {f.sample_masked}</p>
                  <ul className="mt-1 list-disc pl-4 text-xs text-muted">{f.why.map((w) => <li key={w}>{w}</li>)}</ul>
                </>
              )}
            </li>
          );
        })}
      </ul>
    </Card>
  );
}

function Findings({ findings }: { findings: Finding[] }) {
  const [filter, setFilter] = useState("PII");
  const shown = findings
    .filter((f) => (filter === "PII" ? !["NON_PII", "PUBLIK"].includes(f.detected_class) : filter === "ALL" || f.detected_class === filter))
    .sort((a, b) => ORDER.indexOf(a.detected_class) - ORDER.indexOf(b.detected_class) || a.table.localeCompare(b.table));
  return (
    <Card title={`Temuan (${shown.length} dari ${findings.length} kolom)`}
      actions={
        <label className="flex items-center gap-2 text-xs text-muted">
          Tampilkan
          <select value={filter} onChange={(e) => setFilter(e.target.value)} className="rounded-md border border-border bg-surface-2 px-2 py-1 text-sm text-text">
            <option value="PII">Hanya yang perlu dilindungi/diperhatikan</option>
            <option value="ALL">Semua kolom</option>
            {ORDER.map((c) => <option key={c} value={c}>{CLASS_LABEL[c]}</option>)}
          </select>
        </label>
      }>
      <div className="overflow-x-auto">
        <table className="w-full text-sm">
          <thead>
            <tr className="border-b border-border text-left text-xs text-muted">
              {["Kolom", "Kelas", "Jenis", "Yakin", "Contoh (tersamar)", "Alasan"].map((h) => <th key={h} scope="col" className="px-2 py-2 font-medium">{h}</th>)}
            </tr>
          </thead>
          <tbody>
            {shown.map((f) => (
              <tr key={`${f.table}.${f.column}`} className="border-b border-border/60 align-top">
                <td className="px-2 py-2 font-mono text-xs">{f.table}.<strong>{f.column}</strong></td>
                <td className="px-2 py-2"><Badge tone={classTone(f.detected_class)}>{CLASS_LABEL[f.detected_class] ?? f.detected_class}</Badge></td>
                <td className="px-2 py-2">{f.pii_type}</td>
                <td className="px-2 py-2 tabular-nums">{(f.confidence * 100).toFixed(0)}%</td>
                <td className="px-2 py-2 font-mono text-xs">{f.sample_masked}</td>
                <td className="px-2 py-2 text-xs text-muted">{f.why.join("; ")}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </Card>
  );
}

function Confusion({ m }: { m: ModeMetrics }) {
  const cols = ORDER.filter((c) => Object.values(m.confusion).some((r) => r[c]));
  const rows = ORDER.filter((c) => m.confusion[c]);
  return (
    <Card title="Confusion matrix (nama kolom diabaikan)" actions={<span className="text-xs text-muted">baris = acuan kontrak, kolom = terdeteksi</span>}>
      <div className="overflow-x-auto">
        <table className="text-sm">
          <thead>
            <tr>
              <th scope="col" className="px-2 py-1" />
              {cols.map((c) => <th key={c} scope="col" className="px-2 py-1 text-xs font-medium text-muted">{CLASS_LABEL[c]}</th>)}
            </tr>
          </thead>
          <tbody>
            {rows.map((r) => (
              <tr key={r}>
                <th scope="row" className="px-2 py-1 text-left text-xs font-medium text-muted">{CLASS_LABEL[r]}</th>
                {cols.map((c) => {
                  const n = m.confusion[r]?.[c] ?? 0;
                  return (
                    <td key={c} className={`px-2 py-1 text-center tabular-nums ${n === 0 ? "text-muted/40" : r === c ? "font-bold text-safe" : "font-bold text-leak"}`}>{n || "·"}</td>
                  );
                })}
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      {m.mismatches.length > 0 && (
        <ul className="mt-3 list-disc space-y-0.5 pl-5 text-xs text-warn">
          {m.mismatches.map((x) => <li key={`${x.table}.${x.column}`}><code className="font-mono">{x.table}.{x.column}</code>: acuan {x.reference}, terdeteksi {x.detected}</li>)}
        </ul>
      )}
    </Card>
  );
}

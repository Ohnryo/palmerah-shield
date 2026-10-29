import { useState, type FormEvent } from "react";
import { useQuery } from "@tanstack/react-query";
import { Gauge, Loader2 } from "lucide-react";
import { ApiError, getOut, getStatus, type Benchmark, type Target } from "../lib/api";
import { useJob } from "../lib/useJob";
import { Card, Empty } from "../components/ui";
import { TargetTabs, useTarget } from "../components/TargetTabs";
import { Progress } from "../components/Progress";

const NAME: Record<Target, string> = { a: "web-legacy", b: "web-modern" };
const nf = (v: number, d = 1) => v.toLocaleString("id-ID", { maximumFractionDigits: d });
const mb = (b: number) => b / 1e6;

type Row = { members: number; before: number; after: number };
interface Metric { title: string; unit: string; digits: number; note: string; rows: Row[] }

export function Performance() {
  const [target, setTarget] = useTarget();
  const job = useJob();
  const status = useQuery({ queryKey: ["status"], queryFn: getStatus, refetchInterval: 5000 });
  const hardened = status.data?.targets.find((x) => x.target === target)?.mode === "hardened";
  const q = useQuery({
    queryKey: ["out", "benchmark", target],
    queryFn: () => getOut<Benchmark>("benchmark", target),
    retry: (n, e) => !(e instanceof ApiError && e.status === 404) && n < 2,
  });
  const b = q.data;
  const missing = q.error instanceof ApiError && q.error.status === 404;
  const busy = job.running || !!status.data?.operation;
  return (
    <div className="mx-auto max-w-7xl space-y-6">
      <header className="flex flex-wrap items-end justify-between gap-3">
        <div>
          <h1 className="text-2xl font-bold">Kinerja</h1>
          <p className="text-sm text-muted">Biaya perlindungan pada data sintetis yang diperbesar: sebelum (rentan) vs sesudah (terlindungi).</p>
        </div>
        <TargetTabs value={target} onChange={setTarget} />
      </header>

      <RunCard target={target} busy={busy} hardened={hardened} onGo={(c) => job.run("benchmark", target, c)} running={job.running} />
      <Progress events={job.events} running={job.running} error={job.error} />

      {q.isPending && <p className="text-muted">Memuat…</p>}
      {missing && <Empty>Belum ada hasil benchmark untuk website {target.toUpperCase()}.</Empty>}
      {q.isError && !missing && <p role="alert" className="text-leak">{q.error.message}</p>}
      {b && <Result b={b} />}
    </div>
  );
}

function RunCard({ target, busy, hardened, onGo, running }: { target: Target; busy: boolean; hardened: boolean; onGo: (c: string) => void; running: boolean }) {
  const [typed, setTyped] = useState("");
  const ok = typed.trim() === NAME[target];
  function submit(e: FormEvent) { e.preventDefault(); if (ok && !busy && !hardened) { onGo(typed.trim()); setTyped(""); } }
  return (
    <Card>
      <form onSubmit={submit} className="flex flex-wrap items-end gap-3">
        <div>
          <label htmlFor="confirm-bench" className="mb-1 block text-sm">Ketik <code className="rounded bg-surface-2 px-1.5 font-mono">{NAME[target]}</code></label>
          <input id="confirm-bench" value={typed} onChange={(e) => setTyped(e.target.value)} autoComplete="off"
            className="rounded-lg border border-border bg-surface-2 px-3 py-2 font-mono text-sm" />
        </div>
        <button type="submit" disabled={!ok || busy || hardened}
          className="inline-flex items-center gap-2 rounded-lg bg-accent px-4 py-2 text-sm font-semibold text-bg disabled:opacity-40">
          {running ? <Loader2 className="size-4 animate-spin" aria-hidden /> : <Gauge className="size-4" aria-hidden />}
          Jalankan benchmark (10 rb + 100 rb anggota)
        </button>
      </form>
      <p className="mt-2 text-xs text-warn">
        Memuat ulang data website {target.toUpperCase()} (berakhir di seed 734 baris, MODE=vuln). Jangan dijalankan saat demo; butuh beberapa menit.
        {hardened && " Target sedang hardened: rollback dulu."} Ukuran lain: <code className="font-mono">shield benchmark -t {target} --rows N</code>.
      </p>
    </Card>
  );
}

function Result({ b }: { b: Benchmark }) {
  const metrics: Metric[] = [
    { title: "Lookup satu anggota, p95", unit: "ms", digits: 2, note: "sesudah = VIEW peran sdm + dekripsi oleh filter proxy",
      rows: b.sizes.map((s) => ({ members: s.members, before: s.before.lookup.p95_ms ?? 0, after: s.after.lookup.p95_ms ?? 0 })) },
    { title: "Cari berdasarkan NIK, p95", unit: "ms", digits: 2, note: "sesudah = blind index HMAC (berindeks), NIK tidak pernah didekripsi",
      rows: b.sizes.map((s) => ({ members: s.members, before: s.before.search.p95_ms ?? 0, after: s.after.search.p95_ms ?? 0 })) },
    { title: "Ukuran database", unit: "MB", digits: 1, note: "ciphertext + kolom blind index/mask",
      rows: b.sizes.map((s) => ({ members: s.members, before: mb(s.before.db_bytes), after: mb(s.after.db_bytes) })) },
    { title: "Ukuran dump (backup)", unit: "MB", digits: 1, note: "pg_dump / mariadb-dump teks",
      rows: b.sizes.map((s) => ({ members: s.members, before: mb(s.before.dump_bytes), after: mb(s.after.dump_bytes) })) },
    { title: "Waktu dump (backup)", unit: "detik", digits: 2, note: "",
      rows: b.sizes.map((s) => ({ members: s.members, before: s.before.dump_s, after: s.after.dump_s })) },
  ];
  return (
    <>
      <Card title="Ringkasan" actions={<span className="text-xs text-muted">diukur {new Date(b.generated_at).toLocaleString("id-ID")} · {b.machine.cpus} CPU · {b.machine.platform}</span>}>
        <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
          {b.sizes.map((s) => (
            <div key={s.members} className="rounded-lg bg-surface-2 p-3">
              <div className="text-xs text-muted">Apply {nf(s.members, 0)} anggota</div>
              <div className="mt-1 text-2xl font-bold tabular-nums">{nf(s.apply.seconds)} dtk</div>
              <div className="text-xs text-muted">{nf(s.apply.members_per_s, 0)} anggota/dtk · rollback {nf(s.rollback_s)} dtk</div>
            </div>
          ))}
          {b.sizes.map((s) => {
            const err = s.before.lookup.errors + s.before.search.errors + s.after.lookup.errors + s.after.search.errors;
            return (
              <div key={`e${s.members}`} className="rounded-lg bg-surface-2 p-3">
                <div className="text-xs text-muted">Galat kueri ({nf(s.members, 0)} anggota)</div>
                <div className="mt-1 text-2xl font-bold tabular-nums">{err} / {4 * b.queries_per_workload}</div>
                <div className="text-xs text-muted">lookup + search, sebelum + sesudah</div>
              </div>
            );
          })}
        </div>
      </Card>

      <div className="flex items-center gap-4 text-sm" aria-label="Legenda">
        <span className="inline-flex items-center gap-2"><span className="h-3 w-4 rounded-sm bg-series-1" aria-hidden />Sebelum (rentan)</span>
        <span className="inline-flex items-center gap-2"><span className="h-3 w-4 rounded-sm bg-series-2" aria-hidden />Sesudah (terlindungi)</span>
      </div>
      <div className="grid gap-6 lg:grid-cols-2">
        {metrics.map((m) => <Bars key={m.title} m={m} />)}
      </div>

      <Card title="Tabel lengkap">
        <div className="overflow-x-auto">
          <table className="w-full text-sm tabular-nums">
            <thead>
              <tr className="border-b border-border text-left text-xs text-muted">
                {["Anggota", "Fase", "Lookup p50 / p95 (ms)", "Search p50 / p95 (ms)", "Kueri/dtk (lookup)", "DB (MB)", "Dump (MB / dtk)", "Restore (dtk)", "CPU klien (dtk)", "RSS puncak (MB)"].map((h) => (
                  <th key={h} scope="col" className="px-2 py-2 font-medium">{h}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {b.sizes.flatMap((s) => (["before", "after"] as const).map((ph) => {
                const x = s[ph];
                return (
                  <tr key={`${s.members}${ph}`} className="border-b border-border/60">
                    <td className="px-2 py-1.5">{nf(s.members, 0)}</td>
                    <td className="px-2 py-1.5">{ph === "before" ? "sebelum" : "sesudah"}</td>
                    <td className="px-2 py-1.5">{x.lookup.p50_ms} / {x.lookup.p95_ms}</td>
                    <td className="px-2 py-1.5">{x.search.p50_ms} / {x.search.p95_ms}</td>
                    <td className="px-2 py-1.5">{x.lookup.qps !== undefined ? nf(x.lookup.qps, 0) : "–"}</td>
                    <td className="px-2 py-1.5">{nf(mb(x.db_bytes))}</td>
                    <td className="px-2 py-1.5">{nf(mb(x.dump_bytes))} / {x.dump_s}</td>
                    <td className="px-2 py-1.5">{x.restore_s ?? "–"}</td>
                    <td className="px-2 py-1.5">{x.client_cpu_s ?? "–"}</td>
                    <td className="px-2 py-1.5">{x.peak_rss_mb ?? "–"}</td>
                  </tr>
                );
              }))}
            </tbody>
          </table>
        </div>
        <ul className="mt-3 list-disc space-y-1 pl-5 text-xs text-muted">{b.notes.map((n) => <li key={n}>{n}</li>)}</ul>
      </Card>
    </>
  );
}

/** Small multiple: one metric, one scale, rows per data size, before/after bars from a common zero baseline. */
function Bars({ m }: { m: Metric }) {
  const max = Math.max(...m.rows.flatMap((r) => [r.before, r.after]), 0) || 1;
  const [tip, setTip] = useState<string | null>(null);
  return (
    <Card title={m.title} actions={<span className="text-xs text-muted">{m.unit}</span>}>
      <figure>
        <div className="space-y-4" role="list">
          {m.rows.map((r) => (
            <div key={r.members} role="listitem">
              <div className="mb-1 text-xs text-muted">{nf(r.members, 0)} anggota</div>
              {([["before", "Sebelum", "bg-series-1"], ["after", "Sesudah", "bg-series-2"]] as const).map(([k, label, color]) => {
                const v = r[k];
                const text = `${label}, ${nf(r.members, 0)} anggota: ${nf(v, m.digits)} ${m.unit}`;
                return (
                  <div key={k} className="group mb-0.5 flex items-center gap-2" tabIndex={0} aria-label={text}
                    onPointerEnter={() => setTip(text)} onPointerLeave={() => setTip(null)} onFocus={() => setTip(text)} onBlur={() => setTip(null)}>
                    <div className="h-4 flex-1">
                      <div className={`h-4 rounded-r-[4px] ${color} group-hover:brightness-110 group-focus:brightness-110 ${pctClass(v / max)}`} />
                    </div>
                    <span className="w-24 shrink-0 text-right text-xs tabular-nums text-text">{nf(v, m.digits)}</span>
                  </div>
                );
              })}
            </div>
          ))}
        </div>
        <figcaption className="mt-3 min-h-4 text-xs text-muted" aria-live="polite">{tip ?? m.note}</figcaption>
      </figure>
    </Card>
  );
}

// widths as static classes (CSP: no inline style attributes), 2% steps
const W = Array.from({ length: 51 }, (_, i) => i * 2);
function pctClass(f: number): string {
  const p = W.reduce((best, w) => (Math.abs(w - f * 100) < Math.abs(best - f * 100) ? w : best), 0);
  return WIDTH[Math.max(p, f > 0 ? 2 : 0)];
}
const WIDTH: Record<number, string> = {
  0: "w-0", 2: "w-[2%]", 4: "w-[4%]", 6: "w-[6%]", 8: "w-[8%]", 10: "w-[10%]", 12: "w-[12%]", 14: "w-[14%]", 16: "w-[16%]",
  18: "w-[18%]", 20: "w-[20%]", 22: "w-[22%]", 24: "w-[24%]", 26: "w-[26%]", 28: "w-[28%]", 30: "w-[30%]", 32: "w-[32%]",
  34: "w-[34%]", 36: "w-[36%]", 38: "w-[38%]", 40: "w-[40%]", 42: "w-[42%]", 44: "w-[44%]", 46: "w-[46%]", 48: "w-[48%]",
  50: "w-[50%]", 52: "w-[52%]", 54: "w-[54%]", 56: "w-[56%]", 58: "w-[58%]", 60: "w-[60%]", 62: "w-[62%]", 64: "w-[64%]",
  66: "w-[66%]", 68: "w-[68%]", 70: "w-[70%]", 72: "w-[72%]", 74: "w-[74%]", 76: "w-[76%]", 78: "w-[78%]", 80: "w-[80%]",
  82: "w-[82%]", 84: "w-[84%]", 86: "w-[86%]", 88: "w-[88%]", 90: "w-[90%]", 92: "w-[92%]", 94: "w-[94%]", 96: "w-[96%]",
  98: "w-[98%]", 100: "w-full",
};

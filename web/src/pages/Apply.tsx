import { useState, type FormEvent } from "react";
import { useQuery } from "@tanstack/react-query";
import { Loader2, RotateCcw, ShieldCheck } from "lucide-react";
import { ApiError, getOut, getStatus, type ApplyReport, type Plan, type Target } from "../lib/api";
import { useJob } from "../lib/useJob";
import { Badge, Card, Empty, Evidence, Stat } from "../components/ui";
import { TargetTabs, useTarget } from "../components/TargetTabs";
import { Progress } from "../components/Progress";

const NAME: Record<Target, string> = { a: "web-legacy", b: "web-modern" };

export function Apply() {
  const [target, setTarget] = useTarget();
  const job = useJob();
  const status = useQuery({ queryKey: ["status"], queryFn: getStatus, refetchInterval: 5000 });
  const t = status.data?.targets.find((x) => x.target === target);
  const hardened = t?.mode === "hardened";
  const plan = useQuery({
    queryKey: ["out", "plan", target], queryFn: () => getOut<Plan>("plan", target),
    retry: (n, e) => !(e instanceof ApiError && e.status === 404) && n < 2,
  });
  const report = useQuery({
    queryKey: ["out", "apply_report", target, hardened], queryFn: () => getOut<ApplyReport>("apply_report", target),
    enabled: hardened, retry: false,
  });
  const busy = job.running || !!status.data?.operation;
  return (
    <div className="mx-auto max-w-7xl space-y-6">
      <header className="flex flex-wrap items-end justify-between gap-3">
        <div>
          <h1 className="text-2xl font-bold">Terapkan</h1>
          <p className="text-sm text-muted">Backup terenkripsi dulu, lalu enkripsi, tokenisasi, blind index, VIEW per peran. Gagal di tengah = database dikembalikan dari backup.</p>
        </div>
        <TargetTabs value={target} onChange={setTarget} />
      </header>

      {t && (
        <div className="flex items-center gap-3">
          <Badge tone={hardened ? "safe" : "leak"}>MODE={t.mode}</Badge>
          <span className="text-sm text-muted">{t.name} · {t.db}</span>
        </div>
      )}

      {!hardened && <Preview plan={plan.data} missing={plan.error instanceof ApiError && plan.error.status === 404} />}
      {status.data?.operation && !job.running && (
        <p role="status" className="rounded-lg border border-warn/40 bg-warn-bg px-4 py-2 text-sm text-warn">
          Operasi <strong>{status.data.operation.op}</strong> sedang berjalan ({status.data.operation.source === "console" ? "konsol" : "CLI"}); tombol aktif lagi setelah selesai.
        </p>
      )}

      {!hardened ? (
        <ConfirmCard
          key={`apply-${target}`} word={NAME[target]} busy={busy} disabled={!plan.data} icon={<ShieldCheck className="size-4" aria-hidden />}
          title="Terapkan pertahanan" button="Terapkan"
          help="Ketik nama target untuk mengonfirmasi. Kolom duplikat yang butuh keputusan manusia tidak dihapus (opsi --allow-drop hanya di CLI)."
          onGo={(c) => job.run("apply", target, c)} tone="apply"
        />
      ) : (
        <ConfirmCard
          key={`rb-${target}`} word={NAME[target]} busy={busy} icon={<RotateCcw className="size-4" aria-hidden />}
          title="Rollback" button="Rollback ke kondisi rentan"
          help="Memulihkan database dari backup terenkripsi yang dibuat saat apply, menghapus role Shield, MODE=vuln."
          onGo={(c) => job.run("rollback", target, c)} tone="rollback"
        />
      )}
      <Progress events={job.events} running={job.running} error={job.error} />

      {hardened && report.data && <Report r={report.data} />}
    </div>
  );
}

function Preview({ plan, missing }: { plan?: Plan; missing: boolean }) {
  if (missing) return <Empty>Belum ada rencana. Buat dulu di halaman Rencana.</Empty>;
  if (!plan) return null;
  const rows = Object.entries(plan.by_control).filter(([, v]) => v.length);
  return (
    <Card title="Pratinjau perubahan" actions={<span className="text-xs text-muted">dari rencana {new Date(plan.generated_at).toLocaleString("id-ID")}</span>}>
      <ul className="grid gap-3 sm:grid-cols-2 lg:grid-cols-3">
        {rows.map(([k, v]) => (
          <li key={k} className="rounded-lg bg-surface-2 p-3">
            <div className="flex items-center justify-between"><strong className="text-sm">{k}</strong><span className="text-xl font-bold tabular-nums">{v.length}</span></div>
            <p className="mt-1 truncate font-mono text-xs text-muted" title={v.join(", ")}>{v.slice(0, 3).join(", ")}{v.length > 3 ? ` +${v.length - 3}` : ""}</p>
          </li>
        ))}
      </ul>
      {plan.needs_human_review.length > 0 && (
        <p className="mt-3 text-xs text-warn">{plan.needs_human_review.length} keputusan menunggu manusia (lihat halaman Rencana); tidak diterapkan otomatis.</p>
      )}
    </Card>
  );
}

function ConfirmCard({ word, busy, disabled, icon, title, button, help, onGo, tone }: {
  word: string; busy: boolean; disabled?: boolean; icon: React.ReactNode; title: string; button: string; help: string;
  onGo: (confirm: string) => void; tone: "apply" | "rollback";
}) {
  const [typed, setTyped] = useState("");
  const ok = typed.trim() === word;
  function submit(e: FormEvent) { e.preventDefault(); if (ok && !busy && !disabled) { onGo(typed.trim()); setTyped(""); } }
  return (
    <Card title={title}>
      <form onSubmit={submit} className="flex flex-wrap items-end gap-3">
        <div>
          <label htmlFor={`confirm-${tone}`} className="mb-1 block text-sm">Ketik <code className="rounded bg-surface-2 px-1.5 font-mono">{word}</code></label>
          <input id={`confirm-${tone}`} value={typed} onChange={(e) => setTyped(e.target.value)} autoComplete="off"
            className="rounded-lg border border-border bg-surface-2 px-3 py-2 font-mono text-sm" />
        </div>
        <button type="submit" disabled={!ok || busy || disabled}
          className={`inline-flex items-center gap-2 rounded-lg px-4 py-2 text-sm font-semibold disabled:opacity-40 ${tone === "apply" ? "bg-safe text-bg" : "bg-leak text-white"}`}>
          {busy ? <Loader2 className="size-4 animate-spin" aria-hidden /> : icon}{button}
        </button>
      </form>
      <p className="mt-2 text-xs text-muted">{help}</p>
    </Card>
  );
}

interface Verification {
  dump_without_keys?: { sample_values: number; found_in_dump: number; columns_leaking: string[]; residual_derived?: Record<string, string> };
  app_login_denied_on_base_table?: boolean;
  public_view_nik_values?: (string | null)[];
}

function Report({ r }: { r: ApplyReport }) {
  const v = ((r.rerun as { verification?: Verification } | undefined)?.verification ?? r.verification) as Verification;
  const d = v.dump_without_keys;
  return (
    <>
      <Card title="Hasil verifikasi" actions={<span className="text-xs text-muted">diterapkan {new Date(r.applied_at).toLocaleString("id-ID")}</span>}>
        <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
          <Stat label="Nilai asli di dump nyata" value={d ? `${d.found_in_dump} / ${d.sample_values}` : "–"} tone={d?.found_in_dump === 0 ? "safe" : "leak"} sub="dump tanpa kunci" />
          <Stat label="Login aplikasi di tabel dasar" value={v.app_login_denied_on_base_table ? "ditolak" : "terbuka"} tone={v.app_login_denied_on_base_table ? "safe" : "leak"} />
          <Stat label="Peran public melihat NIK" value={v.public_view_nik_values?.every((x) => x === null) ? "NULL" : "terlihat"} tone={v.public_view_nik_values?.every((x) => x === null) ? "safe" : "leak"} />
          <Stat label="Backup" value="terenkripsi" sub={String((r as unknown as { backup?: { file?: string } }).backup?.file ?? "")} tone="safe" />
        </div>
        {d?.residual_derived && Object.keys(d.residual_derived).length > 0 && (
          <p className="mt-3 text-xs text-warn">Sisa risiko: {Object.entries(d.residual_derived).map(([k, x]) => `${k} — ${x}`).join("; ")}</p>
        )}
      </Card>
      <Card title="Kontrol dan bukti">
        <ul className="divide-y divide-border">
          {r.controls.map((c) => (
            <li key={c.control} className="flex flex-wrap items-start gap-3 py-2 text-sm">
              <Evidence status={c.status.replace(/[[\]]/g, "") as "IMPLEMENTED" | "TESTED" | "PLANNED"} />
              <div className="min-w-0 flex-1"><div className="font-medium">{c.control}</div><div className="text-xs text-muted">{c.evidence}</div></div>
            </li>
          ))}
        </ul>
      </Card>
      {r.needs_human_review.length > 0 && (
        <Card title="Perlu keputusan manusia" actions={<Badge tone="warn">{r.needs_human_review.length}</Badge>}>
          <ul className="list-disc space-y-1 pl-5 text-sm">{r.needs_human_review.map((n) => <li key={n}>{n}</li>)}</ul>
        </Card>
      )}
    </>
  );
}

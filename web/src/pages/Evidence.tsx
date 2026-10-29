import { useQuery } from "@tanstack/react-query";
import { FileCheck2, Loader2, Lock, ShieldAlert, Users, KeyRound } from "lucide-react";
import { ApiError, getOut, getStatus, type CellKind, type Evidence as EvidenceData } from "../lib/api";
import { useJob } from "../lib/useJob";
import { Badge, Card, Empty, Evidence as Label, Stat, type Tone } from "../components/ui";
import { TargetTabs, useTarget } from "../components/TargetTabs";
import { Progress } from "../components/Progress";
import { Scoreboard } from "./Home";

const KIND: Record<CellKind, { tone: Tone; text: string }> = {
  none: { tone: "neutral", text: "tidak dikirim" },
  masked: { tone: "warn", text: "tersamar" },
  envelope: { tone: "safe", text: "terenkripsi" },
  token: { tone: "safe", text: "token" },
  PLAINTEXT: { tone: "leak", text: "PLAINTEXT" },
  other: { tone: "warn", text: "tidak terklasifikasi" },
  error: { tone: "warn", text: "galat" },
  "no-row": { tone: "neutral", text: "tidak ada baris" },
};

export function Bukti() {
  const [target, setTarget] = useTarget();
  const job = useJob();
  const status = useQuery({ queryKey: ["status"], queryFn: getStatus, refetchInterval: 5000 });
  const t = status.data?.targets.find((x) => x.target === target);
  const hardened = t?.mode === "hardened";
  const q = useQuery({
    queryKey: ["out", "evidence", target],
    queryFn: () => getOut<EvidenceData>("evidence", target),
    retry: (n, e) => !(e instanceof ApiError && e.status === 404) && n < 2,
  });
  const ev = q.data;
  const missing = q.error instanceof ApiError && q.error.status === 404;
  const busy = job.running || !!status.data?.operation;
  return (
    <div className="mx-auto max-w-7xl space-y-6">
      <header className="flex flex-wrap items-end justify-between gap-3">
        <div>
          <h1 className="text-2xl font-bold">Bukti</h1>
          <p className="text-sm text-muted">Tiga skenario bocor, diukur langsung pada database dan KMS yang sedang berjalan.</p>
        </div>
        <TargetTabs value={target} onChange={setTarget} />
      </header>

      <Card>
        <div className="flex flex-wrap items-center gap-3">
          <button type="button" disabled={busy || !hardened} onClick={() => job.run("evidence", target)}
            className="inline-flex items-center gap-2 rounded-lg bg-accent px-4 py-2 text-sm font-semibold text-bg disabled:opacity-40">
            {job.running ? <Loader2 className="size-4 animate-spin" aria-hidden /> : <FileCheck2 className="size-4" aria-hidden />}
            {ev ? "Ukur ulang" : "Jalankan pembuktian"} website {target.toUpperCase()}
          </button>
          {t && !hardened && <span className="text-sm text-warn">Website {target.toUpperCase()} masih MODE=vuln: terapkan pertahanan dulu.</span>}
          {ev && <span className="text-xs text-muted">diukur {new Date(ev.generated_at).toLocaleString("id-ID")}</span>}
        </div>
        <Progress events={job.events} running={job.running} error={job.error} />
      </Card>

      {q.isPending && <p className="text-muted">Memuat…</p>}
      {missing && <Empty>Belum ada bukti untuk website {target.toUpperCase()}. {hardened ? "Jalankan pembuktian di atas." : "Terapkan pertahanan dulu."}</Empty>}
      {q.isError && !missing && <p role="alert" className="text-leak">{q.error.message}</p>}
      {ev && <Scenarios ev={ev} />}

      <Scoreboard data={status.data?.redcheck ?? { available: false, results: [] }} />
    </div>
  );
}

function Scenarios({ ev }: { ev: EvidenceData }) {
  const a = ev.a_dump_without_keys, b = ev.b_dump_with_keys, c = ev.c_legitimate_users;
  const leaks = a.columns.filter((x) => x.leak).length;
  const sample = a.apply_report_sample;
  return (
    <>
      <Card title="(a) Dump tanpa kunci" icon={<ShieldAlert className="size-5 text-accent" aria-hidden />} actions={<Label status="TESTED" />}>
        <div className="mb-4 grid grid-cols-2 gap-3 lg:grid-cols-3">
          <Stat label="Kolom berisi nilai asli (baris contoh)" value={`${leaks} / ${a.columns.length}`} tone={leaks === 0 ? "safe" : "leak"} />
          <Stat label="Nilai asli di dump nyata (sampel apply)" value={sample.sample_values !== undefined ? `${sample.found_in_dump} / ${sample.sample_values}` : "–"} tone={sample.found_in_dump === 0 ? "safe" : "leak"} />
          <Stat label="Sel plaintext di semua peran" value={ev.plaintext_cells_total} tone={ev.plaintext_cells_total === 0 ? "safe" : "leak"} />
        </div>
        <p className="mb-2 text-xs text-muted">{a.row}. Nilai asli hanya ditampilkan tersamar.</p>
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-border text-left text-xs text-muted">
                {["Kolom", "Sebelum (asli, tersamar)", "Sesudah: isi dump", "Jenis"].map((h) => <th key={h} scope="col" className="px-2 py-2 font-medium">{h}</th>)}
              </tr>
            </thead>
            <tbody>
              {a.columns.map((x) => (
                <tr key={`${x.table}.${x.column}`} className="border-b border-border/60 align-top">
                  <td className="px-2 py-2 font-mono text-xs">{x.table}.<strong>{x.column}</strong>{x.stored_column !== x.column && <span className="text-muted"> → {x.stored_column}</span>}</td>
                  <td className="px-2 py-2 font-mono text-xs">{x.original_masked ?? "–"}</td>
                  <td className="break-all px-2 py-2 font-mono text-xs">{x.stored}</td>
                  <td className="px-2 py-2"><Badge tone={KIND[x.kind].tone}>{KIND[x.kind].text}</Badge></td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
        <p className="mt-3 text-xs text-muted">Token berformat sama dengan aslinya (panjang dan jenis karakter), tetapi tanpa vault KMS tidak bermakna.</p>
      </Card>

      <Card title="(b) Dump + kunci bocor" icon={<KeyRound className="size-5 text-accent" aria-hidden />} actions={<Label status="TESTED" />}>
        <p className="mb-3 text-sm">Yang ikut bocor: tabel <code className="font-mono">shield_keys</code> ({b.shield_keys_rows} kunci data, semuanya <strong>terbungkus</strong>). KEK hanya ada di proses KMS terpisah.</p>
        {b.attempt?.error ? (
          <p role="alert" className="text-sm text-warn">{b.attempt.error}</p>
        ) : b.attempt ? (
          <ul className="mb-4 grid gap-3 lg:grid-cols-3">
            <Attempt title="Pakai DEK terbungkus sebagai kunci" result={b.attempt.wrapped_dek_as_key} bad="BERHASIL" />
            <Attempt title="Panggil KMS dengan token salah" result={b.attempt.kms_with_wrong_token} bad="TIDAK" />
            <li className="rounded-lg border border-border bg-surface-2 p-3">
              <div className="mb-1 flex items-center gap-2 text-sm font-semibold"><Lock className="size-4 text-safe" aria-hidden />Jalur sah via KMS</div>
              <Badge tone={b.attempt.kms_authorised?.startsWith("berhasil") ? "safe" : "warn"}>{b.attempt.kms_authorised?.startsWith("berhasil") ? "berhasil" : "gagal"}</Badge>
              <p className="mt-1 text-xs text-muted">{b.attempt.kms_authorised}</p>
            </li>
          </ul>
        ) : null}
        {b.attempt && <p className="mb-3 text-xs text-muted">Kolom yang dicoba: <code className="font-mono">{b.attempt.column}</code></p>}
        <details className="mb-4 text-sm">
          <summary className="cursor-pointer text-muted">Contoh isi shield_keys (terpotong)</summary>
          <ul className="mt-2 space-y-1 font-mono text-xs">
            {b.sample.map((k) => <li key={k.key_id}>{k.key_id} · {k.purpose} · {k.name} · {k.wrapped}</li>)}
          </ul>
        </details>
        <div className="rounded-lg border border-warn/40 bg-warn-bg p-3">
          <div className="mb-1 flex items-center gap-2 text-sm font-semibold text-warn">Sisa risiko <Badge tone="neutral">teks tertulis</Badge><span className="text-xs font-normal">bukan hasil ukur</span></div>
          <ul className="list-disc space-y-1 pl-5 text-sm">{b.residual_risk_written.map((r) => <li key={r}>{r}</li>)}</ul>
        </div>
      </Card>

      <Card title="(c) Pengguna sah tetap terlayani" icon={<Users className="size-5 text-accent" aria-hidden />} actions={<Badge tone="safe">[TESTED] level database</Badge>}>
        <p className="mb-1 text-xs text-muted">{c.via}. Peran <code className="font-mono">anggota</code> hanya membaca record miliknya (member {c.member_id_for_self_role}).</p>
        <p className="mb-3 text-xs text-muted">Lewat proxy (:8443/:8444): <Label status="IMPLEMENTED" /> dekripsi per peran sesuai matriks; diuji dengan web tiruan, menunggu web A/B yang mengirim header <code className="font-mono">X-Palmerah-Role</code>.</p>
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-border text-left text-xs text-muted">
                <th scope="col" className="px-2 py-2 font-medium">Peran</th>
                {ev.fields.map((f) => <th key={f} scope="col" className="px-2 py-2 font-mono font-medium">{f}</th>)}
                <th scope="col" className="px-2 py-2 text-right font-medium">Terbaca</th>
              </tr>
            </thead>
            <tbody>
              {Object.entries(c.roles).map(([role, r]) => (
                <tr key={role} className="border-b border-border/60 align-top">
                  <th scope="row" className="px-2 py-2 text-left font-medium">{role}</th>
                  {ev.fields.map((f) => {
                    const cell = r.cells[f];
                    const k = cell ? KIND[cell.kind] : KIND.none;
                    return (
                      <td key={f} className="px-2 py-2" title={cell?.value ?? ""}>
                        <Badge tone={k.tone}>{k.text}</Badge>
                      </td>
                    );
                  })}
                  <td className="px-2 py-2 text-right tabular-nums">{r.readable}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
        <p className="mt-3 text-xs text-muted">Di level database, kolom berlevel full tampil sebagai envelope/token karena VIEW tidak mendekripsi (kunci tidak ada di database); proxy yang mendekripsi sesuai peran (ASUMSI A14). Arahkan kursor ke sel untuk nilai tersimpan yang terpotong.</p>
      </Card>
    </>
  );
}

function Attempt({ title, result, bad }: { title: string; result?: string; bad: string }) {
  const failed = !!result && !result.toUpperCase().includes(bad);
  return (
    <li className="rounded-lg border border-border bg-surface-2 p-3">
      <div className="mb-1 text-sm font-semibold">{title}</div>
      <Badge tone={failed ? "safe" : "leak"}>{failed ? "gagal (aman)" : "BERHASIL (bocor)"}</Badge>
      <p className="mt-1 font-mono text-xs text-muted">{result}</p>
    </li>
  );
}

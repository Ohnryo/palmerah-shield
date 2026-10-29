import { useQuery } from "@tanstack/react-query";
import { AlertTriangle, KeyRound, ScrollText } from "lucide-react";
import { getKeys, type AuditLine } from "../lib/api";
import { Badge, Card, Empty, Stat } from "../components/ui";
import { TargetTabs, useTarget } from "../components/TargetTabs";

export function KeysAudit() {
  const [target, setTarget] = useTarget();
  const q = useQuery({ queryKey: ["keys", target], queryFn: () => getKeys(target), refetchInterval: 5000 });
  const k = q.data;
  return (
    <div className="mx-auto max-w-7xl space-y-6">
      <header className="flex flex-wrap items-end justify-between gap-3">
        <div>
          <h1 className="text-2xl font-bold">Kunci & Audit</h1>
          <p className="text-sm text-muted">Status KMS dan jejak akses PII. Tidak ada materi kunci atau nilai data di halaman ini.</p>
        </div>
        <TargetTabs value={target} onChange={setTarget} />
      </header>
      {q.isPending && <p className="text-muted">Memuat…</p>}
      {q.isError && <p role="alert" className="text-leak">{q.error.message}</p>}
      {k && (
        <>
          <Card title="KMS :8200 (proses terpisah)" icon={<KeyRound className="size-5 text-accent" aria-hidden />}
            actions={<Badge tone={k.kms.reachable ? "safe" : "leak"}>{k.kms.reachable ? "aktif" : `tidak terjangkau${k.kms.error ? ` (${k.kms.error})` : ""}`}</Badge>}>
            {k.kms.status ? (
              <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
                <Stat label="ID KEK (sidik, bukan kunci)" value={<span className="font-mono text-lg">{k.kms.status.kek_id}</span>} />
                <Stat label="Token di vault" value={Object.values(k.kms.status.tokens).reduce((a, b) => a + b, 0).toLocaleString("id-ID")}
                  sub={Object.entries(k.kms.status.tokens).map(([d, n]) => `${d}: ${n.toLocaleString("id-ID")}`).join(" · ") || "kosong"} />
                <Stat label="Baris audit KMS" value={k.kms.status.audit_lines.toLocaleString("id-ID")} />
                <Stat label="Alarm pembacaan massal" value={k.kms.status.alerts} tone={k.kms.status.alerts ? "leak" : "safe"} />
              </div>
            ) : <Empty>KMS tidak terjangkau. Jalankan <code className="font-mono">shield dev start</code>.</Empty>}
          </Card>

          <Card title={`Kunci data website ${target.toUpperCase()} (shield_keys)`} actions={<span className="text-xs text-muted">hanya metadata; DEK terbungkus tidak ditampilkan</span>}>
            {k.shield_keys.rows.length ? (
              <div className="max-h-72 overflow-auto">
                <table className="w-full text-sm">
                  <thead className="sticky top-0 bg-surface">
                    <tr className="border-b border-border text-left text-xs text-muted">
                      {["Key ID", "Nama (db:tabel.kolom:tujuan)", "Tujuan", "Dibuat"].map((h) => <th key={h} scope="col" className="px-2 py-2 font-medium">{h}</th>)}
                    </tr>
                  </thead>
                  <tbody>
                    {k.shield_keys.rows.map((r) => (
                      <tr key={r.key_id} className="border-b border-border/60">
                        <td className="px-2 py-1.5 font-mono text-xs">{r.key_id}</td>
                        <td className="px-2 py-1.5 font-mono text-xs">{r.name}</td>
                        <td className="px-2 py-1.5"><Badge tone={r.purpose === "aead" ? "safe" : "neutral"}>{r.purpose}</Badge></td>
                        <td className="px-2 py-1.5 text-xs text-muted">{r.created_at}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            ) : <Empty>Belum ada kunci: website {target.toUpperCase()} belum diterapkan{k.shield_keys.note ? ` (${k.shield_keys.note})` : ""}.</Empty>}
          </Card>

          <div className="grid gap-6 lg:grid-cols-2">
            <AuditCard title="Audit KMS" lines={k.kms.audit ?? []} cols={["caller", "op", "subject", "count"]} empty="Belum ada aktivitas KMS." />
            <AuditCard title={`Audit proxy ${target.toUpperCase()}`} lines={k.proxy_audit} cols={["role", "method", "path", "decrypted", "detokenized", "removed"]} empty="Belum ada respons yang disaring proxy." />
          </div>
          <AuditCard title="Audit konsol" lines={k.console_audit} cols={["session", "action", "target", "detail"]} empty="Belum ada aksi." />
        </>
      )}
    </div>
  );
}

function AuditCard({ title, lines, cols, empty }: { title: string; lines: AuditLine[]; cols: string[]; empty: string }) {
  const rows = [...lines].reverse();
  const alerts = rows.filter((r) => r.alert).length;
  return (
    <Card title={title} icon={<ScrollText className="size-5 text-accent" aria-hidden />}
      actions={alerts ? <Badge tone="leak"><AlertTriangle className="size-3" aria-hidden />{alerts} alarm</Badge> : <span className="text-xs text-muted">terbaru di atas</span>}>
      {rows.length ? (
        <div className="max-h-80 overflow-auto">
          <table className="w-full text-xs">
            <thead className="sticky top-0 bg-surface">
              <tr className="border-b border-border text-left text-muted">
                <th scope="col" className="px-2 py-1.5 font-medium">Waktu</th>
                {cols.map((c) => <th key={c} scope="col" className="px-2 py-1.5 font-medium">{c}</th>)}
              </tr>
            </thead>
            <tbody>
              {rows.map((r, i) => (
                <tr key={i} className={`border-b border-border/60 align-top ${r.alert ? "bg-leak-bg" : ""}`}>
                  <td className="whitespace-nowrap px-2 py-1 font-mono text-muted">{new Date(r.ts).toLocaleTimeString("id-ID")}</td>
                  {cols.map((c) => <td key={c} className="px-2 py-1 font-mono">{r[c] === undefined || r[c] === null ? "" : String(r[c])}</td>)}
                </tr>
              ))}
            </tbody>
          </table>
          {alerts > 0 && <ul className="mt-2 space-y-1 text-xs text-leak">{rows.filter((r) => r.alert).slice(0, 3).map((r, i) => <li key={i}>{String(r.alert)}</li>)}</ul>}
        </div>
      ) : <Empty>{empty}</Empty>}
    </Card>
  );
}

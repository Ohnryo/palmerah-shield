import { useQuery } from "@tanstack/react-query";
import { Link } from "react-router";
import { Activity, ArrowRight, Check, Database, Loader2, Server, ShieldAlert, ShieldCheck, Target } from "lucide-react";
import { getStatus, type RedcheckResult, type Status, type TargetStatus } from "../lib/api";
import { Badge, Card, Empty, Stat } from "../components/ui";

const SERVICE_LABELS: Record<string, string> = {
  mysql: "MySQL :3306",
  postgres: "PostgreSQL :5432",
  kms: "KMS :8200",
  web_a: "Web A :8080",
  web_b: "Web B :3000",
  proxy_a: "Proxy A :8443",
  proxy_b: "Proxy B :8444",
};

const STEP_LINK = { scan: "/scan", plan: "/rencana", apply: "/terapkan" } as const;

export function Home() {
  const q = useQuery({ queryKey: ["status"], queryFn: getStatus, refetchInterval: 5000 });
  if (q.isPending) return <p className="text-muted">Memuat status…</p>;
  if (q.isError) return <p role="alert" className="text-leak">Status tidak dapat dimuat: {q.error.message}</p>;
  const s = q.data;
  return (
    <div className="mx-auto max-w-7xl space-y-6">
      <header className="flex flex-wrap items-end justify-between gap-2">
        <div>
          <h1 className="text-2xl font-bold">Beranda</h1>
          <p className="text-sm text-muted">Status website A dan B, layanan, dan leak scoreboard dari RedCheck.</p>
        </div>
        <span className="text-xs text-muted">diperbarui {new Date(s.generated_at).toLocaleTimeString("id-ID")}</span>
      </header>

      {s.operation && <OperationBanner op={s.operation} />}

      <div className="grid gap-6 lg:grid-cols-2">
        {s.targets.map((t) => (
          <TargetCard key={t.target} t={t} />
        ))}
      </div>

      <Scoreboard data={s.redcheck} />
      <Services services={s.services} />
    </div>
  );
}

function OperationBanner({ op }: { op: NonNullable<Status["operation"]> }) {
  return (
    <div role="status" className="flex items-center gap-3 rounded-xl border border-warn/40 bg-warn-bg px-4 py-3 text-sm text-warn">
      <Loader2 className="size-4 animate-spin" aria-hidden />
      Operasi <strong className="font-mono">{op.op}</strong>
      {op.target && <> pada target <strong>{op.target.toUpperCase()}</strong></>} sedang berjalan
      {op.source === "console" ? " dari konsol" : " dari CLI"}. Operasi lain menunggu sampai selesai.
    </div>
  );
}

function TargetCard({ t }: { t: TargetStatus }) {
  const hardened = t.mode === "hardened";
  const sm = t.summary;
  const steps = [
    { key: "scan", label: "Scan", done: !!t.files.inventory },
    { key: "plan", label: "Rencana", done: !!t.files.plan },
    { key: "apply", label: "Terapkan", done: hardened },
  ];
  return (
    <Card
      title={<>Website {t.target.toUpperCase()} · {t.name}</>}
      icon={hardened ? <ShieldCheck className="size-5 text-safe" aria-hidden /> : <ShieldAlert className="size-5 text-leak" aria-hidden />}
      actions={<Badge tone={hardened ? "safe" : "leak"}>MODE={t.mode}</Badge>}
    >
      <p className="mb-4 flex flex-wrap gap-x-4 gap-y-1 text-xs text-muted">
        <span className="inline-flex items-center gap-1"><Database className="size-3.5" aria-hidden />{t.db}</span>
        <span className="font-mono">{hardened ? t.proxy : t.url}</span>
      </p>

      <ol className="mb-4 flex items-center gap-2 text-sm" aria-label="Langkah">
        {steps.map((st, i) => (
          <li key={st.key} className="flex items-center gap-2">
            {i > 0 && <span className="h-px w-6 bg-border" aria-hidden />}
            <span className={`inline-flex items-center gap-1.5 rounded-full border px-2.5 py-0.5 ${st.done ? "border-safe/40 bg-safe-bg text-safe" : "border-border text-muted"}`}>
              {st.done && <Check className="size-3.5" aria-hidden />}
              {st.label}
            </span>
          </li>
        ))}
      </ol>

      <div className="grid grid-cols-2 gap-3 sm:grid-cols-3">
        <Stat label="Kolom PII terdeteksi" value={sm.pii_columns ?? "–"} sub={sm.columns ? `dari ${sm.columns} kolom` : "belum di-scan"} />
        <Stat
          label="Recall (nama kolom diabaikan)"
          value={sm.recall_content_only !== undefined ? sm.recall_content_only.toFixed(2) : "–"}
          sub={sm.precision_content_only !== undefined ? `presisi ${sm.precision_content_only.toFixed(2)}` : "vs acuan kontrak"}
        />
        {hardened ? (
          <Stat
            label="Nilai asli di dump nyata"
            value={sm.dump_found !== undefined ? `${sm.dump_found} / ${sm.dump_sampled}` : "–"}
            sub="dump tanpa kunci"
            tone={sm.dump_found === 0 ? "safe" : "leak"}
          />
        ) : (
          <Stat label="Data at rest" value="plaintext" sub="belum dilindungi" tone="leak" />
        )}
      </div>

      {hardened && sm.controls_total !== undefined && (
        <p className="mt-3 text-xs text-muted">{sm.controls_tested} dari {sm.controls_total} kontrol berlabel [TESTED] di apply_report_{t.target}.json</p>
      )}

      {t.next_step && (
        <Link
          to={STEP_LINK[t.next_step]}
          className="mt-4 inline-flex items-center gap-1.5 rounded-lg bg-accent px-3 py-1.5 text-sm font-semibold text-bg"
        >
          Langkah berikutnya: {steps.find((x) => x.key === t.next_step)?.label}
          <ArrowRight className="size-4" aria-hidden />
        </Link>
      )}
    </Card>
  );
}

function label(r: RedcheckResult) {
  const target = r.target ? r.target.replace(/^https?:\/\//, "") : r.file;
  return { target, mode: r.mode ?? "?" };
}

function Scoreboard({ data }: { data: Status["redcheck"] }) {
  // before -> after: vuln columns first, then hardened, each grouped by target
  const order = (m?: string) => (m === "vuln" ? 0 : m === "hardened" ? 1 : 2);
  const valid = data.results
    .filter((r) => r.valid)
    .sort((x, y) => order(x.mode) - order(y.mode) || (x.target ?? "").localeCompare(y.target ?? ""));
  const invalid = data.results.filter((r) => !r.valid);
  const keys = Array.from(new Set(valid.flatMap((r) => Object.keys(r.scoreboard ?? {}))));
  return (
    <Card title="Leak scoreboard" icon={<Target className="size-5 text-accent" aria-hidden />} actions={<span className="text-xs text-muted">sumber: out/redcheck_*.json (RedCheck)</span>}>
      {!data.available ? (
        <Empty>
          Belum ada data RedCheck. Scoreboard muncul setelah RedCheck menulis <code className="font-mono">out/redcheck_&lt;mode&gt;.json</code>;
          konsol tidak menampilkan angka karangan.
        </Empty>
      ) : (
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <caption className="sr-only">Jumlah nilai PII mentah yang berhasil dibaca penyerang per kategori</caption>
            <thead>
              <tr className="border-b border-border text-left text-xs text-muted">
                <th scope="col" className="py-2 pr-4 font-medium">Field PII mentah terbaca</th>
                {valid.map((r) => {
                  const l = label(r);
                  return (
                    <th key={r.file} scope="col" className="px-3 py-2 text-right font-medium">
                      <div className="font-mono">{l.target}</div>
                      <Badge tone={l.mode === "hardened" ? "safe" : "leak"}>{l.mode}</Badge>
                    </th>
                  );
                })}
              </tr>
            </thead>
            <tbody>
              {keys.map((k) => (
                <tr key={k} className="border-b border-border/60">
                  <th scope="row" className="py-2 pr-4 text-left font-medium">{k}</th>
                  {valid.map((r) => {
                    const v = r.scoreboard?.[k];
                    return (
                      <td key={r.file} className={`px-3 py-2 text-right text-lg font-bold tabular-nums ${v === undefined ? "text-muted" : v > 0 ? "text-leak" : "text-safe"}`}>
                        {v === undefined ? "–" : v.toLocaleString("id-ID")}
                      </td>
                    );
                  })}
                </tr>
              ))}
              <tr>
                <th scope="row" className="py-2 pr-4 text-left text-xs font-medium text-muted">Temuan gagal / total</th>
                {valid.map((r) => (
                  <td key={r.file} className="px-3 py-2 text-right text-xs text-muted tabular-nums">{r.failed} / {r.findings}</td>
                ))}
              </tr>
            </tbody>
          </table>
        </div>
      )}
      {invalid.length > 0 && (
        <p className="mt-3 text-xs text-warn">Tidak sesuai skema kontrak, diabaikan: {invalid.map((r) => r.file).join(", ")}</p>
      )}
    </Card>
  );
}

function Services({ services }: { services: Record<string, boolean> }) {
  return (
    <Card title="Layanan" icon={<Server className="size-5 text-accent" aria-hidden />} actions={<span className="text-xs text-muted">port di 127.0.0.1</span>}>
      <ul className="flex flex-wrap gap-2">
        {Object.entries(services).map(([k, up]) => (
          <li key={k} className={`inline-flex items-center gap-2 rounded-lg border px-3 py-1.5 text-sm ${up ? "border-safe/40 text-text" : "border-border text-muted"}`}>
            <Activity className={`size-3.5 ${up ? "text-safe" : "text-muted"}`} aria-hidden />
            {SERVICE_LABELS[k] ?? k}
            <span className={`text-xs ${up ? "text-safe" : "text-muted"}`}>{up ? "aktif" : "mati"}</span>
          </li>
        ))}
      </ul>
    </Card>
  );
}

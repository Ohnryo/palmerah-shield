import { useQuery } from "@tanstack/react-query";
import { FileDiff } from "lucide-react";
import { getPatches } from "../lib/api";
import { Badge, Card, Empty } from "../components/ui";
import { TargetTabs, useTarget } from "../components/TargetTabs";

export function Patch() {
  const [target, setTarget] = useTarget();
  const q = useQuery({ queryKey: ["patches", target], queryFn: () => getPatches(target) });
  return (
    <div className="mx-auto max-w-7xl space-y-6">
      <header className="flex flex-wrap items-end justify-between gap-3">
        <div>
          <h1 className="text-2xl font-bold">Patch</h1>
          <p className="text-sm text-muted">Saran perubahan kode aplikasi. Shield tidak pernah mengubah kode web; semuanya <strong>needs human review</strong>.</p>
        </div>
        <TargetTabs value={target} onChange={setTarget} />
      </header>
      {q.isPending && <p className="text-muted">Memuat…</p>}
      {q.isError && <p role="alert" className="text-leak">{q.error.message}</p>}
      {q.data && !q.data.files.length && (
        <Empty>Belum ada patch untuk website {target.toUpperCase()}. Dibuat otomatis oleh apply; diff prepared statement butuh <code className="font-mono">shield patch -t {target} --app-src &lt;kode web&gt;</code>.</Empty>
      )}
      {q.data?.files.filter((f) => f.kind !== "json").map((f) => (
        <Card key={f.name} title={<span className="font-mono">{f.name}</span>} icon={<FileDiff className="size-5 text-accent" aria-hidden />} actions={<Badge tone="warn">needs human review</Badge>}>
          <pre className={`max-h-[32rem] overflow-auto rounded-lg bg-surface-2 p-3 font-mono text-xs leading-relaxed ${f.kind === "md" ? "whitespace-pre-wrap break-words" : ""}`}>
            {f.kind === "diff"
              ? f.text.split("\n").map((l, i) => (
                  <span key={i} className={`block ${l.startsWith("+") && !l.startsWith("+++") ? "text-safe" : l.startsWith("-") && !l.startsWith("---") ? "text-leak" : l.startsWith("@@") ? "text-accent" : ""}`}>{l || " "}</span>
                ))
              : f.text}
          </pre>
        </Card>
      ))}
      {q.data && q.data.files.length > 0 && <p className="text-xs text-muted">Sumber: <code className="font-mono">{q.data.dir}</code></p>}
    </div>
  );
}

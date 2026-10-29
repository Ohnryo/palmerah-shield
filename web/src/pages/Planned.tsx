import { Evidence, Card } from "../components/ui";

/** Pages not built yet: say so honestly, with what they will show and which phase builds them. */
export function Planned({ title, phase, items, cli }: { title: string; phase: string; items: string[]; cli?: string }) {
  return (
    <div className="mx-auto max-w-3xl space-y-4">
      <h1 className="flex items-center gap-3 text-2xl font-bold">
        {title} <Evidence status="PLANNED" />
      </h1>
      <Card>
        <p className="mb-3 text-sm text-muted">Halaman ini dikerjakan di fase <strong className="text-text">{phase}</strong>. Isinya nanti:</p>
        <ul className="list-disc space-y-1 pl-5 text-sm">
          {items.map((i) => (
            <li key={i}>{i}</li>
          ))}
        </ul>
        {cli && (
          <p className="mt-4 text-sm text-muted">
            Sampai halaman ini selesai, fiturnya tersedia di CLI: <code className="rounded bg-surface-2 px-1.5 py-0.5 font-mono text-text">{cli}</code>
          </p>
        )}
      </Card>
    </div>
  );
}

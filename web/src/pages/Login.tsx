import { useState, type FormEvent } from "react";
import { KeyRound, ShieldCheck } from "lucide-react";
import { login } from "../lib/api";

export function Login({ onDone }: { onDone: () => void }) {
  const [token, setToken] = useState("");
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);

  async function submit(e: FormEvent) {
    e.preventDefault();
    setBusy(true);
    setError("");
    try {
      await login(token);
      onDone();
    } catch (err) {
      setError(err instanceof Error ? err.message : "gagal");
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="flex min-h-screen items-center justify-center p-4">
      <form onSubmit={submit} className="w-full max-w-sm rounded-xl border border-border bg-surface p-6">
        <div className="mb-5 flex items-center gap-2">
          <ShieldCheck className="size-7 text-accent" aria-hidden />
          <div>
            <h1 className="text-lg font-bold">Palmerah Shield Console</h1>
            <p className="text-xs text-muted">Hanya 127.0.0.1 · HTTPS TLS 1.3</p>
          </div>
        </div>
        <label htmlFor="token" className="mb-1 block text-sm font-medium">
          Token login
        </label>
        <p className="mb-2 text-xs text-muted">Dicetak di terminal saat <code className="font-mono">shield console</code> dijalankan.</p>
        <input
          id="token"
          type="password"
          autoComplete="off"
          autoFocus
          value={token}
          onChange={(e) => setToken(e.target.value)}
          className="w-full rounded-lg border border-border bg-surface-2 px-3 py-2 font-mono text-sm"
        />
        {error && <p role="alert" className="mt-2 text-sm text-leak">{error}</p>}
        <button
          type="submit"
          disabled={busy || !token}
          className="mt-4 flex w-full items-center justify-center gap-2 rounded-lg bg-accent px-3 py-2 text-sm font-semibold text-bg disabled:opacity-50"
        >
          <KeyRound className="size-4" aria-hidden />
          Masuk
        </button>
      </form>
    </div>
  );
}

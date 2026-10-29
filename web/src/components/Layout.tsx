import { NavLink, Outlet } from "react-router";
import {
  ClipboardList, FileCheck2, FileDiff, Gauge, Home, KeyRound, LogOut, Monitor, Moon, ScanSearch, ShieldCheck, Sun,
} from "lucide-react";
import { usePref } from "../lib/prefs";

export const PAGES = [
  { path: "/", label: "Beranda", icon: Home, step: "Langkah 2–3" },
  { path: "/scan", label: "Scan", icon: ScanSearch, step: "Langkah 4" },
  { path: "/rencana", label: "Rencana", icon: ClipboardList, step: "Langkah 4" },
  { path: "/terapkan", label: "Terapkan", icon: ShieldCheck, step: "Langkah 4" },
  { path: "/bukti", label: "Bukti", icon: FileCheck2, step: "Langkah 5" },
  { path: "/kinerja", label: "Kinerja", icon: Gauge, step: "Tanya jawab" },
  { path: "/kunci-audit", label: "Kunci & Audit", icon: KeyRound, step: "Tanya jawab" },
  { path: "/patch", label: "Patch", icon: FileDiff, step: "Tanya jawab" },
] as const;

export function Layout({ onLogout }: { onLogout: () => void }) {
  const [theme, setTheme] = usePref("theme", "dark", "data-theme");
  const [present, setPresent] = usePref("present", "0", "data-present");
  return (
    <div className="flex min-h-screen">
      <aside className="sticky top-0 flex h-screen w-60 shrink-0 flex-col border-r border-border bg-surface">
        <div className="flex items-center gap-2 px-5 py-5">
          <ShieldCheck className="size-6 text-accent" aria-hidden />
          <div>
            <div className="text-sm font-bold leading-tight">Palmerah Shield</div>
            <div className="text-xs text-muted">Console</div>
          </div>
        </div>
        <nav className="flex-1 space-y-0.5 px-3" aria-label="Halaman">
          {PAGES.map((p, i) => (
            <NavLink
              key={p.path}
              to={p.path}
              end={p.path === "/"}
              className={({ isActive }) =>
                `flex items-center gap-3 rounded-lg px-3 py-2 text-sm ${isActive ? "bg-surface-2 font-semibold text-text" : "text-muted hover:bg-surface-2 hover:text-text"}`
              }
            >
              <span className="w-4 text-right text-xs tabular-nums text-muted">{i + 1}</span>
              <p.icon className="size-4" aria-hidden />
              {p.label}
            </NavLink>
          ))}
        </nav>
        <div className="space-y-1 border-t border-border p-3 text-sm">
          <button
            type="button"
            onClick={() => setTheme(theme === "dark" ? "light" : "dark")}
            className="flex w-full items-center gap-2 rounded-lg px-3 py-2 text-muted hover:bg-surface-2 hover:text-text"
          >
            {theme === "dark" ? <Sun className="size-4" aria-hidden /> : <Moon className="size-4" aria-hidden />}
            Tema {theme === "dark" ? "terang" : "gelap"}
          </button>
          <button
            type="button"
            aria-pressed={present === "1"}
            onClick={() => setPresent(present === "1" ? "0" : "1")}
            className={`flex w-full items-center gap-2 rounded-lg px-3 py-2 hover:bg-surface-2 ${present === "1" ? "text-accent" : "text-muted hover:text-text"}`}
          >
            <Monitor className="size-4" aria-hidden />
            Mode Presentasi
          </button>
          <button
            type="button"
            onClick={onLogout}
            className="flex w-full items-center gap-2 rounded-lg px-3 py-2 text-muted hover:bg-surface-2 hover:text-text"
          >
            <LogOut className="size-4" aria-hidden />
            Keluar
          </button>
        </div>
      </aside>
      <main className="min-w-0 flex-1 p-6 lg:p-8">
        <Outlet />
      </main>
    </div>
  );
}

// Per-viewer display preferences (theme, presentation mode). Storage may be unavailable: never required.
import { useEffect, useState } from "react";

function read(key: string, fallback: string): string {
  try {
    return localStorage.getItem(key) ?? fallback;
  } catch {
    return fallback;
  }
}

function write(key: string, value: string): void {
  try {
    localStorage.setItem(key, value);
  } catch {
    /* ignore */
  }
}

export function usePref(key: "theme" | "present", fallback: string, attr: string) {
  const [value, setValue] = useState(() => read(`palmerah.${key}`, fallback));
  useEffect(() => {
    document.documentElement.setAttribute(attr, value);
    write(`palmerah.${key}`, value);
  }, [key, attr, value]);
  return [value, setValue] as const;
}

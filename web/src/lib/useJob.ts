import { useCallback, useState } from "react";
import { useQueryClient } from "@tanstack/react-query";
import { getJob, startJob, watchJob, type Job, type JobEvent, type Op, type Target } from "./api";

/** Run one console job and follow its progress live. Refreshes status and out/ files when it ends. */
export function useJob() {
  const qc = useQueryClient();
  const [events, setEvents] = useState<JobEvent[]>([]);
  const [job, setJob] = useState<Job | null>(null);
  const [error, setError] = useState("");
  const [running, setRunning] = useState(false);

  const run = useCallback(
    async (op: Op, target: Target | null, confirm?: string) => {
      setError("");
      setEvents([]);
      setJob(null);
      setRunning(true);
      try {
        const j = await startJob(op, target, confirm);
        await watchJob(j.id, (e) => setEvents((prev) => [...prev, e]));
        const done = await getJob(j.id);
        setJob(done);
        if (done.state === "failed") setError(done.error ?? "gagal");
      } catch (e) {
        setError(e instanceof Error ? e.message : "gagal");
      } finally {
        setRunning(false);
        await qc.invalidateQueries();
      }
    },
    [qc],
  );
  return { run, running, events, job, error };
}

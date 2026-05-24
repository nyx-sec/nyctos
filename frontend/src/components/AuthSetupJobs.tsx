import { useQueryClient } from "@tanstack/react-query";
import {
  createContext,
  type ReactNode,
  useCallback,
  useContext,
  useMemo,
  useRef,
  useState,
} from "react";
import {
  getAuthSetupJob,
  qk,
  startAuthAutoSetup,
  type AuthSetupJobRecord,
  type AuthSetupRequest,
} from "@/api/client";
import { useToast } from "@/components/Toast";

interface AuthSetupJobsContextValue {
  startAuthSetup: (projectId: string, body: AuthSetupRequest) => Promise<AuthSetupJobRecord>;
  jobForProject: (projectId: string | undefined) => AuthSetupJobRecord | undefined;
}

const noopContext: AuthSetupJobsContextValue = {
  startAuthSetup: async () => {
    throw new Error("Auth setup job provider is not mounted.");
  },
  jobForProject: () => undefined,
};

const AuthSetupJobsContext = createContext<AuthSetupJobsContextValue>(noopContext);

function isTerminal(job: AuthSetupJobRecord): boolean {
  return job.status === "succeeded" || job.status === "failed";
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => window.setTimeout(resolve, ms));
}

export function AuthSetupJobsProvider({ children }: { children: ReactNode }) {
  const qc = useQueryClient();
  const { showToast } = useToast();
  const [jobs, setJobs] = useState<Record<string, AuthSetupJobRecord>>({});
  const polling = useRef<Set<string>>(new Set());
  const completedToastIds = useRef<Set<string>>(new Set());

  const upsertJob = useCallback(
    (job: AuthSetupJobRecord) => {
      setJobs((current) => ({ ...current, [job.id]: job }));
      qc.setQueryData(qk.authSetupJob(job.project_id, job.id), job);
    },
    [qc],
  );

  const handleTerminalJob = useCallback(
    (job: AuthSetupJobRecord) => {
      if (completedToastIds.current.has(job.id)) return;
      completedToastIds.current.add(job.id);
      if (job.status === "succeeded" && job.result) {
        qc.setQueryData(qk.project(job.project_id), job.result.project);
        qc.invalidateQueries({ queryKey: qk.projects() });
        const warnings = job.result.verification.warnings.join(" ");
        showToast(warnings ? `${job.result.message} ${warnings}` : job.result.message, {
          tone: job.result.verification.status === "verified" ? "success" : "warning",
          durationMs: 7_000,
        });
        return;
      }
      if (job.status === "failed" && job.error) {
        const hint = job.error.hint ? ` ${job.error.hint}` : "";
        showToast(`${job.error.title}: ${job.error.detail}${hint}`, {
          tone: "danger",
          durationMs: 10_000,
        });
      }
    },
    [qc, showToast],
  );

  const pollJob = useCallback(
    async (projectId: string, jobId: string) => {
      if (polling.current.has(jobId)) return;
      polling.current.add(jobId);
      try {
        for (;;) {
          const job = await getAuthSetupJob(projectId, jobId);
          upsertJob(job);
          if (isTerminal(job)) {
            handleTerminalJob(job);
            return;
          }
          await sleep(1_250);
        }
      } catch (err) {
        showToast(`Could not read auth setup progress: ${err instanceof Error ? err.message : String(err)}`, {
          tone: "danger",
          durationMs: 8_000,
        });
      } finally {
        polling.current.delete(jobId);
      }
    },
    [handleTerminalJob, showToast, upsertJob],
  );

  const startAuthSetup = useCallback(
    async (projectId: string, body: AuthSetupRequest) => {
      const { job } = await startAuthAutoSetup(projectId, body);
      upsertJob(job);
      showToast("Auth setup started. You can keep working while the agent explores.", {
        tone: "info",
      });
      void pollJob(projectId, job.id);
      return job;
    },
    [pollJob, showToast, upsertJob],
  );

  const jobForProject = useCallback(
    (projectId: string | undefined) => {
      if (!projectId) return undefined;
      return Object.values(jobs)
        .filter((job) => job.project_id === projectId)
        .sort((a, b) => b.started_at - a.started_at)[0];
    },
    [jobs],
  );

  const value = useMemo(
    () => ({ startAuthSetup, jobForProject }),
    [jobForProject, startAuthSetup],
  );

  return (
    <AuthSetupJobsContext.Provider value={value}>{children}</AuthSetupJobsContext.Provider>
  );
}

export function useAuthSetupJobs(): AuthSetupJobsContextValue {
  return useContext(AuthSetupJobsContext);
}

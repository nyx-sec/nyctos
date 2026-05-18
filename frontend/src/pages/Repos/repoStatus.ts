import type { AgentEventLike } from "@/api/client";

/**
 * Per-repo live status derived from `RunEvent` frames pushed over
 * the WebSocket. `Idle` is the resting state surfaced by `RepoList`
 * when no Run event has named the repo since page load. The
 * `runId` field lets the UI link to the run currently driving the
 * repo (or `null` once the run finishes).
 */
export type RepoLiveStatus = "Idle" | "Running" | "Done" | "Failed";

export interface RepoLiveState {
  status: RepoLiveStatus;
  runId: string | null;
  message?: string;
}

/**
 * Fold a single agent event into the existing repo->state map.
 *
 *   RunStarted        → every named repo becomes Running
 *   RepoStarted       → that repo becomes Running
 *   RepoFinished      → outcome maps to Done / Failed
 *   RepoFailed        → that repo becomes Failed (message surfaced)
 *   RunFinished       → any still-Running repos roll to Idle (a Done/Failed
 *                       row from earlier in the same run stays as-is so the
 *                       operator can see the final state)
 */
export function applyEvent(
  prev: Record<string, RepoLiveState>,
  ev: AgentEventLike,
): Record<string, RepoLiveState> {
  if (!("kind" in ev) || ev.kind !== "Run") return prev;
  const data = ev.data;
  switch (data.kind) {
    case "RunStarted": {
      const next = { ...prev };
      for (const repo of data.repos) {
        next[repo] = { status: "Running", runId: data.run_id };
      }
      return next;
    }
    case "RepoStarted":
      return { ...prev, [data.repo]: { status: "Running", runId: data.run_id } };
    case "RepoFinished": {
      const status: RepoLiveStatus = data.outcome === "Success" ? "Done" : "Failed";
      return { ...prev, [data.repo]: { status, runId: data.run_id } };
    }
    case "RepoFailed":
      return {
        ...prev,
        [data.repo]: { status: "Failed", runId: data.run_id, message: data.message },
      };
    case "RunFinished": {
      const next: Record<string, RepoLiveState> = {};
      for (const [name, state] of Object.entries(prev)) {
        if (state.runId === data.run_id && state.status === "Running") {
          next[name] = { ...state, status: "Idle", runId: null };
        } else {
          next[name] = state;
        }
      }
      return next;
    }
    default:
      return prev;
  }
}

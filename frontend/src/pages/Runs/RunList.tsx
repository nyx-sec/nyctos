import { useMemo } from "react";
import { Link } from "react-router-dom";
import { type RunRecord, useRuns } from "@/api/client";
import { Badge, type BadgeTone } from "@/components/Badge";
import { Card } from "@/components/Card";
import { EmptyState } from "@/components/EmptyState";
import { Spinner } from "@/components/Spinner";

const STATUS_TONE: Record<string, BadgeTone> = {
  Running: "info",
  Succeeded: "success",
  Failed: "danger",
};

export function RunList() {
  const running = useRuns("Running");
  const succeeded = useRuns("Succeeded");
  const failed = useRuns("Failed");
  const rows = useMemo(() => {
    const seen = new Set<string>();
    return [...(running.data ?? []), ...(succeeded.data ?? []), ...(failed.data ?? [])]
      .filter((run) => {
        if (seen.has(run.id)) return false;
        seen.add(run.id);
        return true;
      })
      .sort((a, b) => b.started_at - a.started_at);
  }, [running.data, succeeded.data, failed.data]);
  const pending = running.isPending || succeeded.isPending || failed.isPending;
  const error = running.error ?? succeeded.error ?? failed.error;

  return (
    <Card
      title="Pentest runs"
      subtitle="Project-scoped pentests with live environment and verification status"
    >
      {pending && (
        <div className="repo-list__pending">
          <Spinner /> Loading runs...
        </div>
      )}
      {error && (
        <p className="repo-list__error" role="alert">
          Failed to load runs: {String(error)}
        </p>
      )}
      {!pending && rows.length === 0 && (
        <EmptyState
          title="No pentest runs"
          body="Start a pentest from a project after configuring its launch profile."
        />
      )}
      {rows.length > 0 && (
        <div className="table-scroll">
          <table className="repo-list__table" aria-label="Pentest runs">
            <thead>
              <tr>
                <th scope="col">Run</th>
                <th scope="col">Status</th>
                <th scope="col">Project</th>
                <th scope="col">Started</th>
                <th scope="col">Duration</th>
              </tr>
            </thead>
            <tbody>
              {rows.map((run) => (
                <RunRow key={run.id} run={run} />
              ))}
            </tbody>
          </table>
        </div>
      )}
    </Card>
  );
}

function RunRow({ run }: { run: RunRecord }) {
  return (
    <tr>
      <td>
        <Link className="repo-list__name" to={`/runs/${encodeURIComponent(run.id)}`}>
          {run.id}
        </Link>
        <span className="repo-list__meta"> {run.kind}</span>
      </td>
      <td>
        <Badge tone={STATUS_TONE[run.status] ?? "neutral"}>{run.status}</Badge>
      </td>
      <td>{run.project_id ? <code>{run.project_id}</code> : "-"}</td>
      <td>{formatTime(run.started_at)}</td>
      <td>{formatDuration(run.wall_clock_ms)}</td>
    </tr>
  );
}

function formatTime(epochSeconds: number) {
  return new Date(epochSeconds * 1000).toLocaleString();
}

function formatDuration(ms: number | null | undefined) {
  if (ms == null) return "-";
  if (ms < 1000) return `${ms}ms`;
  return `${(ms / 1000).toFixed(1)}s`;
}

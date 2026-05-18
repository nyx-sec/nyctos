import { useMemo, useState } from "react";
import { useNavigate } from "react-router-dom";
import { Badge, type BadgeTone } from "@/components/Badge";
import { Button } from "@/components/Button";
import { Card } from "@/components/Card";
import { EmptyState } from "@/components/EmptyState";
import { Spinner } from "@/components/Spinner";
import {
  useAgentEvents,
  useDeleteRepo,
  useRepos,
  useTriggerScan,
  type AgentEventLike,
  type RepoRecord,
} from "@/api/client";
import { RepoAddModal } from "./RepoAddModal";
import { applyEvent, type RepoLiveState, type RepoLiveStatus } from "./repoStatus";

type LiveMap = Record<string, RepoLiveState>;

const STATUS_TONE: Record<RepoLiveStatus, BadgeTone> = {
  Idle: "neutral",
  Running: "info",
  Done: "success",
  Failed: "danger",
};

export function RepoList() {
  const repos = useRepos();
  const triggerScan = useTriggerScan();
  const deleteRepo = useDeleteRepo();
  const navigate = useNavigate();
  const [live, setLive] = useState<LiveMap>({});
  const [banner, setBanner] = useState<string | null>(null);
  const [showAdd, setShowAdd] = useState(false);

  useAgentEvents({
    onEvent: (ev: AgentEventLike) => {
      setLive((cur) => applyEvent(cur, ev));
      surfaceRunBanner(ev, setBanner);
    },
  });

  async function onScanOne(name: string) {
    setBanner(`Triggering scan for ${name}…`);
    setLive((cur) => ({ ...cur, [name]: { status: "Running", runId: null } }));
    try {
      const { run_id } = await triggerScan.mutateAsync(name);
      setBanner(`Scan started for ${name} (run ${run_id}).`);
      navigate(`/runs/${encodeURIComponent(run_id)}`);
    } catch (err) {
      setBanner(`Scan for ${name} failed: ${String(err)}`);
      setLive((cur) => ({ ...cur, [name]: { status: "Failed", runId: null } }));
    }
  }

  async function onScanAll() {
    setBanner("Triggering scan across every configured repo…");
    try {
      const { run_id } = await triggerScan.mutateAsync(undefined);
      setBanner(`Scan started (run ${run_id}).`);
      navigate(`/runs/${encodeURIComponent(run_id)}`);
    } catch (err) {
      setBanner(`Scan-all failed: ${String(err)}`);
    }
  }

  async function onDelete(name: string) {
    if (!window.confirm(`Remove repo "${name}" and its workspace dir?`)) {
      return;
    }
    try {
      await deleteRepo.mutateAsync(name);
      setBanner(`Removed ${name}.`);
      setLive((cur) => {
        const next = { ...cur };
        delete next[name];
        return next;
      });
    } catch (err) {
      setBanner(`Could not remove ${name}: ${String(err)}`);
    }
  }

  const rows = useMemo(() => repos.data ?? [], [repos.data]);
  const noneConfigured = !repos.isPending && rows.length === 0;

  return (
    <>
      <Card
        title="Repositories"
        subtitle="Sources the agent scans. Add a git URL or a local checkout, then trigger a scan."
        actions={
          <div className="repo-list__actions">
            <Button
              variant="ghost"
              onClick={onScanAll}
              disabled={triggerScan.isPending || rows.length === 0}
            >
              Scan all
            </Button>
            <Button variant="primary" onClick={() => setShowAdd(true)}>
              Add repo
            </Button>
          </div>
        }
      >
        {banner && (
          <div className="repo-list__banner" role="status" aria-live="polite">
            {banner}
          </div>
        )}

        {repos.isPending && (
          <div className="repo-list__pending">
            <Spinner /> Loading repositories…
          </div>
        )}

        {repos.error && (
          <p className="repo-list__error" role="alert">
            Failed to load repositories: {String(repos.error)}
          </p>
        )}

        {noneConfigured && (
          <EmptyState
            title="No repositories yet"
            body="Add the first one to give the agent something to scan."
            actions={
              <Button variant="primary" onClick={() => setShowAdd(true)}>
                Add repo
              </Button>
            }
          />
        )}

        {rows.length > 0 && (
          <table className="repo-list__table" aria-label="Configured repositories">
            <thead>
              <tr>
                <th scope="col">Repo</th>
                <th scope="col">Kind</th>
                <th scope="col">Source</th>
                <th scope="col">Status</th>
                <th scope="col">Last scan</th>
                <th scope="col" className="repo-list__col--actions">
                  Actions
                </th>
              </tr>
            </thead>
            <tbody>
              {rows.map((repo) => (
                <RepoRow
                  key={repo.name}
                  repo={repo}
                  live={live[repo.name] ?? { status: "Idle", runId: null }}
                  onScan={() => onScanOne(repo.name)}
                  onDelete={() => onDelete(repo.name)}
                  busy={triggerScan.isPending || deleteRepo.isPending}
                />
              ))}
            </tbody>
          </table>
        )}
      </Card>

      {showAdd && (
        <RepoAddModal
          onClose={() => setShowAdd(false)}
          onAdded={(name) => {
            setShowAdd(false);
            setBanner(`Added ${name}. Trigger a scan when ready.`);
          }}
        />
      )}
    </>
  );
}

interface RepoRowProps {
  repo: RepoRecord;
  live: RepoLiveState;
  onScan: () => void;
  onDelete: () => void;
  busy: boolean;
}

function RepoRow({ repo, live, onScan, onDelete, busy }: RepoRowProps) {
  const kindTone: BadgeTone = repo.source_kind === "git" ? "info" : "accent";
  return (
    <tr>
      <td>
        <span className="repo-list__name">{repo.name}</span>
        {repo.branch && <span className="repo-list__meta"> · {repo.branch}</span>}
      </td>
      <td>
        <Badge tone={kindTone}>{repo.source_kind}</Badge>
      </td>
      <td className="repo-list__source" title={repo.source_url_or_path}>
        {repo.source_url_or_path}
      </td>
      <td>
        <Badge tone={STATUS_TONE[live.status]}>{live.status}</Badge>
        {live.message && (
          <span className="repo-list__status-detail" title={live.message}>
            {live.message}
          </span>
        )}
      </td>
      <td>
        <time className="repo-list__last-scan">{formatLastScan(repo)}</time>
      </td>
      <td className="repo-list__col--actions">
        <Button size="sm" onClick={onScan} disabled={busy || live.status === "Running"}>
          Scan now
        </Button>
        <Button size="sm" variant="danger" onClick={onDelete} disabled={busy}>
          Remove
        </Button>
      </td>
    </tr>
  );
}

function formatLastScan(repo: RepoRecord): string {
  if (!repo.last_scan_run_id) return "—";
  if (!repo.updated_at) return repo.last_scan_run_id;
  const date = new Date(repo.updated_at);
  return date.toLocaleString();
}

function surfaceRunBanner(
  ev: AgentEventLike,
  setBanner: (s: string | null) => void,
) {
  if (!("kind" in ev) || ev.kind !== "Run") return;
  const data = ev.data;
  if (data.kind === "RunFinished") {
    setBanner(
      `Run ${data.run_id} finished — ${data.succeeded} ok, ${data.inconclusive} inconclusive, ${data.failed} failed.`,
    );
  }
}

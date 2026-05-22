import { useMemo, useState } from "react";
import { Link, useNavigate, useParams } from "react-router-dom";
import {
  type AgentEventLike,
  type ProjectLaunchProfile,
  type RepoRecord,
  useAgentEvents,
  useDeleteProject,
  useDeleteProjectRepo,
  useProject,
  useProjectRepos,
  useProjectVulnerabilities,
  useStartPentest,
} from "@/api/client";
import { Badge, type BadgeTone } from "@/components/Badge";
import { Button } from "@/components/Button";
import { Card } from "@/components/Card";
import { ConfirmModal } from "@/components/ConfirmModal";
import { EmptyState } from "@/components/EmptyState";
import { Spinner } from "@/components/Spinner";
import { RepoAddModal } from "../Repos/RepoAddModal";
import { RepoEditModal } from "../Repos/RepoEditModal";
import { applyEvent, type RepoLiveState, type RepoLiveStatus } from "../Repos/repoStatus";
import { ProjectProfileModal } from "./ProjectProfileModal";

type LiveMap = Record<string, RepoLiveState>;

const STATUS_TONE: Record<RepoLiveStatus, BadgeTone> = {
  Idle: "neutral",
  Running: "info",
  Done: "success",
  Failed: "danger",
};

export function ProjectDetail() {
  const { projectId } = useParams<{ projectId: string }>();
  const navigate = useNavigate();
  const project = useProject(projectId);
  const repos = useProjectRepos(projectId);
  const startPentest = useStartPentest(projectId ?? "");
  const vulnerabilities = useProjectVulnerabilities(projectId);
  const deleteRepo = useDeleteProjectRepo(projectId ?? "");
  const deleteProject = useDeleteProject();
  const [live, setLive] = useState<LiveMap>({});
  const [banner, setBanner] = useState<string | null>(null);
  const [showAdd, setShowAdd] = useState(false);
  const [showProfileEdit, setShowProfileEdit] = useState(false);
  const [editTarget, setEditTarget] = useState<RepoRecord | null>(null);
  const [removeTarget, setRemoveTarget] = useState<RepoRecord | null>(null);

  useAgentEvents({
    onEvent: (ev: AgentEventLike) => {
      setLive((cur) => applyEvent(cur, ev));
      surfaceRunBanner(ev, setBanner);
    },
  });

  async function onStartPentest() {
    setBanner("Starting pentest for this app...");
    try {
      const { run_id } = await startPentest.mutateAsync();
      setBanner(`Pentest started (run ${run_id}).`);
      navigate(`/runs/${encodeURIComponent(run_id)}`);
    } catch (err) {
      setBanner(`Could not start pentest: ${String(err)}`);
    }
  }

  async function onConfirmRemoveRepo() {
    if (!removeTarget) return;
    const name = removeTarget.name;
    try {
      await deleteRepo.mutateAsync(name);
      setBanner(`Removed ${name}.`);
      setLive((cur) => {
        const next = { ...cur };
        delete next[name];
        return next;
      });
      setRemoveTarget(null);
    } catch (err) {
      setBanner(`Could not remove ${name}: ${String(err)}`);
      setRemoveTarget(null);
    }
  }

  async function onDeleteProject() {
    if (!project.data) return;
    if (
      !window.confirm(
        `Delete project "${project.data.name}"? All repos under it will be removed too.`,
      )
    ) {
      return;
    }
    try {
      await deleteProject.mutateAsync(project.data.id);
      navigate("/projects", { replace: true });
    } catch (err) {
      setBanner(`Could not delete project: ${String(err)}`);
    }
  }

  const rows = useMemo(() => repos.data ?? [], [repos.data]);
  const noneConfigured = !repos.isPending && rows.length === 0;

  if (!projectId) {
    return (
      <Card title="Project">
        <p>Missing project id.</p>
      </Card>
    );
  }

  if (project.isPending) {
    return (
      <Card>
        <div style={{ padding: 40, textAlign: "center" }}>
          <Spinner size="lg" />
        </div>
      </Card>
    );
  }

  if (project.error || !project.data) {
    return (
      <Card title="Project not found">
        <p>
          <Link to="/projects">← Back to projects</Link>
        </p>
      </Card>
    );
  }

  const p = project.data;
  const launchProfile = p.default_launch_profile;
  const runtimeTarget = launchProfile?.target_urls[0] ?? p.target_base_url;
  const runtimeStatus = launchProfileStatus(launchProfile);
  const canStartPentest = rows.length > 0 && launchProfile?.readiness === "Ready";
  const verifiedCount = vulnerabilities.data?.length ?? 0;

  return (
    <>
      <div className="page-stack">
        <Card
          className="project-summary"
          title={p.name}
          subtitle={p.description || undefined}
          actions={
            <div className="repo-list__actions">
              <Button variant="ghost" onClick={() => setShowProfileEdit(true)}>
                Edit launch profile
              </Button>
              <Button variant="ghost" onClick={onDeleteProject} disabled={deleteProject.isPending}>
                Delete project
              </Button>
            </div>
          }
        >
          <dl className="project-meta">
            <div>
              <dt>Project id</dt>
              <dd>
                <code>{p.id}</code>
              </dd>
            </div>
            <div>
              <dt>App URL</dt>
              <dd>{runtimeTarget ? <code>{runtimeTarget}</code> : "-"}</dd>
            </div>
            <div>
              <dt>Launch</dt>
              <dd>
                <Badge tone={runtimeStatus.tone}>{runtimeStatus.label}</Badge>
              </dd>
            </div>
            <div>
              <dt>Mode</dt>
              <dd>{formatLaunchMode(launchProfile)}</dd>
            </div>
            <div>
              <dt>Ready when</dt>
              <dd>{formatReadiness(launchProfile)}</dd>
            </div>
            <div>
              <dt>Verified vulnerabilities</dt>
              <dd>{verifiedCount}</dd>
            </div>
          </dl>
          <RuntimeProfileSummary profile={launchProfile} />
          <div className="project-primary-action">
            <Button
              variant="primary"
              onClick={onStartPentest}
              disabled={!canStartPentest || startPentest.isPending}
            >
              Start pentest
            </Button>
            {!canStartPentest && (
              <span className="project-primary-action__hint">
                Add an app URL and at least one repo.
              </span>
            )}
          </div>
        </Card>

        <Card
          title="Repositories"
          subtitle={`${rows.length} ${rows.length === 1 ? "repository" : "repositories"}`}
          actions={
            <div className="repo-list__actions">
              <Button variant="ghost" onClick={() => setShowProfileEdit(true)}>
                Launch profile
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
              <Spinner /> Loading repositories...
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
              body="Add a repo when this project is ready to scan."
            />
          )}

          {rows.length > 0 && (
            <div className="table-scroll">
              <table className="repo-list__table" aria-label="Configured repositories">
                <thead>
                  <tr>
                    <th scope="col">Repo</th>
                    <th scope="col">Kind</th>
                    <th scope="col">Source</th>
                    <th scope="col">Status</th>
                    <th scope="col">Last pentest</th>
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
                      onEdit={() => setEditTarget(repo)}
                      onDelete={() => setRemoveTarget(repo)}
                      busy={startPentest.isPending || deleteRepo.isPending}
                    />
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </Card>
      </div>

      {showAdd && (
        <RepoAddModal
          projectId={projectId}
          onClose={() => setShowAdd(false)}
          onAdded={(name) => {
            setShowAdd(false);
            setBanner(`Added ${name}. Start a pentest when ready.`);
          }}
        />
      )}

      {editTarget && (
        <RepoEditModal
          projectId={projectId}
          repo={editTarget}
          onClose={() => setEditTarget(null)}
          onSaved={(next) => {
            setEditTarget(null);
            setBanner(`Saved changes to ${next.name}.`);
          }}
        />
      )}

      {showProfileEdit && (
        <ProjectProfileModal
          project={p}
          onClose={() => setShowProfileEdit(false)}
          onSaved={(next) => {
            setShowProfileEdit(false);
            setBanner(`Saved launch profile for ${next.name}.`);
          }}
        />
      )}

      {removeTarget && (
        <ConfirmModal
          title={`Remove "${removeTarget.name}"?`}
          body={
            <>
              <p>
                The daemon will delete the workspace directory for this repo and forget the
                connection. Findings and run history under it are retained.
              </p>
              <p className="repo-list__source">
                Source: <code>{removeTarget.source_url_or_path}</code>
              </p>
            </>
          }
          confirmLabel="Remove repo"
          confirmVariant="danger"
          busy={deleteRepo.isPending}
          onConfirm={onConfirmRemoveRepo}
          onCancel={() => setRemoveTarget(null)}
        />
      )}
    </>
  );
}

function RuntimeProfileSummary({ profile }: { profile: ProjectLaunchProfile | null }) {
  if (!profile) return null;
  return (
    <div className="runtime-profile-summary">
      <div>
        <h3>Setup</h3>
        <p>{formatSetup(profile)}</p>
      </div>
      <CommandSummary title="Start" commands={profile.start_steps} />
      <div>
        <h3>Environment</h3>
        <p>{formatEnvironment(profile)}</p>
      </div>
    </div>
  );
}

function CommandSummary({
  title,
  commands,
}: {
  title: string;
  commands: ProjectLaunchProfile["build_steps"];
}) {
  if (commands.length === 0) {
    return (
      <div>
        <h3>{title}</h3>
        <p>No start commands</p>
      </div>
    );
  }
  return (
    <div>
      <h3>{title}</h3>
      <ul className="runtime-profile-command-list">
        {commands.map((cmd, index) => (
          <li key={`${title}-${index}`}>
            <code>{cmd.command}</code>
            {cmd.repo_name && <span>{cmd.repo_name}</span>}
            {cmd.working_directory && <span>{cmd.working_directory}</span>}
          </li>
        ))}
      </ul>
    </div>
  );
}

function launchProfileStatus(profile: ProjectLaunchProfile | null): {
  label: string;
  tone: BadgeTone;
} {
  if (!profile) return { label: "Not configured", tone: "neutral" };
  if (profile.readiness === "Ready") return { label: "Ready", tone: "success" };
  if (profile.readiness === "NeedsTarget") return { label: "Needs app URL", tone: "info" };
  return { label: "Needs attention", tone: "neutral" };
}

function formatLaunchMode(profile: ProjectLaunchProfile | null): string {
  if (!profile) return "-";
  if (profile.mode === "already-running") return "Already running";
  if (profile.mode === "docker-compose") return "Docker Compose";
  return "Start from project";
}

function formatReadiness(profile: ProjectLaunchProfile | null): string {
  if (!profile) return "-";
  const check = profile.health_checks[0];
  if (check?.command) return check.command.command;
  if (check?.url && profile.target_urls[0] && check.url === profile.target_urls[0]) {
    return "App URL responds";
  }
  if (check?.url) return check.url;
  return "No readiness check";
}

function formatSetup(profile: ProjectLaunchProfile): string {
  if (profile.build_steps.length === 0) return "No setup commands";
  return `${profile.build_steps.length} ${profile.build_steps.length === 1 ? "command" : "commands"}`;
}

function formatEnvironment(profile: ProjectLaunchProfile): string {
  const parts: string[] = [];
  if (profile.env_refs.length > 0) {
    const names = profile.env_refs.map((entry) =>
      entry.secret ? `${entry.value} (secret)` : entry.value,
    );
    parts.push(names.join(", "));
  }
  return parts.length > 0 ? parts.join(" · ") : "-";
}

interface RepoRowProps {
  repo: RepoRecord;
  live: RepoLiveState;
  onEdit: () => void;
  onDelete: () => void;
  busy: boolean;
}

function RepoRow({ repo, live, onEdit, onDelete, busy }: RepoRowProps) {
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
        <Button size="sm" variant="ghost" onClick={onEdit} disabled={busy}>
          Edit
        </Button>
        <Button size="sm" variant="danger" onClick={onDelete} disabled={busy}>
          Remove
        </Button>
      </td>
    </tr>
  );
}

function formatLastScan(repo: RepoRecord): string {
  if (!repo.last_scan_run_id) return "-";
  if (repo.last_scan_finished_at) {
    return new Date(repo.last_scan_finished_at).toLocaleString();
  }
  // Pointer set but no joined finished_at: run is still in flight, or
  // the run row was swept by retention. Surface the id so the operator
  // can still navigate to it.
  return repo.last_scan_run_id;
}

function surfaceRunBanner(ev: AgentEventLike, setBanner: (s: string | null) => void) {
  if (!("kind" in ev) || ev.kind !== "Run") return;
  const data = ev.data;
  if (data.kind === "RunFinished") {
    setBanner(
      `Run ${data.run_id} finished: ${data.succeeded} ok, ${data.inconclusive} inconclusive, ${data.failed} failed.`,
    );
  }
}

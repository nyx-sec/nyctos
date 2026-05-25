import { type FocusEvent, useCallback, useEffect, useMemo, useRef, useState } from "react";
import { Link, useNavigate, useParams } from "react-router-dom";
import {
  type AgentEventLike,
  type ProjectIntegrationRecord,
  type ProjectLaunchProfile,
  type ProjectRecord,
  type RepoRecord,
  type RunRecord,
  useAgentEvents,
  useDeleteProject,
  useDeleteProjectRepo,
  usePatchDefaultLaunchProfile,
  usePatchProject,
  useProject,
  useProjectIntegrations,
  useProjectRepos,
  useProjectVulnerabilities,
  useRuns,
  useStartPentest,
  type VerifiedVulnerabilityRecord,
} from "@/api/client";
import { Badge, type BadgeTone } from "@/components/Badge";
import { Button } from "@/components/Button";
import { Card } from "@/components/Card";
import { ConfirmModal } from "@/components/ConfirmModal";
import { EmptyState } from "@/components/EmptyState";
import { PageHeader, PageShell } from "@/components/Page";
import { Spinner } from "@/components/Spinner";
import { type ToastOptions, useToast } from "@/components/Toast";
import { RepoAddModal } from "../Repos/RepoAddModal";
import { RepoEditModal } from "../Repos/RepoEditModal";
import { applyEvent, type RepoLiveState, type RepoLiveStatus } from "../Repos/repoStatus";
import {
  launchProfileDraftError,
  launchProfileFromDraft,
  launchProfileToDraft,
  ProjectRuntimeProfileForm,
  type RuntimeProfileDraft,
  runtimeProfileFromDraft,
  runtimeProfileToDraft,
} from "./ProjectRuntimeProfileForm";

type LiveMap = Record<string, RepoLiveState>;
type ProjectDetailView = "overview" | "repos" | "environments";
type LiveRunEvent = Extract<AgentEventLike, { kind: "Run" }>["data"];

interface ProjectDetailProps {
  view?: ProjectDetailView;
}

interface ProjectOverviewProps {
  projectPath: string;
  target: string | null;
  repos: RepoRecord[];
  repoCountLabel: string;
  vulnerabilities: VerifiedVulnerabilityRecord[];
  integrations: ProjectIntegrationRecord[];
  runs: RunRecord[];
  activeRun: RunRecord | null;
  runEvents: LiveRunEvent[];
  live: LiveMap;
  launchProfile: ProjectLaunchProfile | null;
  canStartPentest: boolean;
  startPentestPending: boolean;
  runsPending: boolean;
  reposPending: boolean;
  vulnerabilitiesPending: boolean;
  integrationsPending: boolean;
  onStartPentest: () => void;
}

const STATUS_TONE: Record<RepoLiveStatus, BadgeTone> = {
  Idle: "neutral",
  Running: "info",
  Done: "success",
  Failed: "danger",
};

export function ProjectDetail({ view = "overview" }: ProjectDetailProps = {}) {
  const { projectId } = useParams<{ projectId: string }>();
  const navigate = useNavigate();
  const project = useProject(projectId);
  const repos = useProjectRepos(projectId);
  const startPentest = useStartPentest(projectId ?? "");
  const vulnerabilities = useProjectVulnerabilities(projectId);
  const integrations = useProjectIntegrations(projectId);
  const runningRuns = useRuns("Running", projectId, Boolean(projectId));
  const succeededRuns = useRuns("Succeeded", projectId, Boolean(projectId));
  const failedRuns = useRuns("Failed", projectId, Boolean(projectId));
  const deleteRepo = useDeleteProjectRepo(projectId ?? "");
  const deleteProject = useDeleteProject();
  const { showToast } = useToast();
  const [live, setLive] = useState<LiveMap>({});
  const [runEvents, setRunEvents] = useState<LiveRunEvent[]>([]);
  const [showAdd, setShowAdd] = useState(false);
  const [showPentestOptions, setShowPentestOptions] = useState(false);
  const [editTarget, setEditTarget] = useState<RepoRecord | null>(null);
  const [removeTarget, setRemoveTarget] = useState<RepoRecord | null>(null);

  useAgentEvents({
    onEvent: (ev: AgentEventLike) => {
      setLive((cur) => applyEvent(cur, ev));
      if (ev.kind === "Run" && runEventBelongsToProject(ev.data, projectId)) {
        setRunEvents((cur) => [ev.data, ...cur].slice(0, 12));
      }
      surfaceRunToast(ev, showToast);
    },
  });

  async function onStartPentest(options: StartPentestOptions) {
    showToast("Starting pentest for this app...", { tone: "info" });
    try {
      const { run_id } = await startPentest.mutateAsync({
        exploit_mode_enabled: options.exploitMode,
        allow_state_changing_live_probes: options.allowStateChanging,
        browser_checks_enabled: options.browserChecks,
        research_mode_enabled: options.researchMode,
        unsafe_attack_agent_enabled: options.unsafeAttackAgent,
        business_logic_template_ids: [],
      });
      showToast(`Pentest started (run ${run_id}).`, { tone: "success" });
      setShowPentestOptions(false);
      navigate(
        projectId
          ? `/projects/${encodeURIComponent(projectId)}/runs/${encodeURIComponent(run_id)}`
          : `/runs/${encodeURIComponent(run_id)}`,
      );
    } catch (err) {
      showToast(`Could not start pentest: ${String(err)}`, { tone: "danger" });
    }
  }

  async function onConfirmRemoveRepo() {
    if (!removeTarget) return;
    const name = removeTarget.name;
    try {
      await deleteRepo.mutateAsync(name);
      showToast(`Removed ${name}.`, { tone: "success" });
      setLive((cur) => {
        const next = { ...cur };
        delete next[name];
        return next;
      });
      setRemoveTarget(null);
    } catch (err) {
      showToast(`Could not remove ${name}: ${String(err)}`, { tone: "danger" });
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
      showToast(`Could not delete project: ${String(err)}`, { tone: "danger" });
    }
  }

  const rows = useMemo(() => repos.data ?? [], [repos.data]);
  const integrationRows = useMemo(() => integrations.data ?? [], [integrations.data]);
  const runRows = useMemo(
    () => mergeRuns(runningRuns.data, succeededRuns.data, failedRuns.data),
    [runningRuns.data, succeededRuns.data, failedRuns.data],
  );
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
  const verifiedRows = vulnerabilities.data ?? [];
  const repoCountLabel = formatRepoCount(rows.length);
  const activeRun = runRows.find((run) => run.status === "Running") ?? null;
  const encodedProjectId = encodeURIComponent(projectId);

  return (
    <>
      <PageShell size="wide" className="project-detail">
        {view === "overview" && (
          <PageHeader
            title={p.name}
            meta={
              <span className="project-header-meta">
                {p.description?.trim() && <span>{p.description.trim()}</span>}
                {runtimeTarget && <code title={runtimeTarget}>{runtimeTarget}</code>}
                <Badge tone={runtimeStatus.tone}>{runtimeStatus.label}</Badge>
                <span>{formatLaunchMode(launchProfile)}</span>
                {activeRun && <Badge tone="info">Running</Badge>}
              </span>
            }
            actions={
              <>
                <Button
                  variant="primary"
                  onClick={() => setShowPentestOptions(true)}
                  disabled={!canStartPentest || startPentest.isPending}
                >
                  {startPentest.isPending ? "Starting..." : "Start pentest"}
                </Button>
                <Button
                  className="project-summary__delete"
                  variant="ghost"
                  onClick={onDeleteProject}
                  disabled={deleteProject.isPending}
                >
                  Delete project
                </Button>
              </>
            }
          />
        )}

        {view === "repos" && (
          <PageHeader
            title="Repositories"
            meta={repoCountLabel}
            actions={
              <Button variant="primary" onClick={() => setShowAdd(true)}>
                Add repo
              </Button>
            }
          />
        )}

        {view === "environments" && (
          <PageHeader
            title="Environments"
            meta={`${runtimeStatus.label} · ${formatLaunchMode(launchProfile)}`}
          />
        )}

        {view === "overview" && (
          <ProjectOverview
            projectPath={`/projects/${encodedProjectId}`}
            target={runtimeTarget}
            repos={rows}
            repoCountLabel={repoCountLabel}
            vulnerabilities={verifiedRows}
            integrations={integrationRows}
            runs={runRows}
            activeRun={activeRun}
            runEvents={runEvents}
            live={live}
            launchProfile={launchProfile}
            canStartPentest={canStartPentest}
            startPentestPending={startPentest.isPending}
            runsPending={runningRuns.isPending || succeededRuns.isPending || failedRuns.isPending}
            reposPending={repos.isPending}
            vulnerabilitiesPending={vulnerabilities.isPending}
            integrationsPending={integrations.isPending}
            onStartPentest={() => setShowPentestOptions(true)}
          />
        )}

        {view === "repos" && (
          <Card className="table-card">
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
                body="Add one source repo to start scanning this project."
              />
            )}

            {rows.length > 0 && (
              <div className="table-scroll">
                <table className="repo-list__table data-table" aria-label="Configured repositories">
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
        )}

        {view === "environments" && <EnvironmentEditor project={p} />}
      </PageShell>

      {showAdd && (
        <RepoAddModal
          projectId={projectId}
          onClose={() => setShowAdd(false)}
          onAdded={(name) => {
            setShowAdd(false);
            showToast(`Added ${name}. Start a pentest when ready.`, { tone: "success" });
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
            showToast(`Saved changes to ${next.name}.`, { tone: "success" });
          }}
        />
      )}

      {showPentestOptions && (
        <StartPentestModal
          busy={startPentest.isPending}
          onConfirm={onStartPentest}
          onCancel={() => setShowPentestOptions(false)}
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

function ProjectOverview({
  projectPath,
  target,
  repos,
  repoCountLabel,
  vulnerabilities,
  integrations,
  runs,
  activeRun,
  runEvents,
  live,
  launchProfile,
  canStartPentest,
  startPentestPending,
  runsPending,
  reposPending,
  vulnerabilitiesPending,
  integrationsPending,
  onStartPentest,
}: ProjectOverviewProps) {
  const environmentStatus = launchProfileStatus(launchProfile);
  const verifiedCount = vulnerabilities.length;
  const severityCounts = countSeverities(vulnerabilities);
  const highestRisk = highestRiskVulnerability(vulnerabilities);
  const readiness = readinessChecks(projectPath, target, repos.length, launchProfile);
  const activeRunEvent = activeRun
    ? (runEvents.find((event) => runIdForEvent(event) === activeRun.id) ?? null)
    : null;
  const activity = buildProjectActivity({
    projectPath,
    runEvents,
    runs,
    repos,
    vulnerabilities,
    integrations,
  });
  const enabledIntegrations = integrations.filter((integration) => integration.enabled).length;
  const activeRepoStates = Object.values(live).filter((state) => state.status !== "Idle");

  return (
    <div className="project-overview">
      <div className="project-overview__top">
        <section className="project-overview__panel project-overview__panel--run">
          {activeRun ? (
            <CurrentRunPanel
              projectPath={projectPath}
              run={activeRun}
              event={activeRunEvent}
              target={target}
              activeRepoStates={activeRepoStates}
              verifiedThisRun={
                vulnerabilities.filter((vulnerability) => vulnerability.run_id === activeRun.id)
                  .length
              }
            />
          ) : (
            <ReadinessPanel
              readiness={readiness}
              canStartPentest={canStartPentest}
              startPentestPending={startPentestPending}
              reposPending={reposPending}
              onStartPentest={onStartPentest}
            />
          )}
        </section>

        <section className="project-overview__panel project-overview__panel--attention">
          <div className="project-panel__header">
            <div>
              <p className="project-panel__eyebrow">Attention</p>
              <h2>Verified risk</h2>
            </div>
            <Badge tone={verifiedCount > 0 ? "danger" : "success"}>
              {vulnerabilitiesPending ? "Loading" : verifiedCount > 0 ? "Open" : "Clear"}
            </Badge>
          </div>
          <div className="project-attention__count">
            <strong>{vulnerabilitiesPending ? "-" : verifiedCount}</strong>
            <span>
              {verifiedCount === 1 ? "verified vulnerability" : "verified vulnerabilities"}
            </span>
          </div>
          <SeverityBreakdown counts={severityCounts} total={verifiedCount} />
          {highestRisk ? (
            <Link
              className="project-attention__finding"
              to={`${projectPath}/vulnerabilities`}
              title={highestRisk.title}
            >
              <Badge tone={severityTone(highestRisk.severity)}>
                {canonicalSeverity(highestRisk.severity)}
              </Badge>
              <span>{highestRisk.title}</span>
              <small>{formatRelativeTime(highestRisk.last_seen)}</small>
            </Link>
          ) : (
            <div className="project-attention__empty">
              <span>No verified vulnerabilities</span>
              <small>
                {runsPending ? "Checking recent runs" : "Findings will appear after verification."}
              </small>
            </div>
          )}
          <Link
            className="btn btn--ghost project-overview__action"
            to={`${projectPath}/vulnerabilities`}
          >
            Review vulnerabilities
          </Link>
        </section>
      </div>

      <section className="project-scope-grid" aria-label="Project scope">
        <ScopeTile
          to={`${projectPath}/environments`}
          label="Target"
          value={target || "Not set"}
          detail="Runtime URL"
          tone={target ? "success" : "warning"}
          code
        />
        <ScopeTile
          to={`${projectPath}/repos`}
          label="Repositories"
          value={reposPending ? "Loading" : repoCountLabel}
          detail={repos[0]?.name ?? "No source connected"}
          tone={repos.length > 0 ? "success" : "warning"}
        />
        <ScopeTile
          to={`${projectPath}/environments`}
          label="Environment"
          value={environmentStatus.label}
          detail={formatLaunchMode(launchProfile)}
          tone={environmentStatus.tone === "success" ? "success" : "warning"}
        />
        <ScopeTile
          to={`${projectPath}/integrations`}
          label="Integrations"
          value={
            integrationsPending
              ? "Loading"
              : integrations.length > 0
                ? `${enabledIntegrations}/${integrations.length} enabled`
                : "Not configured"
          }
          detail="Delivery"
          tone={integrations.length > 0 ? "success" : "neutral"}
        />
      </section>

      <section className="project-overview__activity">
        <div className="project-activity__header">
          <div>
            <p className="project-panel__eyebrow">Recent activity</p>
            <h2>Project timeline</h2>
          </div>
          <Link to={`${projectPath}/runs`}>View runs</Link>
        </div>
        <ol className="project-activity__list">
          {activity.length > 0 ? (
            activity.slice(0, 5).map((item) => (
              <li className="project-activity__item" key={item.id}>
                <span
                  className={`project-activity__marker project-activity__marker--${item.tone}`}
                  aria-hidden="true"
                />
                <div>
                  {item.to ? <Link to={item.to}>{item.title}</Link> : <strong>{item.title}</strong>}
                  <span>{item.detail}</span>
                </div>
                <time>{formatRelativeTime(item.timestampMs)}</time>
              </li>
            ))
          ) : (
            <li className="project-activity__item project-activity__item--empty">
              <span className="project-activity__marker" aria-hidden="true" />
              <div>
                <strong>No activity yet</strong>
                <span>Start a pentest when setup is ready.</span>
              </div>
            </li>
          )}
        </ol>
      </section>
    </div>
  );
}

function CurrentRunPanel({
  projectPath,
  run,
  event,
  target,
  activeRepoStates,
  verifiedThisRun,
}: {
  projectPath: string;
  run: RunRecord;
  event: LiveRunEvent | null;
  target: string | null;
  activeRepoStates: RepoLiveState[];
  verifiedThisRun: number;
}) {
  const phase = event ? labelForRunEvent(event) : (activeRepoStates[0]?.status ?? "Running");
  return (
    <>
      <div className="project-panel__header">
        <div>
          <p className="project-panel__eyebrow">Current run</p>
          <h2>Pentest in progress</h2>
        </div>
        <Badge tone="info">Running</Badge>
      </div>
      <div className="project-run-metrics">
        <Metric label="Phase" value={phase} />
        <Metric label="Elapsed" value={formatElapsedSince(run.started_at)} />
        <Metric label="Verified" value={String(verifiedThisRun)} />
      </div>
      <div className="project-run-event">
        <span>{event ? detailForRunEvent(event) : target || run.id}</span>
      </div>
      <div className="project-overview__actions">
        <Link className="btn btn--primary" to={`${projectPath}/runs/${encodeURIComponent(run.id)}`}>
          View run
        </Link>
        <Link className="btn btn--ghost" to={`${projectPath}/runs`}>
          Run history
        </Link>
      </div>
    </>
  );
}

function ReadinessPanel({
  readiness,
  canStartPentest,
  startPentestPending,
  reposPending,
  onStartPentest,
}: {
  readiness: ReadinessCheck[];
  canStartPentest: boolean;
  startPentestPending: boolean;
  reposPending: boolean;
  onStartPentest: () => void;
}) {
  const missing = readiness.find((check) => !check.ok);
  return (
    <>
      <div className="project-panel__header">
        <div>
          <p className="project-panel__eyebrow">Readiness</p>
          <h2>{canStartPentest ? "Ready to test" : "Setup needed"}</h2>
        </div>
        <Badge tone={canStartPentest ? "success" : "warning"}>
          {reposPending ? "Checking" : canStartPentest ? "Ready" : "Blocked"}
        </Badge>
      </div>
      <ul className="project-readiness__list">
        {readiness.map((check) => (
          <li key={check.label}>
            <span
              className={`project-readiness__dot ${
                check.ok ? "project-readiness__dot--ok" : "project-readiness__dot--missing"
              }`}
              aria-hidden="true"
            />
            <div>
              <strong>{check.label}</strong>
              <span>{check.detail}</span>
            </div>
            <Link to={check.to}>Open</Link>
          </li>
        ))}
      </ul>
      <div className="project-overview__actions">
        <Button
          variant="primary"
          onClick={onStartPentest}
          disabled={!canStartPentest || startPentestPending}
        >
          {startPentestPending ? "Starting..." : "Start pentest"}
        </Button>
        {missing && (
          <Link className="btn btn--ghost" to={missing.to}>
            Resolve setup
          </Link>
        )}
      </div>
    </>
  );
}

function Metric({ label, value }: { label: string; value: string }) {
  return (
    <div>
      <span>{label}</span>
      <strong>{value}</strong>
    </div>
  );
}

function SeverityBreakdown({
  counts,
  total,
}: {
  counts: Record<SeverityName, number>;
  total: number;
}) {
  return (
    <section className="project-severity" aria-label="Severity breakdown">
      {SEVERITIES.map((severity) => {
        const count = counts[severity];
        const width = total > 0 ? `${Math.max((count / total) * 100, count > 0 ? 8 : 0)}%` : "0";
        return (
          <div className="project-severity__row" key={severity}>
            <span>{severity}</span>
            <div className="project-severity__bar">
              <span
                className={`project-severity__fill project-severity__fill--${severity.toLowerCase()}`}
                style={{ width }}
              />
            </div>
            <strong>{count}</strong>
          </div>
        );
      })}
    </section>
  );
}

function ScopeTile({
  to,
  label,
  value,
  detail,
  tone,
  code = false,
}: {
  to: string;
  label: string;
  value: string;
  detail: string;
  tone: "success" | "warning" | "neutral";
  code?: boolean;
}) {
  return (
    <Link className={`project-scope-tile project-scope-tile--${tone}`} to={to}>
      <span className="project-scope-tile__label">{label}</span>
      {code ? <code title={value}>{value}</code> : <strong title={value}>{value}</strong>}
      <small>{detail}</small>
    </Link>
  );
}

type SeverityName = "Critical" | "High" | "Medium" | "Low";
type ActivityTone = "neutral" | "success" | "warning" | "danger" | "info";

interface ReadinessCheck {
  label: string;
  detail: string;
  ok: boolean;
  to: string;
}

interface ActivityItem {
  id: string;
  title: string;
  detail: string;
  timestampMs: number;
  tone: ActivityTone;
  to?: string;
}

interface ProjectActivityInput {
  projectPath: string;
  runEvents: LiveRunEvent[];
  runs: RunRecord[];
  repos: RepoRecord[];
  vulnerabilities: VerifiedVulnerabilityRecord[];
  integrations: ProjectIntegrationRecord[];
}

const SEVERITIES: SeverityName[] = ["Critical", "High", "Medium", "Low"];
const SEVERITY_RANK: Record<SeverityName, number> = {
  Critical: 4,
  High: 3,
  Medium: 2,
  Low: 1,
};

function readinessChecks(
  projectPath: string,
  target: string | null,
  repoCount: number,
  profile: ProjectLaunchProfile | null,
): ReadinessCheck[] {
  const environment = launchProfileStatus(profile);
  return [
    {
      label: "Target URL",
      detail: target || "Add the app URL",
      ok: Boolean(target),
      to: `${projectPath}/environments`,
    },
    {
      label: "Source repository",
      detail: repoCount > 0 ? formatRepoCount(repoCount) : "Connect a repo",
      ok: repoCount > 0,
      to: `${projectPath}/repos`,
    },
    {
      label: "Environment",
      detail: `${environment.label} · ${formatLaunchMode(profile)}`,
      ok: profile?.readiness === "Ready",
      to: `${projectPath}/environments`,
    },
  ];
}

function countSeverities(rows: VerifiedVulnerabilityRecord[]): Record<SeverityName, number> {
  const counts: Record<SeverityName, number> = {
    Critical: 0,
    High: 0,
    Medium: 0,
    Low: 0,
  };
  for (const row of rows) {
    counts[canonicalSeverity(row.severity)] += 1;
  }
  return counts;
}

function highestRiskVulnerability(
  rows: VerifiedVulnerabilityRecord[],
): VerifiedVulnerabilityRecord | null {
  return (
    [...rows].sort((a, b) => {
      const bySeverity =
        SEVERITY_RANK[canonicalSeverity(b.severity)] - SEVERITY_RANK[canonicalSeverity(a.severity)];
      if (bySeverity !== 0) return bySeverity;
      return (toEpochMs(b.last_seen) ?? 0) - (toEpochMs(a.last_seen) ?? 0);
    })[0] ?? null
  );
}

function canonicalSeverity(severity: string): SeverityName {
  const normalized = severity.toLowerCase();
  return SEVERITIES.find((candidate) => candidate.toLowerCase() === normalized) ?? "Low";
}

function severityTone(severity: string): BadgeTone {
  const canonical = canonicalSeverity(severity);
  if (canonical === "Critical" || canonical === "High") return "danger";
  if (canonical === "Medium") return "warning";
  return "neutral";
}

function buildProjectActivity(input: ProjectActivityInput): ActivityItem[] {
  const items: ActivityItem[] = [];

  input.runEvents.forEach((event, index) => {
    const runId = runIdForEvent(event);
    items.push({
      id: `event-${runId ?? "run"}-${runEventTimestampMs(event)}-${index}`,
      title: labelForRunEvent(event),
      detail: detailForRunEvent(event),
      timestampMs: runEventTimestampMs(event),
      tone: toneForRunEvent(event),
      to: runId
        ? `${input.projectPath}/runs/${encodeURIComponent(runId)}`
        : `${input.projectPath}/runs`,
    });
  });

  for (const run of input.runs.slice(0, 4)) {
    const runTime = toEpochMs(run.finished_at ?? run.started_at) ?? 0;
    items.push({
      id: `run-${run.id}`,
      title: run.status === "Running" ? "Pentest running" : `Pentest ${run.status.toLowerCase()}`,
      detail: `${run.kind} · ${formatRunDuration(run)}`,
      timestampMs: runTime,
      tone: toneForRunStatus(run.status),
      to: `${input.projectPath}/runs/${encodeURIComponent(run.id)}`,
    });
  }

  [...input.vulnerabilities]
    .sort((a, b) => (toEpochMs(b.last_seen) ?? 0) - (toEpochMs(a.last_seen) ?? 0))
    .slice(0, 3)
    .forEach((vulnerability) => {
      items.push({
        id: `vulnerability-${vulnerability.id}`,
        title: "Vulnerability verified",
        detail: `${canonicalSeverity(vulnerability.severity)} · ${vulnerability.title}`,
        timestampMs: toEpochMs(vulnerability.last_seen) ?? 0,
        tone: severityTone(vulnerability.severity) === "danger" ? "danger" : "warning",
        to: `${input.projectPath}/vulnerabilities`,
      });
    });

  [...input.repos]
    .sort((a, b) => (toEpochMs(b.created_at) ?? 0) - (toEpochMs(a.created_at) ?? 0))
    .slice(0, 2)
    .forEach((repo) => {
      items.push({
        id: `repo-${repo.id}`,
        title: "Repository connected",
        detail: repo.name,
        timestampMs: toEpochMs(repo.created_at) ?? 0,
        tone: "success",
        to: `${input.projectPath}/repos`,
      });
    });

  [...input.integrations]
    .sort((a, b) => (toEpochMs(b.updated_at) ?? 0) - (toEpochMs(a.updated_at) ?? 0))
    .slice(0, 1)
    .forEach((integration) => {
      items.push({
        id: `integration-${integration.id}`,
        title: integration.enabled ? "Integration enabled" : "Integration configured",
        detail: integration.name,
        timestampMs: toEpochMs(integration.updated_at) ?? 0,
        tone: integration.enabled ? "success" : "neutral",
        to: `${input.projectPath}/integrations`,
      });
    });

  const seen = new Set<string>();
  return items
    .filter((item) => item.timestampMs > 0)
    .sort((a, b) => b.timestampMs - a.timestampMs)
    .filter((item) => {
      if (seen.has(item.id)) return false;
      seen.add(item.id);
      return true;
    });
}

function runIdForEvent(event: LiveRunEvent): string | null {
  return "run_id" in event ? event.run_id : null;
}

function runEventTimestampMs(event: LiveRunEvent): number {
  if ("started_at_ms" in event) return event.started_at_ms;
  if ("finished_at_ms" in event) return event.finished_at_ms;
  if ("ts_ms" in event) return event.ts_ms;
  return Date.now();
}

function labelForRunEvent(event: LiveRunEvent): string {
  switch (event.kind) {
    case "RunStarted":
    case "ProjectStarted":
      return "Pentest started";
    case "PhaseStarted":
      return `${formatPhaseName(event.phase)} started`;
    case "PhaseFinished":
      return `${formatPhaseName(event.phase)} finished`;
    case "EnvironmentStatus":
      return `Environment ${formatStatusLabel(event.status)}`;
    case "AuthSessionStatus":
      return `Session ${formatStatusLabel(event.status)}`;
    case "RepoStarted":
      return `${event.repo} started`;
    case "RepoStaticDone":
      return "Static analysis finished";
    case "RepoDynamicDone":
      return "Dynamic checks finished";
    case "RepoFailed":
    case "RepoIngestFailed":
      return "Repository failed";
    case "RepoFinished":
      return "Repository finished";
    case "ProjectFinished":
    case "RunFinished":
      return "Pentest finished";
    default:
      return "Run updated";
  }
}

function detailForRunEvent(event: LiveRunEvent): string {
  switch (event.kind) {
    case "RunStarted":
      return `${event.repos.length} ${event.repos.length === 1 ? "repo" : "repos"}`;
    case "ProjectStarted":
      return event.project_name;
    case "PhaseStarted":
      return formatPhaseName(event.phase);
    case "PhaseFinished":
      return event.message || event.status;
    case "EnvironmentStatus":
      return event.message || event.target_urls[0] || event.status;
    case "AuthSessionStatus":
      return `${event.role} · ${event.message || event.status}`;
    case "RepoStarted":
      return event.repo;
    case "RepoStaticDone":
      return `${event.repo} · ${event.n_diags} ${event.n_diags === 1 ? "signal" : "signals"}`;
    case "RepoDynamicDone":
    case "RepoFinished":
      return `${event.repo} · ${formatCompactDuration(event.elapsed_ms)}`;
    case "RepoFailed":
      return `${event.repo} · ${event.message}`;
    case "RepoIngestFailed":
      return `${event.repo} · ${event.message}`;
    case "ProjectFinished":
      return event.run_id;
    case "RunFinished":
      return `${event.succeeded} ok · ${event.inconclusive} inconclusive · ${event.failed} failed`;
    default:
      return runIdForEvent(event) ?? "Run event";
  }
}

function toneForRunEvent(event: LiveRunEvent): ActivityTone {
  switch (event.kind) {
    case "RepoFailed":
    case "RepoIngestFailed":
      return "danger";
    case "PhaseFinished":
      return event.status.toLowerCase().includes("fail") ? "danger" : "success";
    case "RunFinished":
      return event.failed > 0 ? "warning" : "success";
    case "ProjectFinished":
    case "RepoFinished":
    case "RepoStaticDone":
    case "RepoDynamicDone":
      return "success";
    case "EnvironmentStatus":
    case "AuthSessionStatus":
      return event.status.toLowerCase().includes("fail") ? "danger" : "info";
    default:
      return "info";
  }
}

function toneForRunStatus(status: string): ActivityTone {
  if (status === "Failed") return "danger";
  if (status === "Succeeded") return "success";
  if (status === "Running") return "info";
  return "neutral";
}

function formatRunDuration(run: RunRecord): string {
  if (run.wall_clock_ms != null) return formatCompactDuration(run.wall_clock_ms);
  if (run.status === "Running") return formatElapsedSince(run.started_at);
  return "duration unavailable";
}

function formatPhaseName(phase: string): string {
  return phase
    .replace(/[-_]/g, " ")
    .replace(/([a-z])([A-Z])/g, "$1 $2")
    .replace(/\b\w/g, (char) => char.toUpperCase());
}

function formatStatusLabel(status: string): string {
  return status
    .replace(/[-_]/g, " ")
    .replace(/([a-z])([A-Z])/g, "$1 $2")
    .toLowerCase();
}

function formatRelativeTime(value: number | null | undefined): string {
  const ms = toEpochMs(value);
  if (!ms) return "-";
  const diffMs = Date.now() - ms;
  const absMs = Math.abs(diffMs);
  const suffix = diffMs >= 0 ? "ago" : "from now";
  if (absMs < 45_000) return "just now";
  if (absMs < 90_000) return `1 min ${suffix}`;
  const minutes = Math.round(absMs / 60_000);
  if (minutes < 60) return `${minutes} min ${suffix}`;
  const hours = Math.round(minutes / 60);
  if (hours < 24) return `${hours} hr ${suffix}`;
  const days = Math.round(hours / 24);
  if (days < 14) return `${days} day${days === 1 ? "" : "s"} ${suffix}`;
  return new Date(ms).toLocaleDateString();
}

function formatElapsedSince(value: number): string {
  const ms = toEpochMs(value);
  if (!ms) return "-";
  return formatCompactDuration(Math.max(Date.now() - ms, 0));
}

function formatCompactDuration(ms: number): string {
  if (ms < 1_000) return `${ms}ms`;
  const seconds = Math.floor(ms / 1_000);
  if (seconds < 60) return `${seconds}s`;
  const minutes = Math.floor(seconds / 60);
  if (minutes < 60) return `${minutes}m ${seconds % 60}s`;
  const hours = Math.floor(minutes / 60);
  return `${hours}h ${minutes % 60}m`;
}

function toEpochMs(value: number | null | undefined): number | null {
  if (value == null || value <= 0) return null;
  return value < 10_000_000_000 ? value * 1000 : value;
}

const ENVIRONMENT_AUTOSAVE_DELAY_MS = 800;

type EnvironmentSaveStatus = "saved" | "dirty" | "saving" | "blocked" | "error";

function EnvironmentEditor({ project }: { project: ProjectRecord }) {
  const patchProfile = usePatchDefaultLaunchProfile(project.id);
  const patchProject = usePatchProject();
  const initialDraft = useMemo(() => profileDraftFromProject(project), [project]);
  const [draft, setDraft] = useState<RuntimeProfileDraft>(initialDraft);
  const [error, setError] = useState<string | null>(null);
  const [saveStatus, setSaveStatus] = useState<EnvironmentSaveStatus>("saved");
  const [editorFocused, setEditorFocused] = useState(false);
  const savedSnapshotRef = useRef(environmentSaveSnapshot(initialDraft));
  const draftSnapshotRef = useRef(savedSnapshotRef.current);
  const saveSeqRef = useRef(0);

  useEffect(() => {
    const nextDraft = profileDraftFromProject(project);
    const snapshot = environmentSaveSnapshot(nextDraft);
    setDraft(nextDraft);
    savedSnapshotRef.current = snapshot;
    draftSnapshotRef.current = snapshot;
    saveSeqRef.current += 1;
    setError(null);
    setSaveStatus("saved");
  }, [project.id]);

  const persistDraft = useCallback(
    async (nextDraft: RuntimeProfileDraft, snapshot: string) => {
      const saveSeq = saveSeqRef.current + 1;
      saveSeqRef.current = saveSeq;
      setError(null);
      const profileError = launchProfileDraftError(nextDraft);
      if (profileError) {
        setError(profileError);
        setSaveStatus("blocked");
        return;
      }
      if (!nextDraft.target_base_url.trim()) {
        setError("Add an app URL before saving the environment profile.");
        setSaveStatus("blocked");
        return;
      }
      const launchProfile = launchProfileFromDraft(nextDraft);
      const runtimeProfile = runtimeProfileFromDraft(nextDraft);
      if (!launchProfile) {
        setError("Add an app URL before saving the environment profile.");
        setSaveStatus("blocked");
        return;
      }
      setSaveStatus("saving");
      try {
        await patchProject.mutateAsync({
          id: project.id,
          patch: { runtime_profile: runtimeProfile ?? null },
        });
        await patchProfile.mutateAsync(launchProfile);
        if (saveSeq !== saveSeqRef.current) return;
        savedSnapshotRef.current = snapshot;
        setError(null);
        setSaveStatus(draftSnapshotRef.current === snapshot ? "saved" : "dirty");
      } catch (err) {
        if (saveSeq !== saveSeqRef.current) return;
        setError(String(err));
        setSaveStatus("error");
      }
    },
    [patchProfile.mutateAsync, patchProject.mutateAsync, project.id],
  );

  const flushDraft = useCallback(() => {
    const snapshot = environmentSaveSnapshot(draft);
    draftSnapshotRef.current = snapshot;
    if (snapshot !== savedSnapshotRef.current) {
      void persistDraft(draft, snapshot);
    }
  }, [draft, persistDraft]);

  useEffect(() => {
    const snapshot = environmentSaveSnapshot(draft);
    draftSnapshotRef.current = snapshot;
    if (snapshot === savedSnapshotRef.current) {
      setSaveStatus("saved");
      return;
    }
    setSaveStatus((current) => (current === "saving" ? current : "dirty"));
    if (editorFocused) return;
    const timer = window.setTimeout(() => {
      if (snapshot !== savedSnapshotRef.current) {
        void persistDraft(draft, snapshot);
      }
    }, ENVIRONMENT_AUTOSAVE_DELAY_MS);
    return () => window.clearTimeout(timer);
  }, [draft, editorFocused, persistDraft]);

  function onDraftChange(nextDraft: RuntimeProfileDraft) {
    setDraft(nextDraft);
  }

  function onEditorBlur(event: FocusEvent<HTMLDivElement>) {
    const nextTarget = event.relatedTarget;
    if (nextTarget instanceof Node && event.currentTarget.contains(nextTarget)) return;
    setEditorFocused(false);
    flushDraft();
  }

  return (
    <Card
      className="environment-editor-card"
      title="Launch Profile"
      actions={<EnvironmentAutosaveStatus status={saveStatus} />}
      onFocus={() => setEditorFocused(true)}
      onBlur={onEditorBlur}
    >
      <ProjectRuntimeProfileForm value={draft} onChange={onDraftChange} projectId={project.id} />
      {error && (
        <p className="repo-add__error" role="alert">
          {error}
        </p>
      )}
    </Card>
  );
}

function EnvironmentAutosaveStatus({ status }: { status: EnvironmentSaveStatus }) {
  if (status === "saving") {
    return (
      <span className="environment-editor-status" role="status" aria-live="polite">
        <Spinner />
        Saving...
      </span>
    );
  }
  const label =
    status === "dirty"
      ? "Unsaved changes"
      : status === "blocked"
        ? "Fix errors to autosave"
        : status === "error"
          ? "Autosave failed"
          : "Autosaved";
  return (
    <span
      className={`environment-editor-status environment-editor-status--${status}`}
      role="status"
      aria-live="polite"
    >
      {label}
    </span>
  );
}

function environmentSaveSnapshot(draft: RuntimeProfileDraft): string {
  return JSON.stringify({
    launchProfile: launchProfileFromDraft(draft) ?? null,
    runtimeProfile: runtimeProfileFromDraft(draft) ?? null,
  });
}

function profileDraftFromProject(project: ProjectRecord): RuntimeProfileDraft {
  const draft = launchProfileToDraft(project.default_launch_profile, project.target_base_url ?? "");
  const runtimeDraft = runtimeProfileToDraft(
    project.runtime_profile,
    project.target_base_url ?? "",
  );
  draft.auth_profiles = runtimeDraft.auth_profiles;
  return draft;
}

interface StartPentestOptions {
  exploitMode: boolean;
  allowStateChanging: boolean;
  browserChecks: boolean;
  researchMode: boolean;
  unsafeAttackAgent: boolean;
}

interface StartPentestModalProps {
  busy: boolean;
  onConfirm: (options: StartPentestOptions) => void;
  onCancel: () => void;
}

function StartPentestModal({ busy, onConfirm, onCancel }: StartPentestModalProps) {
  const [exploitMode, setExploitMode] = useState(false);
  const [allowStateChanging, setAllowStateChanging] = useState(false);
  const [browserChecks, setBrowserChecks] = useState(false);
  const [researchMode, setResearchMode] = useState(false);
  const [unsafeAttackAgent, setUnsafeAttackAgent] = useState(false);

  function setExploitModeChecked(checked: boolean) {
    setExploitMode(checked);
    if (!checked) setAllowStateChanging(false);
  }

  return (
    <ConfirmModal
      title="Start pentest"
      confirmLabel={exploitMode ? "Start with exploit mode" : "Start safe pentest"}
      busy={busy}
      onConfirm={() =>
        onConfirm({
          exploitMode,
          allowStateChanging,
          browserChecks,
          researchMode,
          unsafeAttackAgent,
        })
      }
      onCancel={onCancel}
      body={
        <div className="pentest-options">
          <p className="pentest-options__note">
            Safe mode is the default. State-changing probes stay blocked unless both switches are
            enabled for this run.
          </p>
          <label className="pentest-options__check">
            <input
              type="checkbox"
              checked={browserChecks}
              onChange={(event) => setBrowserChecks(event.currentTarget.checked)}
            />
            <span>
              <strong>Browser verification</strong>
              <small>Allow Playwright-backed checks for DOM and browser-only workflows.</small>
            </span>
          </label>
          <label className="pentest-options__check">
            <input
              type="checkbox"
              checked={researchMode}
              onChange={(event) => setResearchMode(event.currentTarget.checked)}
            />
            <span>
              <strong>Vuln research mode</strong>
              <small>
                Generate deeper product-invariant hypotheses without changing safety gates.
              </small>
            </span>
          </label>
          <label className="pentest-options__check">
            <input
              type="checkbox"
              checked={unsafeAttackAgent}
              onChange={(event) => setUnsafeAttackAgent(event.currentTarget.checked)}
            />
            <span>
              <strong>Unsafe attack agent</strong>
              <small>Let the final local agent mutate and break the disposable dev app.</small>
            </span>
          </label>
          <label className="pentest-options__check">
            <input
              type="checkbox"
              checked={exploitMode}
              onChange={(event) => setExploitModeChecked(event.currentTarget.checked)}
            />
            <span>
              <strong>Exploit mode</strong>
              <small>Allow Nyctos to evaluate invasive live-verification plans.</small>
            </span>
          </label>
          <label className="pentest-options__check">
            <input
              type="checkbox"
              checked={allowStateChanging}
              disabled={!exploitMode}
              onChange={(event) => setAllowStateChanging(event.currentTarget.checked)}
            />
            <span>
              <strong>State-changing probes</strong>
              <small>
                Permit POST, PUT, PATCH, DELETE, and browser workflows that may mutate data.
              </small>
            </span>
          </label>
        </div>
      }
    />
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

function formatRepoCount(count: number): string {
  return `${count} ${count === 1 ? "repository" : "repositories"}`;
}

interface RepoRowProps {
  repo: RepoRecord;
  live: RepoLiveState;
  onEdit: () => void;
  onDelete: () => void;
  busy: boolean;
}

function RepoRow({ repo, live, onEdit, onDelete, busy }: RepoRowProps) {
  return (
    <tr>
      <td>
        <span className="repo-list__name">{repo.name}</span>
        {repo.branch && <span className="repo-list__meta"> · {repo.branch}</span>}
      </td>
      <td className="repo-list__muted">{formatSourceKind(repo.source_kind)}</td>
      <td className="repo-list__source" title={repo.source_url_or_path}>
        {repo.source_url_or_path}
      </td>
      <td>
        {live.status === "Idle" ? (
          <span className="repo-list__muted">Idle</span>
        ) : (
          <Badge tone={STATUS_TONE[live.status]}>{live.status}</Badge>
        )}
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

function formatSourceKind(kind: string): string {
  if (kind === "LocalPath") return "Local path";
  return kind;
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

function runEventBelongsToProject(data: LiveRunEvent, projectId: string | undefined): boolean {
  return Boolean(projectId && "project_id" in data && data.project_id === projectId);
}

function mergeRuns(
  running: RunRecord[] | undefined,
  succeeded: RunRecord[] | undefined,
  failed: RunRecord[] | undefined,
): RunRecord[] {
  const byId = new Map<string, RunRecord>();
  for (const row of [...(running ?? []), ...(succeeded ?? []), ...(failed ?? [])]) {
    byId.set(row.id, row);
  }
  return Array.from(byId.values()).sort((a, b) => b.started_at - a.started_at);
}

function surfaceRunToast(
  ev: AgentEventLike,
  showToast: (message: string, options?: ToastOptions) => string,
) {
  if (!("kind" in ev) || ev.kind !== "Run") return;
  const data = ev.data;
  if (data.kind === "RunFinished") {
    showToast(
      `Run ${data.run_id} finished: ${data.succeeded} ok, ${data.inconclusive} inconclusive, ${data.failed} failed.`,
      { tone: "success" },
    );
  }
}

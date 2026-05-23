import { useMemo, useState } from "react";
import { Link, useNavigate, useParams } from "react-router-dom";
import {
  type AgentEventLike,
  runEventLogDownloadUrl,
  useAgentEvents,
  useRunEnvironmentRuns,
  useRunVulnerabilities,
} from "@/api/client";
import type { AiEvent, RunEvent, SandboxEvent } from "@/api/types.gen";
import { Badge, type BadgeTone } from "@/components/Badge";
import { Button } from "@/components/Button";
import { Card } from "@/components/Card";
import { Spinner } from "@/components/Spinner";

type RepoPhase = "queued" | "static" | "static-done" | "dynamic-done" | "finished" | "failed";

interface RepoProgress {
  name: string;
  phase: RepoPhase;
  startedAt?: number;
  staticDoneAt?: number;
  dynamicDoneAt?: number;
  finishedAt?: number;
  elapsedMs?: number;
  outcome?: "Success" | "Inconclusive" | "Failed";
  message?: string;
  nDiags?: number;
}

interface LogLine {
  ts: number;
  level: "info" | "warn" | "error";
  text: string;
}

interface PhaseProgress {
  phase: string;
  label: string;
  status: "pending" | "running" | "finished";
  startedAt?: number;
  finishedAt?: number;
  message?: string | null;
}

interface AuthSessionProgress {
  role: string;
  status: string;
  acquiredBy: string;
  message?: string | null;
  ts?: number;
}

interface RunSummary {
  startedAt?: number;
  finishedAt?: number;
  wallClockMs?: number;
  succeeded?: number;
  inconclusive?: number;
  failed?: number;
  done: boolean;
}

const PHASE_LABEL: Record<RepoPhase, string> = {
  queued: "Queued",
  static: "Static",
  "static-done": "Static done",
  "dynamic-done": "Dynamic done",
  finished: "Source done",
  failed: "Failed",
};

const PHASE_TONE: Record<RepoPhase, BadgeTone> = {
  queued: "neutral",
  static: "info",
  "static-done": "info",
  "dynamic-done": "info",
  finished: "success",
  failed: "danger",
};

const MAX_LIVE_LOG_LINES = 500;

const RUN_PROGRESS_PHASES = [
  { phase: "EnvironmentBuildStarted", weight: 10 },
  { phase: "EnvironmentReady", weight: 5 },
  { phase: "NyxSignalsStarted", weight: 25 },
  { phase: "RouteModelStarted", weight: 10 },
  { phase: "OptionalScannersStarted", weight: 10 },
  { phase: "CandidateSynthesisStarted", weight: 5 },
  { phase: "AgentReviewStarted", weight: 15 },
  { phase: "AiAttackPlanningStarted", weight: 5 },
  { phase: "AuthSessionAcquisitionStarted", weight: 5 },
  { phase: "LiveVerificationStarted", weight: 12 },
  { phase: "BrowserVerificationStarted", weight: 3 },
];

const PHASE_ORDER = RUN_PROGRESS_PHASES.map((phase) => phase.phase);

export function LiveScanView() {
  const { runId = "" } = useParams<{ runId: string }>();
  const navigate = useNavigate();
  const [repos, setRepos] = useState<Record<string, RepoProgress>>({});
  const [logs, setLogs] = useState<LogLine[]>([]);
  const [phases, setPhases] = useState<Record<string, PhaseProgress>>({});
  const [authSessions, setAuthSessions] = useState<Record<string, AuthSessionProgress>>({});
  const [summary, setSummary] = useState<RunSummary>({ done: false });
  const environmentRuns = useRunEnvironmentRuns(runId);
  const vulnerabilities = useRunVulnerabilities(runId);

  useAgentEvents({
    runId,
    onEvent: (ev) => {
      applyToRepos(ev, setRepos);
      applyToLogs(ev, setLogs);
      applyToPhases(ev, setPhases);
      applyToAuthSessions(ev, setAuthSessions);
      applyToSummary(ev, setSummary);
    },
  });

  const orderedRepos = useMemo(() => {
    const items = Object.values(repos);
    items.sort((a, b) => a.name.localeCompare(b.name));
    return items;
  }, [repos]);

  const totalRepos = orderedRepos.length;
  const finishedRepos = orderedRepos.filter(
    (r) => r.phase === "finished" || r.phase === "failed",
  ).length;
  const orderedPhases = useMemo(() => orderPhases(phases), [phases]);
  const orderedAuthSessions = useMemo(() => orderAuthSessions(authSessions), [authSessions]);
  const runProgress = useMemo(
    () => runProgressPercent(orderedRepos, orderedPhases, summary),
    [orderedRepos, orderedPhases, summary],
  );
  const showRunProgress = summary.done || totalRepos > 0 || orderedPhases.length > 0;

  return (
    <div className="live-scan">
      <Card
        title={`Run ${runId}`}
        subtitle={
          summary.done
            ? `Finished in ${summary.wallClockMs ?? "-"}ms · ${summary.succeeded ?? 0} ok / ${
                summary.inconclusive ?? 0
              } inconclusive / ${summary.failed ?? 0} failed`
            : finishedRepos === totalRepos && totalRepos > 0
              ? `${finishedRepos}/${totalRepos} code sources scanned · AI/live phases still running`
              : `${finishedRepos}/${totalRepos || "?"} code sources scanned`
        }
        actions={
          <div className="live-scan__actions">
            <Button
              variant="ghost"
              onClick={() => navigate(`/vulnerabilities?run_id=${encodeURIComponent(runId)}`)}
            >
              View vulnerabilities
            </Button>
            <a className="btn btn--ghost" href={runEventLogDownloadUrl(runId)} download>
              Download log
            </a>
          </div>
        }
      >
        {!summary.done && totalRepos === 0 && (
          <div className="live-scan__pending">
            <Spinner /> Preparing app...
          </div>
        )}

        {showRunProgress && (
          <div className="live-scan__run-progress">
            <div
              className="live-scan__bar"
              role="progressbar"
              aria-label="Run progress"
              aria-valuenow={runProgress}
              aria-valuemin={0}
              aria-valuemax={100}
              aria-valuetext={`${runProgress}% complete`}
            >
              <div
                className={`live-scan__bar-fill${
                  summary.done ? " live-scan__bar-fill--finished" : ""
                }`}
                style={{ width: `${runProgress}%` }}
              />
            </div>
          </div>
        )}

        {environmentRuns.data && environmentRuns.data.length > 0 && (
          <section className="live-scan__environment">
            <h3 className="live-scan__h3">App</h3>
            {environmentRuns.data.map((env) => (
              <div key={env.id} className="live-scan__env-row">
                <Badge tone={environmentTone(env.status)}>{env.status}</Badge>
                <span>
                  {env.target_urls.length > 0 ? env.target_urls.join(", ") : "No target URLs"}
                </span>
              </div>
            ))}
          </section>
        )}

        {orderedAuthSessions.length > 0 && (
          <section className="live-scan__auth">
            <h3 className="live-scan__h3">Auth sessions</h3>
            <ul className="live-scan__auth-list">
              {orderedAuthSessions.map((session) => (
                <li key={session.role} className="live-scan__auth-row">
                  <Badge tone={authTone(session.status)}>{session.status}</Badge>
                  <span className="live-scan__auth-role">{session.role}</span>
                  <span className="live-scan__auth-method">{session.acquiredBy}</span>
                  {session.message && <small>{session.message}</small>}
                </li>
              ))}
            </ul>
          </section>
        )}

        {orderedRepos.length > 0 && (
          <ul className="live-scan__repos">
            {orderedRepos.map((repo) => (
              <RepoProgressRow key={repo.name} repo={repo} />
            ))}
          </ul>
        )}

        {orderedPhases.length > 0 && (
          <section className="live-scan__phases">
            <h3 className="live-scan__h3">Pentest phases</h3>
            <ol className="live-scan__phase-list">
              {orderedPhases.map((phase) => (
                <li
                  key={phase.phase}
                  className={`live-scan__phase live-scan__phase--${phase.status}`}
                >
                  <Badge tone={phaseTone(phase.status)}>{phase.status}</Badge>
                  <span>{phase.label}</span>
                  {phase.message && <small>{phase.message}</small>}
                </li>
              ))}
            </ol>
          </section>
        )}

        <section className="live-scan__logs">
          <h3 className="live-scan__h3">Stream</h3>
          {logs.length === 0 ? (
            <p className="live-scan__muted">No log lines yet.</p>
          ) : (
            <ol className="live-scan__log">
              {logs.map((line, idx) => (
                <li key={idx} className={`live-scan__log-line live-scan__log-line--${line.level}`}>
                  <time>{new Date(line.ts).toLocaleTimeString()}</time>
                  <span>{line.text}</span>
                </li>
              ))}
            </ol>
          )}
        </section>

        {summary.done && (
          <p className="live-scan__cta">
            Run finished with {vulnerabilities.data?.length ?? 0} verified vulnerabilities.{" "}
            <Link to={`/vulnerabilities?run_id=${encodeURIComponent(runId)}`}>
              Open vulnerabilities →
            </Link>
          </p>
        )}
      </Card>
    </div>
  );
}

interface RepoProgressRowProps {
  repo: RepoProgress;
}

function RepoProgressRow({ repo }: RepoProgressRowProps) {
  return (
    <li className="live-scan__repo">
      <div className="live-scan__repo-header">
        <span className="live-scan__repo-name">{repo.name}</span>
        <Badge tone={PHASE_TONE[repo.phase]}>{PHASE_LABEL[repo.phase]}</Badge>
        {repo.outcome && repo.phase !== "failed" && (
          <Badge tone={repo.outcome === "Success" ? "success" : "warning"}>{repo.outcome}</Badge>
        )}
        {repo.nDiags !== undefined && (
          <span className="live-scan__repo-count">{repo.nDiags} signal(s)</span>
        )}
        {repo.elapsedMs !== undefined && (
          <span className="live-scan__repo-elapsed">{repo.elapsedMs}ms</span>
        )}
      </div>
      {repo.message && (
        <p className="live-scan__repo-msg" title={repo.message}>
          {repo.message}
        </p>
      )}
    </li>
  );
}

function sourceScanProgress(phase: RepoPhase): number {
  switch (phase) {
    case "queued":
      return 0.05;
    case "static":
      return 0.4;
    case "static-done":
      return 0.85;
    case "dynamic-done":
      return 1;
    case "finished":
      return 1;
    case "failed":
      return 1;
  }
}

function runProgressPercent(
  repos: RepoProgress[],
  phases: PhaseProgress[],
  summary: RunSummary,
): number {
  if (summary.done) return 100;

  const phaseStatus = new Map(phases.map((phase) => [phase.phase, phase.status]));
  const sourceProgress =
    repos.length === 0
      ? 0
      : repos.reduce((sum, repo) => sum + sourceScanProgress(repo.phase), 0) / repos.length;

  let weightedProgress = 0;
  let totalWeight = 0;
  for (const step of RUN_PROGRESS_PHASES) {
    const phaseProgress = phaseStatusProgress(phaseStatus.get(step.phase));
    const progress =
      step.phase === "NyxSignalsStarted" ? Math.max(phaseProgress, sourceProgress) : phaseProgress;
    weightedProgress += progress * step.weight;
    totalWeight += step.weight;
  }

  if (totalWeight === 0 || (repos.length === 0 && phases.length === 0)) return 0;
  return Math.min(95, Math.max(5, Math.round((weightedProgress / totalWeight) * 100)));
}

function phaseStatusProgress(status?: PhaseProgress["status"]): number {
  if (status === "finished") return 1;
  if (status === "running") return 0.5;
  return 0;
}

function environmentTone(status: string): BadgeTone {
  if (status === "Ready") return "success";
  if (status === "Failed") return "danger";
  if (status === "Stopped") return "neutral";
  return "info";
}

type RepoMap = Record<string, RepoProgress>;
type RepoSetter = (updater: (prev: RepoMap) => RepoMap) => void;
type LogSetter = (updater: (prev: LogLine[]) => LogLine[]) => void;
type PhaseMap = Record<string, PhaseProgress>;
type PhaseSetter = (updater: (prev: PhaseMap) => PhaseMap) => void;
type AuthSessionMap = Record<string, AuthSessionProgress>;
type AuthSessionSetter = (updater: (prev: AuthSessionMap) => AuthSessionMap) => void;
type SummarySetter = (updater: (prev: RunSummary) => RunSummary) => void;

function applyToRepos(ev: AgentEventLike, set: RepoSetter) {
  if (!("kind" in ev) || ev.kind !== "Run") return;
  const data = ev.data;
  switch (data.kind) {
    case "RunStarted":
      set((prev) => {
        const next = { ...prev };
        for (const name of data.repos) {
          next[name] = next[name] ?? { name, phase: "queued" };
        }
        return next;
      });
      return;
    case "RepoStarted":
      set((prev) => ({
        ...prev,
        [data.repo]: {
          ...(prev[data.repo] ?? { name: data.repo, phase: "queued" }),
          phase: "static",
          startedAt: data.started_at_ms,
        },
      }));
      return;
    case "RepoStaticDone":
      set((prev) => ({
        ...prev,
        [data.repo]: {
          ...(prev[data.repo] ?? { name: data.repo, phase: "queued" }),
          phase: "static-done",
          staticDoneAt: Date.now(),
          nDiags: data.n_diags,
        },
      }));
      return;
    case "RepoDynamicDone":
      set((prev) => ({
        ...prev,
        [data.repo]: {
          ...(prev[data.repo] ?? { name: data.repo, phase: "queued" }),
          phase: "dynamic-done",
          dynamicDoneAt: Date.now(),
        },
      }));
      return;
    case "RepoFinished":
      set((prev) => ({
        ...prev,
        [data.repo]: {
          ...(prev[data.repo] ?? { name: data.repo, phase: "queued" }),
          phase: "finished",
          finishedAt: Date.now(),
          outcome: data.outcome,
          elapsedMs: data.elapsed_ms,
        },
      }));
      return;
    case "RepoFailed":
      set((prev) => ({
        ...prev,
        [data.repo]: {
          ...(prev[data.repo] ?? { name: data.repo, phase: "queued" }),
          phase: "failed",
          message: data.message,
          finishedAt: Date.now(),
          elapsedMs: data.elapsed_ms,
        },
      }));
      return;
  }
}

function applyToAuthSessions(ev: AgentEventLike, set: AuthSessionSetter) {
  if (!("kind" in ev) || ev.kind !== "Run") return;
  const data = ev.data;
  if (data.kind !== "AuthSessionStatus") return;
  set((prev) => ({
    ...prev,
    [data.role]: {
      role: data.role,
      status: data.status,
      acquiredBy: data.acquired_by,
      message: data.message,
      ts: data.ts_ms,
    },
  }));
}

function orderAuthSessions(sessions: AuthSessionMap): AuthSessionProgress[] {
  return Object.values(sessions).sort((a, b) => {
    if (a.role === "anonymous") return -1;
    if (b.role === "anonymous") return 1;
    return a.role.localeCompare(b.role);
  });
}

function applyToPhases(ev: AgentEventLike, set: PhaseSetter) {
  if (!("kind" in ev) || ev.kind !== "Run") return;
  const data = ev.data;
  if (data.kind === "PhaseStarted") {
    set((prev) => ({
      ...prev,
      [data.phase]: {
        ...(prev[data.phase] ?? {
          phase: data.phase,
          label: formatPhase(data.phase),
          status: "pending",
        }),
        status: "running",
        startedAt: data.started_at_ms,
      },
    }));
  }
  if (data.kind === "PhaseFinished") {
    set((prev) => ({
      ...prev,
      [data.phase]: {
        ...(prev[data.phase] ?? {
          phase: data.phase,
          label: formatPhase(data.phase),
          status: "pending",
        }),
        status: "finished",
        finishedAt: data.finished_at_ms,
        message: data.message,
      },
    }));
  }
}

function orderPhases(phases: PhaseMap): PhaseProgress[] {
  return Object.values(phases).sort((a, b) => {
    const ai = PHASE_ORDER.indexOf(a.phase);
    const bi = PHASE_ORDER.indexOf(b.phase);
    if (ai !== -1 || bi !== -1) return (ai === -1 ? 999 : ai) - (bi === -1 ? 999 : bi);
    return a.label.localeCompare(b.label);
  });
}

function phaseTone(status: PhaseProgress["status"]): BadgeTone {
  if (status === "running") return "info";
  if (status === "finished") return "success";
  return "neutral";
}

function authTone(status: string): BadgeTone {
  if (status === "acquired" || status === "reused") return "success";
  if (status === "skipped") return "warning";
  if (status === "failed") return "danger";
  return "neutral";
}

function applyToLogs(ev: AgentEventLike, set: LogSetter) {
  if (!("kind" in ev)) return;
  if (ev.kind === "Lagged") {
    appendLog(set, {
      ts: Date.now(),
      level: "warn",
      text: `[lagged] skipped ${ev.skipped} frame(s)`,
    });
    return;
  }
  if (ev.kind === "Ai") {
    const text = describeAiEvent(ev.data);
    if (!text) return;
    const level: LogLine["level"] = ev.data.kind === "TaskHalted" ? "warn" : "info";
    appendLog(set, { ts: Date.now(), level, text });
    return;
  }
  if (ev.kind === "Sandbox") {
    const text = describeSandboxEvent(ev.data);
    if (!text) return;
    appendLog(set, { ts: Date.now(), level: "info", text });
    return;
  }
  if (ev.kind !== "Run") return;
  const data = ev.data;
  const text = describeRunEvent(data);
  if (!text) return;
  const level: LogLine["level"] = data.kind === "RepoFailed" ? "error" : "info";
  appendLog(set, { ts: Date.now(), level, text });
}

function appendLog(set: LogSetter, line: LogLine) {
  set((prev) => prev.concat(line).slice(-MAX_LIVE_LOG_LINES));
}

function describeRunEvent(data: RunEvent): string | undefined {
  switch (data.kind) {
    case "Heartbeat":
      return undefined;
    case "ProjectStarted":
      return `Project ${data.project_name} started.`;
    case "PhaseStarted":
      return `${formatPhase(data.phase)} started.`;
    case "PhaseFinished":
      return data.message
        ? `${formatPhase(data.phase)}: ${data.message}`
        : `${formatPhase(data.phase)} finished.`;
    case "EnvironmentStatus":
      return data.message
        ? `App ${formatEnvironmentStatus(data.status)}: ${data.message}`
        : `App ${formatEnvironmentStatus(data.status)}.`;
    case "AuthSessionStatus":
      return data.message
        ? `[auth ${data.role}] ${data.status}: ${data.message}`
        : `[auth ${data.role}] ${data.status} via ${data.acquired_by}.`;
    case "RunStarted":
      return `Pentest ${data.run_id} started over ${data.repos.length} code source(s).`;
    case "RepoStarted":
      return `[${data.repo}] static pass started.`;
    case "RepoStaticDone":
      return `[${data.repo}] static pass recorded ${data.n_diags} signal(s) in ${data.elapsed_ms}ms.`;
    case "RepoDynamicDone":
      return `[${data.repo}] dynamic pass done in ${data.elapsed_ms}ms.`;
    case "RepoFinished":
      return `[${data.repo}] source scan finished: ${data.outcome} (${data.elapsed_ms}ms).`;
    case "RepoFailed":
      return `[${data.repo}] failed: ${data.message}`;
    case "RunFinished":
      return `Pentest ${data.run_id} finished in ${data.wall_clock_ms}ms.`;
    case "RepoIngestFailed":
      return `[${data.repo}] ingest failed: ${data.message}`;
    case "ProjectFinished":
      return `Project phase finished.`;
  }
}

function describeAiEvent(data: AiEvent): string | undefined {
  switch (data.kind) {
    case "ToolCallStarted":
      return `[AI ${data.task_id}] tool ${data.name} started.`;
    case "ToolCallFinished":
      return `[AI ${data.task_id}] tool ${data.name} ${data.ok ? "finished" : "failed"}.`;
    case "TaskHalted":
      return `[AI ${data.task_id}] halted: ${data.reason}.`;
    case "TokenReceived":
      return `[AI ${data.task_id}] ${truncateLogToken(data.token)}`;
    case "CacheHit":
      return `[AI ${data.task_id}] cache hit: ${data.tokens} token(s).`;
    case "CacheMiss":
      return `[AI ${data.task_id}] cache miss: ${data.tokens} token(s).`;
    case "BudgetTick":
      return `[AI ${data.task_id}] budget spent: $${(data.spent_usd_micros / 1_000_000).toFixed(
        6,
      )}.`;
  }
}

function truncateLogToken(token: string): string {
  const compact = token.replace(/\s+/g, " ").trim();
  return compact.length > 280 ? `${compact.slice(0, 277)}...` : compact;
}

function describeSandboxEvent(data: SandboxEvent): string | undefined {
  switch (data.kind) {
    case "VerifierStarted":
      return `[${data.repo}] verifier started for ${data.finding_id}.`;
    case "VerifierFinished":
      return `[${data.repo}] verifier ${data.verdict} for ${data.finding_id} in ${
        data.elapsed_ms
      }ms.`;
  }
}

function formatEnvironmentStatus(status: string): string {
  if (status === "SettingUp") return "Setting up";
  return status;
}

function formatPhase(phase: string): string {
  if (phase === "EnvironmentBuildStarted") return "App launch";
  if (phase === "EnvironmentReady") return "App ready";
  if (phase === "NyxSignalsStarted") return "Static analysis";
  if (phase === "RouteModelStarted") return "Route/auth modeling";
  if (phase === "OptionalScannersStarted") return "Optional scanners";
  if (phase === "CandidateSynthesisStarted") return "Candidate synthesis";
  if (phase === "AgentReviewStarted") return "AI pentest review";
  if (phase === "AiAttackPlanningStarted") return "AI attack planning";
  if (phase === "AuthSessionAcquisitionStarted") return "Auth sessions";
  if (phase === "LiveVerificationStarted") return "Live verification";
  if (phase === "BrowserVerificationStarted") return "Browser verification";
  return phase;
}

function applyToSummary(ev: AgentEventLike, set: SummarySetter) {
  if (!("kind" in ev) || ev.kind !== "Run") return;
  const data = ev.data;
  if (data.kind === "RunStarted") {
    set(() => ({ done: false, startedAt: data.started_at_ms }));
    return;
  }
  if (data.kind === "RunFinished") {
    set((prev) => ({
      ...prev,
      done: true,
      finishedAt: data.finished_at_ms,
      wallClockMs: data.wall_clock_ms,
      succeeded: data.succeeded,
      inconclusive: data.inconclusive,
      failed: data.failed,
    }));
  }
}

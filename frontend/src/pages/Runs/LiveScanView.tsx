import { useMemo, useState } from "react";
import { Link, useNavigate, useParams } from "react-router-dom";
import {
  type AgentEventLike,
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

export function LiveScanView() {
  const { runId = "" } = useParams<{ runId: string }>();
  const navigate = useNavigate();
  const [repos, setRepos] = useState<Record<string, RepoProgress>>({});
  const [logs, setLogs] = useState<LogLine[]>([]);
  const [summary, setSummary] = useState<RunSummary>({ done: false });
  const environmentRuns = useRunEnvironmentRuns(runId);
  const vulnerabilities = useRunVulnerabilities(runId);

  useAgentEvents({
    runId,
    onEvent: (ev) => {
      applyToRepos(ev, setRepos);
      applyToLogs(ev, setLogs);
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
          </div>
        }
      >
        {!summary.done && totalRepos === 0 && (
          <div className="live-scan__pending">
            <Spinner /> Preparing app...
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

        {orderedRepos.length > 0 && (
          <ul className="live-scan__repos">
            {orderedRepos.map((repo) => (
              <RepoProgressRow key={repo.name} repo={repo} />
            ))}
          </ul>
        )}

        <section className="live-scan__logs">
          <h3 className="live-scan__h3">Stream</h3>
          {logs.length === 0 ? (
            <p className="live-scan__muted">No log lines yet.</p>
          ) : (
            <ol className="live-scan__log">
              {logs.slice(-200).map((line, idx) => (
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
  const pct = phaseToPercent(repo.phase);
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
      <div
        className="live-scan__bar"
        role="progressbar"
        aria-valuenow={pct}
        aria-valuemin={0}
        aria-valuemax={100}
      >
        <div
          className={`live-scan__bar-fill live-scan__bar-fill--${repo.phase}`}
          style={{ width: `${pct}%` }}
        />
      </div>
      {repo.message && (
        <p className="live-scan__repo-msg" title={repo.message}>
          {repo.message}
        </p>
      )}
    </li>
  );
}

function phaseToPercent(phase: RepoPhase): number {
  switch (phase) {
    case "queued":
      return 5;
    case "static":
      return 40;
    case "static-done":
      return 70;
    case "dynamic-done":
      return 90;
    case "finished":
      return 100;
    case "failed":
      return 100;
  }
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

function applyToLogs(ev: AgentEventLike, set: LogSetter) {
  if (!("kind" in ev)) return;
  if (ev.kind === "Lagged") {
    set((prev) =>
      prev.concat({
        ts: Date.now(),
        level: "warn",
        text: `[lagged] skipped ${ev.skipped} frame(s)`,
      }),
    );
    return;
  }
  if (ev.kind === "Ai") {
    const text = describeAiEvent(ev.data);
    if (!text) return;
    const level: LogLine["level"] = ev.data.kind === "TaskHalted" ? "warn" : "info";
    set((prev) => prev.concat({ ts: Date.now(), level, text }).slice(-500));
    return;
  }
  if (ev.kind === "Sandbox") {
    const text = describeSandboxEvent(ev.data);
    if (!text) return;
    set((prev) => prev.concat({ ts: Date.now(), level: "info", text }).slice(-500));
    return;
  }
  if (ev.kind !== "Run") return;
  const data = ev.data;
  const text = describeRunEvent(data);
  if (!text) return;
  const level: LogLine["level"] = data.kind === "RepoFailed" ? "error" : "info";
  set((prev) => prev.concat({ ts: Date.now(), level, text }).slice(-500));
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
  if (phase === "AgentReviewStarted") return "AI pentest review";
  if (phase === "LiveVerificationStarted") return "Live verification";
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

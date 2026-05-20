import { useMemo, useRef, useState } from "react";
import { Badge } from "@/components/Badge";
import { Button } from "@/components/Button";
import { CodeExcerpt, type CodeExcerptLine } from "@/components/CodeExcerpt";
import { Spinner } from "@/components/Spinner";
import { AiTraceViewer } from "@/components/AiTraceViewer";
import {
  reproBundleDownloadUrl,
  startReplayStream,
  useBuildReproBundle,
  useFinding,
  type BundleManifest,
  type FindingRecord,
  type ReplayEvent,
} from "@/api/client";
import { ORIGIN_TONE, SEVERITY_TONE, STATUS_TONE } from "./diff";

export interface FindingDetailProps {
  id: string;
  onClose: () => void;
}

interface FlowStep {
  path: string;
  line?: number;
  message?: string;
}

interface Evidence {
  message?: string;
  flow_steps?: FlowStep[];
  source?: unknown;
  sink?: unknown;
  symbolic?: unknown;
  notes?: string | string[];
  source_excerpt?: string;
  [key: string]: unknown;
}

export function FindingDetail({ id, onClose }: FindingDetailProps) {
  const finding = useFinding(id);
  const evidence = useMemo(() => parseEvidence(finding.data), [finding.data]);

  return (
    <aside
      className="finding-detail"
      role="complementary"
      aria-label="Finding detail"
    >
      <header className="finding-detail__header">
        <div>
          <h2 className="finding-detail__title">Finding</h2>
          {finding.data && (
            <p className="finding-detail__subtitle" title={finding.data.id}>
              {finding.data.cap} · {finding.data.rule}
            </p>
          )}
        </div>
        <button
          type="button"
          className="finding-detail__close"
          aria-label="Close detail panel"
          onClick={onClose}
        >
          ×
        </button>
      </header>

      <div className="finding-detail__body">
        {finding.isPending && (
          <div className="finding-detail__pending">
            <Spinner /> Loading finding…
          </div>
        )}
        {finding.error && (
          <p className="finding-detail__error" role="alert">
            Failed to load finding: {String(finding.error)}
          </p>
        )}
        {finding.data && <FindingDetailBody finding={finding.data} evidence={evidence} />}
      </div>
    </aside>
  );
}

interface BodyProps {
  finding: FindingRecord;
  evidence: Evidence | null;
}

function FindingDetailBody({ finding, evidence }: BodyProps) {
  return (
    <>
      <section className="finding-detail__section">
        <h3 className="finding-detail__h3">Location</h3>
        <p className="finding-detail__location">
          <span className="finding-detail__repo">{finding.repo}</span>
          {" / "}
          <span className="finding-detail__path">{finding.path}</span>
          {finding.line !== null && (
            <span className="finding-detail__line"> :{finding.line}</span>
          )}
        </p>
        {evidence?.message && <p className="finding-detail__msg">{evidence.message}</p>}
      </section>

      <section className="finding-detail__section">
        <h3 className="finding-detail__h3">Provenance</h3>
        <div className="finding-detail__badges">
          <Badge tone={SEVERITY_TONE[finding.severity] ?? "neutral"}>{finding.severity}</Badge>
          <Badge tone={STATUS_TONE[finding.status] ?? "neutral"}>{finding.status}</Badge>
          <Badge tone={ORIGIN_TONE[finding.finding_origin] ?? "neutral"}>
            {finding.finding_origin}
          </Badge>
          {finding.triage_state !== "Open" && (
            <Badge tone="warning">triage: {finding.triage_state}</Badge>
          )}
          {finding.attack_provenance && (
            <Badge tone="info" title={finding.attack_provenance}>
              attack provenance
            </Badge>
          )}
          {finding.chain_id && (
            <Badge tone="accent" title={finding.chain_id}>
              chain
            </Badge>
          )}
        </div>
        <dl className="finding-detail__meta">
          <dt>Run</dt>
          <dd>{finding.run_id}</dd>
          <dt>First seen</dt>
          <dd>{new Date(finding.first_seen).toLocaleString()}</dd>
          <dt>Last seen</dt>
          <dd>{new Date(finding.last_seen).toLocaleString()}</dd>
        </dl>
      </section>

      <SourceExcerpt finding={finding} evidence={evidence} />

      <FlowStepsBlock steps={evidence?.flow_steps ?? []} />

      <DynamicVerdict finding={finding} evidence={evidence} />

      <ReproBundleSection finding={finding} />

      <AiReasoningSection finding={finding} />
    </>
  );
}

interface ReproBundleSectionProps {
  finding: FindingRecord;
}

function ReproBundleSection({ finding }: ReproBundleSectionProps) {
  const build = useBuildReproBundle();
  const [manifest, setManifest] = useState<BundleManifest | null>(null);
  const [replayLines, setReplayLines] = useState<ReplayEvent[]>([]);
  const [replayStatus, setReplayStatus] = useState<
    "idle" | "running" | "done" | "error"
  >("idle");
  const stopRef = useRef<(() => void) | null>(null);

  const downloadUrl = reproBundleDownloadUrl(finding.id);

  const onBuild = async () => {
    try {
      const m = await build.mutateAsync(finding.id);
      setManifest(m);
    } catch {
      // surfaced via build.error below
    }
  };

  const onReplay = () => {
    setReplayLines([]);
    setReplayStatus("running");
    stopRef.current?.();
    stopRef.current = startReplayStream(finding.id, (ev) => {
      setReplayLines((prev) => [...prev, ev]);
      if (ev.kind === "end") setReplayStatus("done");
      if (ev.kind === "error") setReplayStatus("error");
    });
  };

  const onStop = () => {
    stopRef.current?.();
    stopRef.current = null;
    setReplayStatus("idle");
  };

  return (
    <section className="finding-detail__section">
      <h3 className="finding-detail__h3">Repro bundle</h3>
      <div className="finding-detail__actions">
        <Button size="sm" onClick={onBuild} disabled={build.isPending}>
          {build.isPending ? "Building…" : manifest ? "Rebuild bundle" : "Build bundle"}
        </Button>
        <a
          className="btn btn--sm"
          href={downloadUrl}
          download={`${finding.id}.tar`}
        >
          Download repro bundle
        </a>
        <Button
          size="sm"
          variant="primary"
          onClick={onReplay}
          disabled={replayStatus === "running"}
        >
          {replayStatus === "running" ? "Replaying…" : "Replay locally"}
        </Button>
        {replayStatus === "running" && (
          <Button size="sm" variant="ghost" onClick={onStop}>
            Stop
          </Button>
        )}
      </div>
      {build.error && (
        <p className="finding-detail__error" role="alert">
          Bundle build failed: {String(build.error)}
        </p>
      )}
      {manifest && (
        <dl className="finding-detail__meta">
          <dt>Bundle path</dt>
          <dd>
            <code className="finding-detail__code">{manifest.bundle_path}</code>
          </dd>
          <dt>SHA-256</dt>
          <dd>
            <code className="finding-detail__code">{manifest.sha256}</code>
          </dd>
          <dt>Size</dt>
          <dd>{manifest.byte_size} bytes</dd>
          <dt>Artifacts</dt>
          <dd>{manifest.artifacts.join(", ")}</dd>
        </dl>
      )}
      {replayLines.length > 0 && (
        <pre className="finding-detail__replay-log" aria-live="polite">
          {replayLines.map((ev, idx) => (
            <span key={idx} className={`finding-detail__replay-line finding-detail__replay-line--${ev.kind}`}>
              [{ev.kind}] {ev.data}
              {"\n"}
            </span>
          ))}
        </pre>
      )}
      {replayStatus === "idle" && replayLines.length === 0 && (
        <p className="finding-detail__muted">
          Build a bundle, then replay it locally on this host. The daemon
          spawns <code>bash repro.sh</code> in a sandboxed tempdir and
          streams stdout / stderr back into this panel.
        </p>
      )}
    </section>
  );
}

interface SourceExcerptProps {
  finding: FindingRecord;
  evidence: Evidence | null;
}

function SourceExcerpt({ finding, evidence }: SourceExcerptProps) {
  // Phase 11 ships a placeholder excerpt: the daemon does not yet persist
  // the raw source line, so we render the rule message + the file:line
  // anchor. When Phase 12 wires AI verdicts (and the persist path lifts
  // Diag.evidence into the verdict_blob), the lines below pick up the
  // real `source_excerpt` payload.
  const lines = useMemo<CodeExcerptLine[]>(() => {
    if (evidence && typeof evidence.source_excerpt === "string") {
      const startLine = finding.line ?? 1;
      const code = evidence.source_excerpt.split("\n");
      return code.map((text, idx) => ({
        lineno: startLine + idx,
        code: text,
        highlight: idx === 0,
      }));
    }
    const fallbackLine = finding.line ?? 1;
    return [
      {
        lineno: fallbackLine,
        code: evidence?.message ?? `// ${finding.path}:${fallbackLine}`,
        highlight: true,
      },
    ];
  }, [evidence, finding]);

  return (
    <section className="finding-detail__section">
      <h3 className="finding-detail__h3">Source excerpt</h3>
      <CodeExcerpt lines={lines} />
    </section>
  );
}

interface FlowStepsBlockProps {
  steps: FlowStep[];
}

function FlowStepsBlock({ steps }: FlowStepsBlockProps) {
  if (steps.length === 0) {
    return (
      <section className="finding-detail__section">
        <h3 className="finding-detail__h3">Flow steps</h3>
        <p className="finding-detail__muted">No flow steps recorded for this finding.</p>
      </section>
    );
  }
  return (
    <section className="finding-detail__section">
      <h3 className="finding-detail__h3">Flow steps</h3>
      <ol className="finding-detail__flow">
        {steps.map((step, idx) => (
          <li key={idx}>
            <button
              type="button"
              className="finding-detail__flow-step"
              onClick={() => {
                // Phase 11 stub: no editor jump yet. Surface the
                // target so the operator can copy it; Phase 22's
                // editor integration owns the click.
                const target = `${step.path}${step.line ? `:${step.line}` : ""}`;
                window.alert(`Step → ${target}`);
              }}
            >
              <span className="finding-detail__flow-path">{step.path}</span>
              {step.line && (
                <span className="finding-detail__flow-line"> :{step.line}</span>
              )}
              {step.message && (
                <span className="finding-detail__flow-msg"> · {step.message}</span>
              )}
            </button>
          </li>
        ))}
      </ol>
    </section>
  );
}

interface DynamicVerdictProps {
  finding: FindingRecord;
  evidence: Evidence | null;
}

function DynamicVerdict({ finding, evidence }: DynamicVerdictProps) {
  const hasRepro = Boolean(finding.repro_path);
  return (
    <section className="finding-detail__section">
      <h3 className="finding-detail__h3">Dynamic verdict</h3>
      {hasRepro ? (
        <p>
          <Badge tone="danger">verified</Badge>{" "}
          <code className="finding-detail__code">{finding.repro_path}</code>
        </p>
      ) : (
        <p className="finding-detail__muted">
          No dynamic verdict yet. Sandbox + repro will land in Phase 18 and Phase 26.
        </p>
      )}
      {evidence?.notes && <NotesBlock notes={evidence.notes} />}
    </section>
  );
}

function NotesBlock({ notes }: { notes: string | string[] }) {
  const list = Array.isArray(notes) ? notes : [notes];
  return (
    <ul className="finding-detail__notes">
      {list.map((note, idx) => (
        <li key={idx}>{note}</li>
      ))}
    </ul>
  );
}

interface AiReasoningSectionProps {
  finding: FindingRecord;
}

function AiReasoningSection({ finding }: AiReasoningSectionProps) {
  const [open, setOpen] = useState(false);
  return (
    <section className="finding-detail__section">
      <header className="finding-detail__row">
        <h3 className="finding-detail__h3">AI reasoning</h3>
        <Button size="sm" variant="ghost" onClick={() => setOpen((v) => !v)}>
          {open ? "Hide" : "Expand"}
        </Button>
      </header>
      {open ? (
        <AiTraceViewer findingId={finding.id} />
      ) : (
        <p className="finding-detail__muted">Collapsed. Expand to read the per-turn trace.</p>
      )}
    </section>
  );
}

function parseEvidence(finding: FindingRecord | undefined): Evidence | null {
  if (!finding?.verdict_blob) return null;
  try {
    return JSON.parse(finding.verdict_blob) as Evidence;
  } catch {
    return { message: finding.verdict_blob };
  }
}

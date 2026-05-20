import { useMemo, useState } from "react";
import { Badge } from "./Badge";
import { Spinner } from "./Spinner";
import { useFindingTraces, type AgentTraceRow } from "@/api/client";

export interface AiTraceViewerProps {
  /**
   * The finding (or candidate) id to fetch traces for. The backend's
   * `agent_traces.finding_id` foreign key uses the same id space as
   * `findings.id`; for candidates whose verifier promote has not yet
   * fired the list will be empty (the trace row is keyed to the
   * promoted finding once it lands).
   */
  findingId: string;
}

/**
 * Per-turn audit view of an AI task's conversation. Phase 24 surfaces
 * one card per `agent_traces` row, since the per-pass outcome
 * envelopes do not yet carry per-message prompt + response bodies.
 * The deferred items that asked for this row in the first place track
 * widening the envelope; until then this surface is "every AI call
 * that touched this finding", with cost + duration stamped per row.
 *
 * Each card is collapsible so dense traces do not flood the panel.
 * Tool-use turns expand inline when the trace fields lift into the
 * row (today the row carries task-level metadata only).
 */
export function AiTraceViewer({ findingId }: AiTraceViewerProps) {
  const query = useFindingTraces(findingId);

  if (query.isPending) {
    return (
      <div className="ai-trace-viewer ai-trace-viewer--pending">
        <Spinner /> Loading trace…
      </div>
    );
  }
  if (query.error) {
    return (
      <p className="ai-trace-viewer ai-trace-viewer--error" role="alert">
        Failed to load trace: {String(query.error)}
      </p>
    );
  }

  const rows = query.data ?? [];
  if (rows.length === 0) {
    return (
      <p className="ai-trace-viewer ai-trace-viewer--empty">
        No AI calls recorded for this finding yet.
      </p>
    );
  }

  return (
    <div className="ai-trace-viewer">
      <header className="ai-trace-viewer__header">
        <h3 className="ai-trace-viewer__title">AI conversation</h3>
        <p className="ai-trace-viewer__subtitle">
          {rows.length} turn{rows.length === 1 ? "" : "s"} ·{" "}
          <CostInline rows={rows} />
        </p>
      </header>
      <ol className="ai-trace-viewer__list">
        {rows.map((row, idx) => (
          <TraceRowCard key={row.id} row={row} index={idx + 1} />
        ))}
      </ol>
    </div>
  );
}

function CostInline({ rows }: { rows: AgentTraceRow[] }) {
  const total = rows.reduce((acc, r) => acc + r.cost_usd_micros, 0);
  return <span>${(total / 1_000_000).toFixed(6)}</span>;
}

function TraceRowCard({ row, index }: { row: AgentTraceRow; index: number }) {
  const [open, setOpen] = useState(false);
  const subtitle = useMemo(() => formatSubtitle(row), [row]);

  return (
    <li className="ai-trace-viewer__turn">
      <button
        type="button"
        className={`ai-trace-viewer__turn-toggle${open ? " is-open" : ""}`}
        aria-expanded={open}
        onClick={() => setOpen((prev) => !prev)}
      >
        <span className="ai-trace-viewer__turn-chevron" aria-hidden="true">
          {open ? "▾" : "▸"}
        </span>
        <span className="ai-trace-viewer__turn-index">#{index}</span>
        <span className="ai-trace-viewer__turn-kind">
          <Badge tone={toneForTaskKind(row.task_kind)}>{row.task_kind}</Badge>
        </span>
        <span className="ai-trace-viewer__turn-subtitle">{subtitle}</span>
      </button>
      {open && (
        <dl className="ai-trace-viewer__turn-body">
          <Row label="Trace id" value={<code>{row.id}</code>} />
          <Row label="Runtime" value={row.runtime_name} />
          <Row label="Model" value={row.model || <em>unspecified</em>} />
          <Row
            label="Prompt version"
            value={row.prompt_version ?? <em>unknown</em>}
          />
          <Row label="Tokens in" value={String(row.tokens_in)} />
          <Row label="Tokens out" value={String(row.tokens_out)} />
          <Row
            label="Cache hits / misses"
            value={`${row.cache_hits} / ${row.cache_misses}`}
          />
          <Row label="Cost" value={`$${(row.cost_usd_micros / 1_000_000).toFixed(6)}`} />
          <Row
            label="Duration"
            value={row.duration_ms !== null ? `${row.duration_ms} ms` : "-"}
          />
          <Row label="Started" value={formatStamp(row.started_at)} />
          <Row
            label="Finished"
            value={row.finished_at !== null ? formatStamp(row.finished_at) : "-"}
          />
          {row.conversation_jsonl_path && (
            <Row
              label="JSONL log"
              value={<code>{row.conversation_jsonl_path}</code>}
            />
          )}
        </dl>
      )}
    </li>
  );
}

function Row({ label, value }: { label: string; value: React.ReactNode }) {
  return (
    <div className="ai-trace-viewer__turn-row">
      <dt className="ai-trace-viewer__turn-label">{label}</dt>
      <dd className="ai-trace-viewer__turn-value">{value}</dd>
    </div>
  );
}

function formatSubtitle(row: AgentTraceRow): string {
  const cost = `$${(row.cost_usd_micros / 1_000_000).toFixed(6)}`;
  const dur =
    row.duration_ms !== null && row.duration_ms > 0
      ? ` · ${row.duration_ms}ms`
      : "";
  return `${row.runtime_name} · ${cost}${dur}`;
}

function formatStamp(ms: number): string {
  if (!Number.isFinite(ms) || ms === 0) return "-";
  return new Date(ms).toLocaleString();
}

function toneForTaskKind(
  kind: string,
): "info" | "warning" | "success" | "neutral" | "accent" {
  switch (kind) {
    case "PayloadSynthesis":
      return "info";
    case "SpecDerivation":
      return "info";
    case "ChainReasoning":
      return "success";
    case "NovelFindings":
      return "warning";
    case "Exploration":
      return "accent";
    default:
      return "neutral";
  }
}

import { useMemo, useState } from "react";
import { useParams } from "react-router-dom";
import {
  type QuarantineItem,
  useDismissQuarantine,
  usePromoteQuarantine,
  useQuarantine,
} from "@/api/client";
import { AiTraceViewer } from "@/components/AiTraceViewer";
import { Badge, type BadgeTone } from "@/components/Badge";
import { Button } from "@/components/Button";
import { Card } from "@/components/Card";
import { EmptyState } from "@/components/EmptyState";
import { PageHeader, PageShell } from "@/components/Page";
import { Spinner } from "@/components/Spinner";
import { useToast } from "@/components/Toast";

const KIND_TONE: Record<QuarantineItem["kind"], BadgeTone> = {
  finding: "warning",
  candidate: "info",
};

const KIND_LABEL: Record<QuarantineItem["kind"], string> = {
  finding: "Finding",
  candidate: "Candidate",
};

/**
 * Operator-facing Quarantine surface. Phase 24 keeps the page hidden
 * behind Settings → Show advanced. AI-discovered findings that have
 * not yet been dynamic-confirmed land here; a manual promote moves
 * the row into the regular Findings table.
 */
export function QuarantineList() {
  const { projectId } = useParams<{ projectId?: string }>();
  const query = useQuarantine(projectId);
  const promote = usePromoteQuarantine();
  const dismiss = useDismissQuarantine();
  const { showToast } = useToast();
  const [selectedId, setSelectedId] = useState<string | null>(null);

  const rows = query.data ?? [];
  const counts = useMemo(() => {
    const findings = rows.filter((r) => r.kind === "finding").length;
    const candidates = rows.filter((r) => r.kind === "candidate").length;
    return { findings, candidates };
  }, [rows]);

  async function onPromote(item: QuarantineItem) {
    showToast(`Promoting ${shortId(item.id)}...`, { tone: "info" });
    try {
      await promote.mutateAsync(item.id);
      showToast(`Promoted ${shortId(item.id)} into findings.`, { tone: "success" });
    } catch (err) {
      showToast(`Promote failed for ${shortId(item.id)}: ${String(err)}`, { tone: "danger" });
    }
  }

  async function onDismiss(item: QuarantineItem) {
    if (
      !window.confirm(
        `Dismiss quarantined ${KIND_LABEL[item.kind].toLowerCase()} ${shortId(item.id)}? This closes the row without confirming.`,
      )
    ) {
      return;
    }
    showToast(`Dismissing ${shortId(item.id)}...`, { tone: "info" });
    try {
      await dismiss.mutateAsync(item.id);
      showToast(`Dismissed ${shortId(item.id)}.`, { tone: "success" });
      if (selectedId === item.id) setSelectedId(null);
    } catch (err) {
      showToast(`Dismiss failed for ${shortId(item.id)}: ${String(err)}`, { tone: "danger" });
    }
  }

  const selected = rows.find((r) => r.id === selectedId) ?? null;
  const countLabel = query.isPending
    ? "Loading quarantine..."
    : `${counts.findings + counts.candidates} awaiting review`;

  return (
    <PageShell size="wide" className="quarantine-page">
      <PageHeader
        title="Candidate Queue"
        meta={countLabel}
        actions={
          <Button onClick={() => query.refetch()} disabled={query.isPending}>
            Refresh
          </Button>
        }
      />

      <Card className="quarantine-page__list">
        {query.isPending && (
          <div className="quarantine-page__pending">
            <Spinner /> Loading quarantine...
          </div>
        )}
        {query.error && (
          <p role="alert" className="quarantine-page__error">
            Failed to load quarantine: {String(query.error)}
          </p>
        )}
        {!query.isPending && rows.length === 0 && <EmptyState title="Nothing in quarantine" />}
        {rows.length > 0 && (
          <div className="table-scroll">
            <table className="quarantine-page__table data-table">
              <thead>
                <tr>
                  <th scope="col">Kind</th>
                  <th scope="col">Cap</th>
                  <th scope="col">Repo</th>
                  <th scope="col">Path</th>
                  <th scope="col">Rationale</th>
                  <th scope="col" aria-label="Row actions" />
                </tr>
              </thead>
              <tbody>
                {rows.map((row) => {
                  const isSelected = row.id === selectedId;
                  return (
                    <tr
                      key={row.id}
                      className={`quarantine-page__row${isSelected ? " is-selected" : ""}`}
                    >
                      <td>
                        <Badge tone={KIND_TONE[row.kind]}>{KIND_LABEL[row.kind]}</Badge>
                      </td>
                      <td>
                        <code>{row.cap}</code>
                      </td>
                      <td>{row.repo}</td>
                      <td>
                        <button
                          type="button"
                          className="quarantine-page__pathlink"
                          onClick={() => setSelectedId(isSelected ? null : row.id)}
                        >
                          {row.path}
                          {row.line !== null ? `:${row.line}` : ""}
                        </button>
                      </td>
                      <td className="quarantine-page__rationale">
                        {row.rationale ?? extractRationale(row.verdict_blob)}
                      </td>
                      <td className="quarantine-page__actions">
                        <Button onClick={() => onPromote(row)} disabled={promote.isPending}>
                          Promote
                        </Button>
                        <Button
                          variant="ghost"
                          onClick={() => onDismiss(row)}
                          disabled={dismiss.isPending}
                        >
                          Dismiss
                        </Button>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </Card>

      {selected && (
        <aside className="quarantine-page__side">
          <QuarantineDetail item={selected} onClose={() => setSelectedId(null)} />
        </aside>
      )}
    </PageShell>
  );
}

function QuarantineDetail({ item, onClose }: { item: QuarantineItem; onClose: () => void }) {
  return (
    <Card
      title={`${KIND_LABEL[item.kind]} · ${item.cap}`}
      subtitle={`${item.repo} / ${item.path}${item.line !== null ? `:${item.line}` : ""}`}
      actions={
        <Button variant="ghost" onClick={onClose}>
          Close
        </Button>
      }
    >
      <dl className="quarantine-detail__meta">
        <div>
          <dt>Origin</dt>
          <dd>{item.finding_origin ?? "-"}</dd>
        </div>
        <div>
          <dt>Prompt</dt>
          <dd>
            <code>{item.prompt_version ?? "-"}</code>
          </dd>
        </div>
        <div>
          <dt>Provenance</dt>
          <dd>{item.attack_provenance ?? "-"}</dd>
        </div>
        <div>
          <dt>Run</dt>
          <dd>
            <code>{item.run_id}</code>
          </dd>
        </div>
      </dl>
      {item.rationale && (
        <section className="quarantine-detail__rationale">
          <h4>Rationale</h4>
          <p>{item.rationale}</p>
        </section>
      )}
      {item.verdict_blob && item.kind === "finding" && (
        <section className="quarantine-detail__rationale">
          <h4>Verdict blob</h4>
          <pre className="quarantine-detail__blob">{item.verdict_blob}</pre>
        </section>
      )}
      <AiTraceViewer findingId={item.id} />
    </Card>
  );
}

function shortId(id: string): string {
  return id.length > 16 ? `${id.slice(0, 16)}…` : id;
}

/** Pull a `rationale` string out of a typed verdict blob, if present. */
function extractRationale(blob: string | null): string {
  if (!blob) return "-";
  try {
    const parsed: unknown = JSON.parse(blob);
    if (parsed && typeof parsed === "object" && "rationale" in parsed) {
      const v = (parsed as { rationale?: unknown }).rationale;
      if (typeof v === "string") return v;
    }
    if (parsed && typeof parsed === "object" && "reason" in parsed) {
      const v = (parsed as { reason?: unknown }).reason;
      if (typeof v === "string") return v;
    }
  } catch {
    // not JSON; fall through
  }
  return "-";
}

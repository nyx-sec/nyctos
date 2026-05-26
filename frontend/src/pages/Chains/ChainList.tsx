import { useMemo } from "react";
import { Link, useParams, useSearchParams } from "react-router-dom";
import { type ChainRecord, type RunRecord, useRunChains, useRuns } from "@/api/client";
import { Badge } from "@/components/Badge";
import { Card } from "@/components/Card";
import { EmptyState } from "@/components/EmptyState";
import { PageHeader, PageShell } from "@/components/Page";
import { Spinner } from "@/components/Spinner";
import { extractChainRationale } from "@/pages/Findings/FindingList";
import { parseChainEvidence } from "./chainEvidence";
import { parseMemberIds } from "./memberIds";

const RATIONALE_PREVIEW_CHARS = 160;

export function ChainList() {
  const { projectId } = useParams<{ projectId?: string }>();
  const [params, setParams] = useSearchParams();
  const runIdParam = params.get("run_id") ?? undefined;

  // The chain explorer is anchored on a single run. Operators pick a
  // run via the URL query param; otherwise we default to the most
  // recent Succeeded run so the page is useful on first visit.
  const succeededQuery = useRuns("Succeeded", projectId);
  const succeededRuns = succeededQuery.data ?? [];
  const fallbackRunId = succeededRuns[0]?.id;
  const runId = runIdParam ?? fallbackRunId;

  const chainsQuery = useRunChains(runId);
  const chains = chainsQuery.data ?? [];

  function setRunId(next: string | undefined) {
    const search = new URLSearchParams(params);
    if (next) search.set("run_id", next);
    else search.delete("run_id");
    setParams(search, { replace: true });
  }

  const hasCompletedRuns = succeededRuns.length > 0;
  const isLoadingRuns = succeededQuery.isPending;
  const isLoadingChains = Boolean(runId) && chainsQuery.isPending;

  const headerMeta = useMemo(() => {
    if (isLoadingRuns) return "Loading runs…";
    if (!runId) return "No completed runs yet";
    const total = chains.length;
    const crossRepo = chains.filter((c) => c.cross_repo).length;
    if (total === 0) return `Run ${runId} - no chains`;
    const tail = crossRepo > 0 ? `, ${crossRepo} cross-repo` : "";
    return `Run ${runId} - ${total} ${total === 1 ? "chain" : "chains"}${tail}`;
  }, [isLoadingRuns, runId, chains]);

  return (
    <PageShell className="findings-page">
      <PageHeader
        title="Raw Chains"
        meta={headerMeta}
        actions={
          <RunPicker
            runs={succeededRuns}
            value={runId}
            onChange={setRunId}
            disabled={isLoadingRuns || !hasCompletedRuns}
          />
        }
      />

      <Card className="table-card">
        {isLoadingChains && (
          <div className="findings-page__pending">
            <Spinner /> Loading chains…
          </div>
        )}

        {chainsQuery.error && (
          <p className="findings-page__error" role="alert">
            Failed to load chains: {String(chainsQuery.error)}
          </p>
        )}

        {!isLoadingChains && !chainsQuery.error && !runId && (
          <EmptyState title="No completed runs yet" />
        )}

        {!isLoadingChains && !chainsQuery.error && runId && chains.length === 0 && (
          <EmptyState title="No chains for this run" />
        )}

        {chains.length > 0 && <ChainTable chains={chains} projectId={projectId} />}
      </Card>
    </PageShell>
  );
}

interface RunPickerProps {
  runs: RunRecord[];
  value: string | undefined;
  onChange: (next: string | undefined) => void;
  disabled?: boolean;
}

function RunPicker({ runs, value, onChange, disabled }: RunPickerProps) {
  if (disabled || runs.length === 0) {
    return null;
  }
  return (
    <label className="findings-filter">
      <span className="findings-filter__label">Run</span>
      <select
        className="findings-filter__select"
        value={value ?? ""}
        onChange={(e) => onChange(e.target.value || undefined)}
        aria-label="Run"
      >
        {runs.map((run) => (
          <option key={run.id} value={run.id}>
            {run.id}
          </option>
        ))}
      </select>
    </label>
  );
}

interface ChainTableProps {
  chains: ChainRecord[];
  projectId?: string;
}

function ChainTable({ chains, projectId }: ChainTableProps) {
  return (
    <div className="table-scroll">
      <table className="findings-table data-table" aria-label="Chains">
        <thead>
          <tr>
            <th scope="col">Chain</th>
            <th scope="col">Scope</th>
            <th scope="col">Members</th>
            <th scope="col">Confidence</th>
            <th scope="col">Proof gaps</th>
            <th scope="col">Rationale</th>
          </tr>
        </thead>
        <tbody>
          {chains.map((chain) => {
            const rationale = extractChainRationale(chain.rationale_blob);
            const members = parseMemberIds(chain.member_ids);
            const evidence = parseChainEvidence(chain.evidence_blob);
            const proofGaps = evidence?.missing_verification_steps ?? [];
            return (
              <tr key={chain.id}>
                <td className="findings-table__repo">
                  <Link to={chainHref(chain.id, projectId)}>{shortChainId(chain.id)}</Link>
                </td>
                <td>
                  {chain.cross_repo ? (
                    <Badge tone="accent">cross-repo</Badge>
                  ) : (
                    <Badge tone="neutral">single-repo</Badge>
                  )}
                </td>
                <td>{members.length}</td>
                <td>
                  {typeof evidence?.confidence === "number" ? `${evidence.confidence}%` : "-"}
                </td>
                <td>{proofGaps.length > 0 ? proofGaps.length : "-"}</td>
                <td className="findings-table__rule" title={rationale ?? ""}>
                  {previewRationale(rationale)}
                </td>
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}

function chainHref(chainId: string, projectId: string | undefined): string {
  const encodedChain = encodeURIComponent(chainId);
  return projectId
    ? `/projects/${encodeURIComponent(projectId)}/chains/${encodedChain}`
    : `/chains/${encodedChain}`;
}

function previewRationale(rationale: string | null): string {
  if (!rationale) return "-";
  if (rationale.length <= RATIONALE_PREVIEW_CHARS) return rationale;
  return `${rationale.slice(0, RATIONALE_PREVIEW_CHARS)}…`;
}

export function shortChainId(id: string): string {
  const stripped = id.startsWith("chain-") ? id.slice("chain-".length) : id;
  return stripped.length > 16 ? `${stripped.slice(0, 16)}…` : stripped;
}

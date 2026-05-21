import { useMemo, useState } from "react";
import { useSearchParams } from "react-router-dom";
import {
  type ChainRecord,
  type FindingDiffStatus,
  type FindingRecord,
  type FindingsQuery,
  type FindingWithDiff,
  type RunFindingsQuery,
  useAllRepos,
  useFindings,
  useRunChains,
  useRunFindings,
} from "@/api/client";
import { Badge } from "@/components/Badge";
import { Button } from "@/components/Button";
import { Card } from "@/components/Card";
import { EmptyState } from "@/components/EmptyState";
import { Spinner } from "@/components/Spinner";
import { DIFF_LABEL, DIFF_TONE, ORIGIN_TONE, SEVERITY_TONE, STATUS_TONE } from "./diff";
import { FindingDetail } from "./FindingDetail";

type FilterKey = keyof Pick<FindingsQuery, "repo" | "cap" | "origin" | "status" | "severity">;

const FILTER_KEYS: FilterKey[] = ["repo", "cap", "origin", "status", "severity"];

const ORIGIN_OPTIONS = ["Static", "AI", "Manual"];
const STATUS_OPTIONS = ["Open", "Verified", "Closed"];
const SEVERITY_OPTIONS = ["Critical", "High", "Medium", "Low", "Info"];

export function FindingList() {
  const [params, setParams] = useSearchParams();
  const runId = params.get("run_id") ?? undefined;

  const filters: FindingsQuery = useMemo(() => {
    const f: FindingsQuery = {};
    for (const key of FILTER_KEYS) {
      const v = params.get(key);
      if (v) f[key] = v;
    }
    if (runId) f.run_id = runId;
    if (params.get("include_quarantine") === "true") {
      f.include_quarantine = true;
    }
    return f;
  }, [params, runId]);

  const runFilters: RunFindingsQuery = useMemo(() => {
    const f: RunFindingsQuery = {};
    for (const key of FILTER_KEYS) {
      const v = filters[key];
      if (v) f[key] = v;
    }
    return f;
  }, [filters]);

  const repos = useAllRepos();
  const runQuery = useRunFindings(runId, runFilters);
  const listQuery = useFindings(runId ? {} : filters);
  const chainsQuery = useRunChains(runId);

  // When run_id is set, the run-scoped endpoint already applies the
  // facet filters server-side and stamps diff status against the prior
  // run. The unscoped view falls back to a flat list.
  const rows: FindingWithDiff[] = useMemo(() => {
    if (runId) {
      return runQuery.data?.items ?? [];
    }
    return (listQuery.data ?? []).map((r) => ({
      ...r,
      diff_status: "unchanged" as FindingDiffStatus,
    }));
  }, [runId, runQuery.data, listQuery.data]);

  const [groupByChain, setGroupByChain] = useState(false);
  const [selected, setSelected] = useState<string | null>(() => params.get("focus"));

  function selectFinding(id: string | null) {
    setSelected(id);
    const next = new URLSearchParams(params);
    if (id) next.set("focus", id);
    else next.delete("focus");
    setParams(next, { replace: true });
  }

  const isLoading = runId ? runQuery.isPending : listQuery.isPending;
  const error = runId ? runQuery.error : listQuery.error;

  const repoOptions = useMemo(() => (repos.data ?? []).map((r) => r.name), [repos.data]);
  const capOptions = useMemo(() => uniqueValues(rows, "cap"), [rows]);

  function setFilter(key: FilterKey, value: string | undefined) {
    const next = new URLSearchParams(params);
    if (value && value !== "") next.set(key, value);
    else next.delete(key);
    setParams(next, { replace: true });
  }

  function clearAll() {
    const next = new URLSearchParams();
    if (runId) next.set("run_id", runId);
    setParams(next, { replace: true });
  }

  const chainSummaries = useMemo(
    () => buildChainSummaryIndex(chainsQuery.data ?? []),
    [chainsQuery.data],
  );
  const grouped = useMemo(
    () => groupRowsByChain(rows, groupByChain, chainSummaries),
    [rows, groupByChain, chainSummaries],
  );
  const priorRunId = runId ? (runQuery.data?.prior_run_id ?? null) : null;
  const resultSummary = isLoading
    ? "Loading findings..."
    : runId
      ? priorRunId
        ? `Run ${runId} compared with ${priorRunId}`
        : `Run ${runId}`
      : `${rows.length} active ${rows.length === 1 ? "finding" : "findings"}`;

  return (
    <div className="findings-page">
      <div className="page-toolbar">
        <p className="page-toolbar__meta">{resultSummary}</p>
        <div className="findings-page__actions">
          <label className="findings-page__toggle">
            <input
              type="checkbox"
              checked={groupByChain}
              onChange={(e) => setGroupByChain(e.target.checked)}
            />
            Group by chain
          </label>
          <label className="findings-page__toggle">
            <input
              type="checkbox"
              checked={params.get("include_quarantine") === "true"}
              onChange={(e) => {
                const next = new URLSearchParams(params);
                if (e.target.checked) next.set("include_quarantine", "true");
                else next.delete("include_quarantine");
                setParams(next, { replace: true });
              }}
            />
            Show quarantined
          </label>
          <Button variant="ghost" size="sm" onClick={clearAll}>
            Reset filters
          </Button>
        </div>
      </div>

      <Card className="table-card">
        <div className="findings-filters">
          <FilterSelect
            label="Repo"
            value={filters.repo ?? ""}
            onChange={(v) => setFilter("repo", v)}
            options={repoOptions}
          />
          <FilterSelect
            label="Cap"
            value={filters.cap ?? ""}
            onChange={(v) => setFilter("cap", v)}
            options={capOptions}
          />
          <FilterSelect
            label="Origin"
            value={filters.origin ?? ""}
            onChange={(v) => setFilter("origin", v)}
            options={ORIGIN_OPTIONS}
          />
          <FilterSelect
            label="Status"
            value={filters.status ?? ""}
            onChange={(v) => setFilter("status", v)}
            options={STATUS_OPTIONS}
          />
          <FilterSelect
            label="Severity"
            value={filters.severity ?? ""}
            onChange={(v) => setFilter("severity", v)}
            options={SEVERITY_OPTIONS}
          />
        </div>

        {isLoading && (
          <div className="findings-page__pending">
            <Spinner /> Loading findings...
          </div>
        )}

        {error && (
          <p className="findings-page__error" role="alert">
            Failed to load findings: {String(error)}
          </p>
        )}

        {!isLoading && !error && rows.length === 0 && (
          <EmptyState
            title="No findings match"
            body={
              runId
                ? "This run produced no findings, or every row is filtered out."
                : "No active findings. Run a scan from the Repos page to populate this view."
            }
          />
        )}

        {rows.length > 0 && (
          <FindingTable
            grouped={grouped}
            onSelect={(id) => selectFinding(id)}
            selected={selected}
          />
        )}
      </Card>

      {selected && <FindingDetail id={selected} onClose={() => selectFinding(null)} />}
    </div>
  );
}

function uniqueValues<T extends FindingRecord>(rows: T[], key: keyof T): string[] {
  const set = new Set<string>();
  for (const r of rows) {
    const v = r[key];
    if (typeof v === "string" && v.length > 0) set.add(v);
  }
  return Array.from(set).sort();
}

interface FilterSelectProps {
  label: string;
  value: string;
  onChange: (next: string | undefined) => void;
  options: string[];
}

function FilterSelect({ label, value, onChange, options }: FilterSelectProps) {
  return (
    <label className="findings-filter">
      <span className="findings-filter__label">{label}</span>
      <select
        className="findings-filter__select"
        value={value}
        onChange={(e) => onChange(e.target.value || undefined)}
      >
        <option value="">All</option>
        {options.map((opt) => (
          <option key={opt} value={opt}>
            {opt}
          </option>
        ))}
      </select>
    </label>
  );
}

type ChainGroup = {
  key: string;
  label: string;
  rationale: string | null;
  crossRepo: boolean;
  items: FindingWithDiff[];
};

export interface ChainSummary {
  rationale: string | null;
  crossRepo: boolean;
}

const CHAIN_RATIONALE_PREVIEW_CHARS = 140;

export function extractChainRationale(blob: string | null): string | null {
  if (!blob) return null;
  try {
    const parsed = JSON.parse(blob) as unknown;
    if (parsed && typeof parsed === "object" && "rationale" in parsed) {
      const value = (parsed as { rationale?: unknown }).rationale;
      if (typeof value === "string" && value.length > 0) {
        return value;
      }
    }
  } catch {
    // Fall through; treat blob as the rationale.
  }
  return blob.length > 0 ? blob : null;
}

export function buildChainSummaryIndex(chains: ChainRecord[]): Map<string, ChainSummary> {
  const map = new Map<string, ChainSummary>();
  for (const chain of chains) {
    map.set(chain.id, {
      rationale: extractChainRationale(chain.rationale_blob),
      crossRepo: chain.cross_repo,
    });
  }
  return map;
}

function shortChainId(id: string): string {
  const stripped = id.startsWith("chain-") ? id.slice("chain-".length) : id;
  return stripped.length > 12 ? `${stripped.slice(0, 12)}…` : stripped;
}

export function chainLabelFor(chainId: string, summary: ChainSummary | undefined): string {
  const base = `Chain ${shortChainId(chainId)}`;
  if (!summary) return base;
  const tag = summary.crossRepo ? " (cross-repo)" : "";
  if (!summary.rationale) return `${base}${tag}`;
  const rationale =
    summary.rationale.length > CHAIN_RATIONALE_PREVIEW_CHARS
      ? `${summary.rationale.slice(0, CHAIN_RATIONALE_PREVIEW_CHARS)}…`
      : summary.rationale;
  return `${base}${tag} — ${rationale}`;
}

function groupRowsByChain(
  rows: FindingWithDiff[],
  groupByChain: boolean,
  chainSummaries: Map<string, ChainSummary>,
): ChainGroup[] {
  if (!groupByChain) {
    return [{ key: "_all", label: "", rationale: null, crossRepo: false, items: rows }];
  }
  const groups = new Map<string, FindingWithDiff[]>();
  for (const row of rows) {
    const key = row.chain_id ?? "_no-chain";
    const bucket = groups.get(key) ?? [];
    bucket.push(row);
    groups.set(key, bucket);
  }
  return Array.from(groups.entries())
    .sort(([a], [b]) => (a === "_no-chain" ? 1 : b === "_no-chain" ? -1 : a.localeCompare(b)))
    .map(([key, items]) => {
      if (key === "_no-chain") {
        return {
          key,
          label: "Unchained",
          rationale: null,
          crossRepo: false,
          items,
        };
      }
      const summary = chainSummaries.get(key);
      return {
        key,
        label: chainLabelFor(key, summary),
        rationale: summary?.rationale ?? null,
        crossRepo: summary?.crossRepo ?? false,
        items,
      };
    });
}

interface FindingTableProps {
  grouped: ChainGroup[];
  selected: string | null;
  onSelect: (id: string) => void;
}

function FindingTable({ grouped, selected, onSelect }: FindingTableProps) {
  return (
    <div className="findings-table__wrap">
      {grouped.map((group) => (
        <section key={group.key} className="findings-group">
          {group.label && <h3 className="findings-group__title">{group.label}</h3>}
          <table className="findings-table" aria-label="Findings">
            <thead>
              <tr>
                <th scope="col">Diff</th>
                <th scope="col">Repo</th>
                <th scope="col">Path · line</th>
                <th scope="col">Cap</th>
                <th scope="col">Rule</th>
                <th scope="col">Severity</th>
                <th scope="col">Origin</th>
                <th scope="col">Status</th>
              </tr>
            </thead>
            <tbody>
              {group.items.map((row) => (
                <tr
                  key={row.id}
                  className={row.id === selected ? "findings-row--selected" : undefined}
                  onClick={() => onSelect(row.id)}
                >
                  <td>
                    <Badge tone={DIFF_TONE[row.diff_status]}>{DIFF_LABEL[row.diff_status]}</Badge>
                  </td>
                  <td className="findings-table__repo">{row.repo}</td>
                  <td className="findings-table__path">
                    <span title={row.path}>{row.path}</span>
                    {row.line !== null && (
                      <span className="findings-table__line"> :{row.line}</span>
                    )}
                  </td>
                  <td>
                    <Badge tone="accent">{row.cap}</Badge>
                  </td>
                  <td className="findings-table__rule" title={row.rule}>
                    {row.rule}
                  </td>
                  <td>
                    <Badge tone={SEVERITY_TONE[row.severity] ?? "neutral"}>{row.severity}</Badge>
                  </td>
                  <td>
                    <Badge tone={ORIGIN_TONE[row.finding_origin] ?? "neutral"}>
                      {row.finding_origin}
                    </Badge>
                  </td>
                  <td>
                    <Badge tone={STATUS_TONE[row.status] ?? "neutral"}>{row.status}</Badge>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </section>
      ))}
    </div>
  );
}

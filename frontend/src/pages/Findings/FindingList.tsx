import { useMemo, useState } from "react";
import { useSearchParams } from "react-router-dom";
import { Badge } from "@/components/Badge";
import { Button } from "@/components/Button";
import { Card } from "@/components/Card";
import { EmptyState } from "@/components/EmptyState";
import { Spinner } from "@/components/Spinner";
import {
  useAllRepos,
  useFindings,
  useRunFindings,
  type FindingDiffStatus,
  type FindingRecord,
  type FindingWithDiff,
  type FindingsQuery,
} from "@/api/client";
import { FindingDetail } from "./FindingDetail";
import {
  DIFF_LABEL,
  DIFF_TONE,
  ORIGIN_TONE,
  SEVERITY_TONE,
  STATUS_TONE,
} from "./diff";

type FilterKey = keyof Pick<
  FindingsQuery,
  "repo" | "cap" | "origin" | "status" | "severity"
>;

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

  const repos = useAllRepos();
  const runQuery = useRunFindings(runId);
  const listQuery = useFindings(runId ? {} : filters);

  // When run_id is set, render the diff-decorated rows. Apply the
  // client-side facet filters (cap/origin/status/severity/repo) on top
  // of the run findings so the operator can narrow within a single run
  // without leaving the page.
  const rows: FindingWithDiff[] = useMemo(() => {
    if (runId) {
      const items = runQuery.data?.items ?? [];
      return items.filter((r) => matchesClientFilters(r, filters));
    }
    return (listQuery.data ?? []).map((r) => ({
      ...r,
      diff_status: "unchanged" as FindingDiffStatus,
    }));
  }, [runId, runQuery.data, listQuery.data, filters]);

  const [groupByChain, setGroupByChain] = useState(false);
  const [selected, setSelected] = useState<string | null>(null);

  const isLoading = runId ? runQuery.isPending : listQuery.isPending;
  const error = runId ? runQuery.error : listQuery.error;

  const repoOptions = useMemo(
    () => (repos.data ?? []).map((r) => r.name),
    [repos.data],
  );
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

  const grouped = useMemo(() => groupRowsByChain(rows, groupByChain), [rows, groupByChain]);
  const priorRunId = runId ? runQuery.data?.prior_run_id ?? null : null;

  return (
    <div className="findings-page">
      <Card
        title="Findings"
        subtitle={
          runId
            ? priorRunId
              ? `Run ${runId} — diff vs ${priorRunId}`
              : `Run ${runId} — first run, every finding marked new`
            : "All active findings across configured repositories. Quarantined rows are hidden by default."
        }
        actions={
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
        }
      >
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
            <Spinner /> Loading findings…
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
            onSelect={(id) => setSelected(id)}
            selected={selected}
          />
        )}
      </Card>

      {selected && <FindingDetail id={selected} onClose={() => setSelected(null)} />}
    </div>
  );
}

function matchesClientFilters(row: FindingRecord, filters: FindingsQuery): boolean {
  if (filters.repo && row.repo !== filters.repo) return false;
  if (filters.cap && row.cap !== filters.cap) return false;
  if (filters.origin && row.finding_origin !== filters.origin) return false;
  if (filters.status && row.status !== filters.status) return false;
  if (filters.severity && row.severity !== filters.severity) return false;
  return true;
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

type ChainGroup = { key: string; label: string; items: FindingWithDiff[] };

function groupRowsByChain(rows: FindingWithDiff[], groupByChain: boolean): ChainGroup[] {
  if (!groupByChain) {
    return [{ key: "_all", label: "", items: rows }];
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
    .map(([key, items]) => ({
      key,
      label: key === "_no-chain" ? "Unchained" : `Chain ${key}`,
      items,
    }));
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

/* TanStack Query hooks covering the Phase 07 daemon surface.
 *
 * All hooks talk to `/api/v1/...` relative — Vite proxies that to
 * `http://127.0.0.1:8765` in dev, and the daemon serves the same path
 * itself in release builds.
 */

import {
  useMutation,
  useQuery,
  useQueryClient,
  type QueryClient,
} from "@tanstack/react-query";
import { useEffect, useRef, useState } from "react";
import type { AgentEvent } from "./types.gen";

const API_BASE = "/api/v1";

// ---- core fetch helpers ----------------------------------------------------

export class ApiError extends Error {
  readonly status: number;
  readonly code?: string;

  constructor(status: number, message: string, code?: string) {
    super(message);
    this.status = status;
    this.code = code;
  }
}

interface NyxBootstrap {
  authToken?: string;
}

declare global {
  interface Window {
    __NYX_BOOTSTRAP__?: NyxBootstrap;
  }
}

/** Bearer token injected by `nyx-agent-ui::spa_handler_with` into
 *  `index.html`. `undefined` when the daemon was started with
 *  `--headless` (auth disabled). */
export function getAuthToken(): string | undefined {
  if (typeof window === "undefined") return undefined;
  return window.__NYX_BOOTSTRAP__?.authToken;
}

async function request<T>(
  path: string,
  init: RequestInit = {},
): Promise<T> {
  const headers = new Headers(init.headers ?? {});
  if (init.body !== undefined && !headers.has("Content-Type")) {
    headers.set("Content-Type", "application/json");
  }
  const token = getAuthToken();
  if (token && !headers.has("Authorization")) {
    headers.set("Authorization", `Bearer ${token}`);
  }
  const res = await fetch(`${API_BASE}${path}`, { ...init, headers });
  if (!res.ok) {
    let message = `${res.status} ${res.statusText}`;
    let code: string | undefined;
    try {
      const body = (await res.json()) as { error?: { code?: string; message?: string } };
      if (body.error?.message) message = body.error.message;
      code = body.error?.code;
    } catch {
      // body was not JSON
    }
    throw new ApiError(res.status, message, code);
  }
  if (res.status === 204) return undefined as T;
  return (await res.json()) as T;
}

// ---- record shapes ---------------------------------------------------------
//
// These mirror the `*Record` structs in `nyx_agent_core::store`. The
// shared schema will move into `nyx-agent-types` once the type-hoist
// deferred item lands.

export interface RepoRecord {
  name: string;
  source_kind: string;
  source_url_or_path: string;
  branch: string | null;
  auth_ref: string | null;
  i_own_this: boolean;
  last_scan_run_id: string | null;
  created_at: number;
  updated_at: number;
}

export interface RunRecord {
  id: string;
  started_at_ms: number;
  finished_at_ms: number | null;
  status: string;
  wall_clock_ms: number | null;
  succeeded: number | null;
  inconclusive: number | null;
  failed: number | null;
}

export interface FindingRecord {
  id: string;
  run_id: string;
  repo: string;
  path: string;
  line: number | null;
  cap: string;
  rule: string;
  severity: string;
  status: string;
  finding_origin: string;
  first_seen: number;
  last_seen: number;
  superseded_by: string | null;
  triage_state: string;
  triage_assigned_to: string | null;
  verdict_blob: string | null;
  repro_path: string | null;
  attack_provenance: string | null;
  prompt_version: string | null;
  chain_id: string | null;
}

export type FindingDiffStatus = "new" | "regressed" | "closed" | "unchanged";

export interface FindingWithDiff extends FindingRecord {
  diff_status: FindingDiffStatus;
}

export interface RunFindingsResponse {
  run_id: string;
  prior_run_id: string | null;
  items: FindingWithDiff[];
}

export interface ChainRecord {
  id: string;
  run_id: string;
  cross_repo: boolean;
  member_ids: string;
  rationale_blob: string | null;
  attack_provenance: string | null;
  prompt_version: string | null;
}

export type QuarantineKind = "finding" | "candidate";

/**
 * Row shape returned by `GET /api/v1/quarantine`. Combines two
 * sources: `findings` rows with `status = 'Quarantine'` (the
 * `finding` kind) and `candidate_findings` rows with
 * `status = 'Pending'` (the `candidate` kind).
 */
export interface QuarantineItem {
  kind: QuarantineKind;
  id: string;
  run_id: string;
  repo: string;
  path: string;
  line: number | null;
  cap: string;
  rule: string | null;
  severity: string | null;
  finding_origin: string | null;
  prompt_version: string | null;
  attack_provenance: string | null;
  rationale: string | null;
  verdict_blob: string | null;
  last_seen: number | null;
}

export interface AgentTraceRow {
  id: string;
  finding_id: string | null;
  task_kind: string;
  runtime_name: string;
  model: string;
  prompt_version: string | null;
  conversation_jsonl_path: string | null;
  tokens_in: number;
  tokens_out: number;
  cost_usd_micros: number;
  cache_hits: number;
  cache_misses: number;
  duration_ms: number | null;
  started_at: number;
  finished_at: number | null;
}

export type RepoSourceKind = "git" | "local-path" | "github" | "gitlab" | "local";

export interface CreateRepoRequest {
  name: string;
  source_kind: RepoSourceKind;
  source_url_or_path: string;
  branch?: string;
  auth_ref?: string;
  i_own_this: boolean;
}

/**
 * Partial update body for `PATCH /api/v1/repos/:name`. Nullable fields
 * (`branch`, `auth_ref`) use tri-state semantics:
 *   - omitted: leave existing value untouched
 *   - `null`: clear the existing value
 *   - string: set the field to the supplied value
 */
export interface PatchRepoRequest {
  source_kind?: RepoSourceKind;
  source_url_or_path?: string;
  branch?: string | null;
  auth_ref?: string | null;
  i_own_this?: boolean;
}

export interface TestRepoRequest {
  source_kind: RepoSourceKind;
  source_url_or_path: string;
  branch?: string;
}

export interface TestRepoResponse {
  ok: boolean;
  message: string;
  on_disk_git_remote?: string;
}

export interface HealthResponse {
  status: "ok";
  version: string;
}

// ---- setup wizard ----------------------------------------------------------

export type AiRuntimeChoice = "none" | "anthropic" | "local-llm" | "claude-code";
export type SandboxBackendChoice =
  | "auto"
  | "process"
  | "birdcage"
  | "libkrun"
  | "firecracker"
  | "docker";

export interface SetupStatusResponse {
  complete: boolean;
  config_path: string;
  ai_runtime: AiRuntimeChoice;
  sandbox_backend: SandboxBackendChoice;
}

export interface SetupRequest {
  ai_runtime: AiRuntimeChoice;
  anthropic_api_key?: string;
  local_llm_url?: string;
  local_llm_token?: string;
  sandbox_backend: SandboxBackendChoice;
  i_own_this: boolean;
}

export interface DoctorCheck {
  name: string;
  passed: boolean;
  message: string;
}

export interface DoctorResponse {
  checks: DoctorCheck[];
}

// ---- query keys ------------------------------------------------------------

export interface FindingsQuery {
  repo?: string;
  run_id?: string;
  cap?: string;
  origin?: string;
  status?: string;
  severity?: string;
  triage_state?: string;
  chain_id?: string;
  include_quarantine?: boolean;
}

export const qk = {
  health: () => ["health"] as const,
  setupStatus: () => ["setup", "status"] as const,
  repos: () => ["repos"] as const,
  runs: (status?: string) => ["runs", status ?? "Running"] as const,
  run: (id: string) => ["runs", id] as const,
  findings: (params: FindingsQuery) =>
    [
      "findings",
      params.repo ?? null,
      params.run_id ?? null,
      params.cap ?? null,
      params.origin ?? null,
      params.status ?? null,
      params.severity ?? null,
      params.triage_state ?? null,
      params.chain_id ?? null,
      params.include_quarantine ?? false,
    ] as const,
  finding: (id: string) => ["findings", id] as const,
  runFindings: (run_id: string) => ["runs", run_id, "findings"] as const,
  chain: (id: string) => ["chains", id] as const,
  quarantine: () => ["quarantine"] as const,
  findingTraces: (id: string) => ["findings", id, "traces"] as const,
};

// ---- hooks -----------------------------------------------------------------

export function useHealth() {
  return useQuery({
    queryKey: qk.health(),
    queryFn: () => request<HealthResponse>("/health"),
    staleTime: 5_000,
  });
}

export function useSetupStatus() {
  return useQuery({
    queryKey: qk.setupStatus(),
    queryFn: () => request<SetupStatusResponse>("/setup/status"),
    staleTime: 0,
  });
}

export function useSubmitSetup() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (body: SetupRequest) =>
      request<{ ok: boolean; config_path: string }>("/setup", {
        method: "POST",
        body: JSON.stringify(body),
      }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: qk.setupStatus() });
    },
  });
}

export function useDoctor() {
  return useMutation({
    mutationFn: (body: { ai_runtime: AiRuntimeChoice; sandbox_backend: SandboxBackendChoice }) =>
      request<DoctorResponse>("/setup/doctor", {
        method: "POST",
        body: JSON.stringify(body),
      }),
  });
}

export function useRepos() {
  return useQuery({
    queryKey: qk.repos(),
    queryFn: () => request<RepoRecord[]>("/repos"),
  });
}

export function useCreateRepo() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (body: CreateRepoRequest) =>
      request<RepoRecord>("/repos", { method: "POST", body: JSON.stringify(body) }),
    onSuccess: () => invalidateRepoLists(qc),
  });
}

export function useDeleteRepo() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (name: string) =>
      request<{ ok: boolean; message: string }>(`/repos/${encodeURIComponent(name)}`, {
        method: "DELETE",
      }),
    onSuccess: () => invalidateRepoLists(qc),
  });
}

export function usePatchRepo() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: ({ name, patch }: { name: string; patch: PatchRepoRequest }) =>
      request<RepoRecord>(`/repos/${encodeURIComponent(name)}`, {
        method: "PATCH",
        body: JSON.stringify(patch),
      }),
    onSuccess: () => invalidateRepoLists(qc),
  });
}

export function useTestRepo() {
  return useMutation({
    mutationFn: (body: TestRepoRequest) =>
      request<TestRepoResponse>("/repos/test", {
        method: "POST",
        body: JSON.stringify(body),
      }),
  });
}

export function useTriggerScan() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (repo?: string) => {
      const query = repo ? `?repo=${encodeURIComponent(repo)}` : "";
      return request<{ run_id: string }>(`/scan${query}`, { method: "POST" });
    },
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["runs"] });
    },
  });
}

export function useRuns(status?: string) {
  return useQuery({
    queryKey: qk.runs(status),
    queryFn: () => {
      const query = status ? `?status=${encodeURIComponent(status)}` : "";
      return request<RunRecord[]>(`/runs${query}`);
    },
  });
}

export function useRun(id: string | undefined) {
  return useQuery({
    queryKey: id ? qk.run(id) : ["runs", "_disabled"],
    queryFn: () => request<RunRecord>(`/runs/${encodeURIComponent(id!)}`),
    enabled: Boolean(id),
  });
}

export function useFindings(params: FindingsQuery = {}) {
  return useQuery({
    queryKey: qk.findings(params),
    queryFn: () => {
      const search = new URLSearchParams();
      for (const [key, value] of Object.entries(params)) {
        if (value === undefined || value === null || value === "") continue;
        if (typeof value === "boolean") {
          if (value) search.set(key, "true");
        } else {
          search.set(key, String(value));
        }
      }
      const qs = search.toString();
      return request<FindingRecord[]>(`/findings${qs ? `?${qs}` : ""}`);
    },
  });
}

/**
 * Findings produced by a single run, decorated with diff status
 * ("new", "regressed", "closed", "unchanged") computed server-side
 * against the prior run.
 */
export function useRunFindings(runId: string | undefined) {
  return useQuery({
    queryKey: runId ? qk.runFindings(runId) : ["runs", "_disabled", "findings"],
    queryFn: () => request<RunFindingsResponse>(`/runs/${encodeURIComponent(runId!)}/findings`),
    enabled: Boolean(runId),
  });
}

export function useFinding(id: string | undefined) {
  return useQuery({
    queryKey: id ? qk.finding(id) : ["findings", "_disabled"],
    queryFn: () => request<FindingRecord>(`/findings/${encodeURIComponent(id!)}`),
    enabled: Boolean(id),
  });
}

export function useChain(id: string | undefined) {
  return useQuery({
    queryKey: id ? qk.chain(id) : ["chains", "_disabled"],
    queryFn: () => request<ChainRecord>(`/chains/${encodeURIComponent(id!)}`),
    enabled: Boolean(id),
  });
}

function invalidateRepoLists(qc: QueryClient) {
  qc.invalidateQueries({ queryKey: qk.repos() });
}

// ---- quarantine + traces ---------------------------------------------------

export function useQuarantine() {
  return useQuery({
    queryKey: qk.quarantine(),
    queryFn: () => request<QuarantineItem[]>("/quarantine"),
  });
}

export function usePromoteQuarantine() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (id: string) =>
      request<QuarantineItem>(`/quarantine/${encodeURIComponent(id)}/promote`, {
        method: "POST",
      }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: qk.quarantine() });
      qc.invalidateQueries({ queryKey: ["findings"] });
    },
  });
}

export function useDismissQuarantine() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (id: string) =>
      request<QuarantineItem>(`/quarantine/${encodeURIComponent(id)}/dismiss`, {
        method: "POST",
      }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: qk.quarantine() });
      qc.invalidateQueries({ queryKey: ["findings"] });
    },
  });
}

export function useFindingTraces(id: string | undefined) {
  return useQuery({
    queryKey: id ? qk.findingTraces(id) : ["findings", "_disabled", "traces"],
    queryFn: () =>
      request<AgentTraceRow[]>(`/findings/${encodeURIComponent(id!)}/traces`),
    enabled: Boolean(id),
  });
}

// ---- WebSocket event subscription -----------------------------------------

export type AgentEventLike = AgentEvent | { kind: "Lagged"; skipped: number };

export interface UseAgentEventsOptions {
  runId?: string;
  onEvent?: (event: AgentEventLike) => void;
}

/**
 * Subscribes to the agent's WebSocket event stream. Returns the most
 * recent event (if any) plus the live connection state. Pass a
 * `runId` to filter to a single run.
 */
export function useAgentEvents(options: UseAgentEventsOptions = {}) {
  const { runId, onEvent } = options;
  const [last, setLast] = useState<AgentEventLike | null>(null);
  const [status, setStatus] = useState<"connecting" | "open" | "closed">("connecting");
  const handlerRef = useRef(onEvent);
  handlerRef.current = onEvent;

  useEffect(() => {
    const proto = window.location.protocol === "https:" ? "wss" : "ws";
    const params = new URLSearchParams();
    if (runId) params.set("run_id", runId);
    const token = getAuthToken();
    if (token) params.set("token", token);
    const qs = params.toString();
    const url = `${proto}://${window.location.host}${API_BASE}/events${qs ? `?${qs}` : ""}`;
    const ws = new WebSocket(url);
    setStatus("connecting");

    ws.onopen = () => setStatus("open");
    ws.onclose = () => setStatus("closed");
    ws.onerror = () => setStatus("closed");
    ws.onmessage = (msg) => {
      try {
        const parsed = JSON.parse(msg.data as string) as AgentEventLike;
        setLast(parsed);
        handlerRef.current?.(parsed);
      } catch {
        // ignore malformed frames; daemon should never send any
      }
    };

    return () => {
      ws.close();
    };
  }, [runId]);

  return { last, status };
}

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
  repo: string;
  path: string;
  line: number;
  cap: string;
  rule: string;
  severity: string | null;
  finding_origin: string;
  status: string;
  triage_state: string | null;
  first_seen_run_id: string | null;
  last_seen_run_id: string | null;
  superseded_by: string | null;
  chain_id: string | null;
  verdict_blob: string | null;
  updated_at: number;
}

export interface ChainRecord {
  id: string;
  summary: string | null;
  created_at: number;
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

export const qk = {
  health: () => ["health"] as const,
  setupStatus: () => ["setup", "status"] as const,
  repos: () => ["repos"] as const,
  runs: (status?: string) => ["runs", status ?? "Running"] as const,
  run: (id: string) => ["runs", id] as const,
  findings: (params: { repo?: string; run_id?: string }) =>
    ["findings", params.repo ?? null, params.run_id ?? null] as const,
  finding: (id: string) => ["findings", id] as const,
  chain: (id: string) => ["chains", id] as const,
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

export function useFindings(params: { repo?: string; run_id?: string }) {
  const enabled = Boolean(params.repo || params.run_id);
  return useQuery({
    queryKey: qk.findings(params),
    queryFn: () => {
      const search = new URLSearchParams();
      if (params.repo) search.set("repo", params.repo);
      if (params.run_id) search.set("run_id", params.run_id);
      return request<FindingRecord[]>(`/findings?${search.toString()}`);
    },
    enabled,
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

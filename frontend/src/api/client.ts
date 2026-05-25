/* TanStack Query hooks covering the Phase 07 daemon surface.
 *
 * All hooks talk to `/api/v1/...` relative; Vite proxies that to
 * `http://127.0.0.1:8765` in dev, and the daemon serves the same path
 * itself in release builds.
 */

import { type QueryClient, useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useEffect, useRef, useState } from "react";
import type {
  AgentEvent,
  AgentTraceRow,
  AuthSetupJobRecord,
  AuthSetupRequest,
  AuthSetupResponse,
  AuthSetupStartResponse,
  BundleManifest,
  ChainRecord,
  CreateProjectIntegrationRequest,
  CreateProjectRequest,
  CreateRepoRequest,
  DoctorCheck,
  DoctorRequest,
  DoctorResponse,
  EnvironmentRunRecord,
  FindingDiffStatus,
  FindingRecord,
  FindingWithDiff,
  HealthResponse,
  LaunchEnvRef,
  LaunchHealthCheck,
  LaunchStep,
  LaunchWorkingDir,
  NyxSignalRecord,
  PatchProjectIntegrationRequest,
  PatchProjectRequest,
  PatchRepoRequest,
  PentestCandidateRecord,
  ProjectAuthHeaderRef,
  ProjectAuthOwnedObject,
  ProjectAuthProfile,
  ProjectIntegrationEvent,
  ProjectIntegrationKind,
  ProjectIntegrationRecord,
  ProjectLaunchProfile,
  ProjectLaunchProfileInput,
  ProjectRecord,
  ProjectRuntimeCommand,
  ProjectRuntimeEnvVar,
  ProjectRuntimeProfile,
  QuarantineItem,
  QuarantineKind,
  ReplayEvent,
  ReplayEventKind,
  RepoRecord,
  RouteModelRecord,
  RunFindingsResponse,
  RunRecord,
  SetupRequest,
  SetupStatusResponse,
  StartPentestRequest,
  TestLaunchTargetRequest,
  TestLaunchTargetResponse,
  TestProjectIntegrationResponse,
  TestRepoRequest,
  TestRepoResponse,
  VerificationAttemptRecord,
  VerifiedVulnerabilityRecord,
} from "./types.gen";

export type {
  AgentTraceRow,
  AuthSetupJobRecord,
  AuthSetupRequest,
  AuthSetupResponse,
  AuthSetupStartResponse,
  BundleManifest,
  ChainRecord,
  CreateProjectIntegrationRequest,
  CreateProjectRequest,
  CreateRepoRequest,
  DoctorCheck,
  DoctorRequest,
  DoctorResponse,
  EnvironmentRunRecord,
  FindingDiffStatus,
  FindingRecord,
  FindingWithDiff,
  HealthResponse,
  LaunchEnvRef,
  LaunchHealthCheck,
  LaunchStep,
  LaunchWorkingDir,
  NyxSignalRecord,
  PatchProjectIntegrationRequest,
  PatchProjectRequest,
  PatchRepoRequest,
  PentestCandidateRecord,
  ProjectAuthHeaderRef,
  ProjectAuthOwnedObject,
  ProjectAuthProfile,
  ProjectIntegrationEvent,
  ProjectIntegrationKind,
  ProjectIntegrationRecord,
  ProjectLaunchProfile,
  ProjectLaunchProfileInput,
  ProjectRecord,
  ProjectRuntimeCommand,
  ProjectRuntimeEnvVar,
  ProjectRuntimeProfile,
  QuarantineItem,
  QuarantineKind,
  ReplayEvent,
  ReplayEventKind,
  RepoRecord,
  RouteModelRecord,
  RunFindingsResponse,
  RunRecord,
  SetupRequest,
  SetupStatusResponse,
  StartPentestRequest,
  TestLaunchTargetRequest,
  TestLaunchTargetResponse,
  TestProjectIntegrationResponse,
  TestRepoRequest,
  TestRepoResponse,
  VerificationAttemptRecord,
  VerifiedVulnerabilityRecord,
};

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
    __NYCTOS_BOOTSTRAP__?: NyxBootstrap;
  }
}

/** Bearer token injected by `nyctos-ui::spa_handler_with` into
 *  `index.html`. `undefined` when the daemon was started with
 *  `--headless` (auth disabled). */
export function getAuthToken(): string | undefined {
  if (typeof window === "undefined") return undefined;
  return window.__NYCTOS_BOOTSTRAP__?.authToken;
}

async function request<T>(path: string, init: RequestInit = {}): Promise<T> {
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
// These mirror the `*Record` structs in `nyctos_core::store`. Shapes
// already hoisted into `nyctos-types` are re-exported above via
// `./types.gen`; the rest still live here until the DTO-drop deferred
// item retires them.

export type RepoSourceKind = "git" | "local-path" | "github" | "gitlab" | "local";

// ---- setup wizard ----------------------------------------------------------
//
// `AiRuntimeChoice` / `SandboxBackendChoice` literal unions stay as
// ergonomic FE aliases on top of the generated `SetupRequest` /
// `SetupStatusResponse` shapes (whose `ai_runtime` / `sandbox_backend`
// fields are `string` because the daemon's router validates against the
// closed enum sets at handler time). Both unions are subtypes of
// `string`, so existing call sites assign without casting.

export type AiRuntimeChoice = "claude-code" | "codex" | "anthropic" | "local-llm" | "none";
export type SandboxBackendChoice =
  | "auto"
  | "process"
  | "birdcage"
  | "libkrun"
  | "firecracker"
  | "docker";

// ---- query keys ------------------------------------------------------------

export interface FindingsQuery {
  project_id?: string;
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

export interface RunFindingsQuery {
  repo?: string;
  cap?: string;
  origin?: string;
  status?: string;
  severity?: string;
  triage_state?: string;
  chain_id?: string;
}

export interface VulnerabilityStatusPatch {
  status: string;
}

export interface BulkVulnerabilityStatusPatch {
  ids: string[];
  status: string;
}

export const qk = {
  health: () => ["health"] as const,
  setupStatus: () => ["setup", "status"] as const,
  projects: () => ["projects"] as const,
  project: (id: string) => ["projects", id] as const,
  projectRepos: (projectId: string) => ["projects", projectId, "repos"] as const,
  projectIntegrations: (projectId: string) => ["projects", projectId, "integrations"] as const,
  allRepos: () => ["projects", "_all", "repos"] as const,
  runs: (status?: string, projectId?: string) =>
    ["runs", status ?? "Running", projectId ?? null] as const,
  run: (id: string) => ["runs", id] as const,
  runEnvironment: (id: string) => ["runs", id, "environment-runs"] as const,
  runVerificationAttempts: (id: string) => ["runs", id, "verification-attempts"] as const,
  runVulnerabilities: (id: string) => ["runs", id, "vulnerabilities"] as const,
  runRouteModel: (id: string) => ["runs", id, "route-model"] as const,
  runCandidates: (id: string) => ["runs", id, "candidates"] as const,
  vulnerabilities: () => ["vulnerabilities"] as const,
  vulnerability: (id: string) => ["vulnerabilities", id] as const,
  projectVulnerabilities: (id: string) => ["projects", id, "vulnerabilities"] as const,
  runSignals: (id: string, meaningfulOnly: boolean) =>
    ["runs", id, "signals", meaningfulOnly] as const,
  findings: (params: FindingsQuery) =>
    [
      "findings",
      params.project_id ?? null,
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
  runFindings: (run_id: string, params: RunFindingsQuery = {}) =>
    [
      "runs",
      run_id,
      "findings",
      params.repo ?? null,
      params.cap ?? null,
      params.origin ?? null,
      params.status ?? null,
      params.severity ?? null,
      params.triage_state ?? null,
      params.chain_id ?? null,
    ] as const,
  chain: (id: string) => ["chains", id] as const,
  runChains: (run_id: string) => ["runs", run_id, "chains"] as const,
  quarantine: (projectId?: string) =>
    projectId ? (["quarantine", projectId] as const) : (["quarantine"] as const),
  findingTraces: (id: string) => ["findings", id, "traces"] as const,
  defaultLaunchProfile: (projectId: string) =>
    ["projects", projectId, "launch-profile", "default"] as const,
  authSetupJob: (projectId: string, jobId: string) =>
    ["projects", projectId, "auth-setup", jobId] as const,
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
    mutationFn: (body: DoctorRequest) =>
      request<DoctorResponse>("/setup/doctor", {
        method: "POST",
        body: JSON.stringify(body),
      }),
  });
}

export function testLaunchTarget(body: TestLaunchTargetRequest): Promise<TestLaunchTargetResponse> {
  return request<TestLaunchTargetResponse>("/launch-target/test", {
    method: "POST",
    body: JSON.stringify(body),
  });
}

// ---- projects --------------------------------------------------------------

export function useProjects(enabled = true) {
  return useQuery({
    queryKey: qk.projects(),
    queryFn: () => request<ProjectRecord[]>("/projects"),
    enabled,
  });
}

export function useProject(id: string | undefined) {
  return useQuery({
    queryKey: id ? qk.project(id) : ["projects", "_disabled"],
    queryFn: () => request<ProjectRecord>(`/projects/${encodeURIComponent(id!)}`),
    enabled: Boolean(id),
  });
}

export function useCreateProject() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (body: CreateProjectRequest) =>
      request<ProjectRecord>("/projects", {
        method: "POST",
        body: JSON.stringify(body),
      }),
    onSuccess: () => invalidateProjectLists(qc),
  });
}

export function usePatchProject() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: ({ id, patch }: { id: string; patch: PatchProjectRequest }) =>
      request<ProjectRecord>(`/projects/${encodeURIComponent(id)}`, {
        method: "PATCH",
        body: JSON.stringify(patch),
      }),
    onSuccess: (_data, vars) => {
      invalidateProjectLists(qc);
      qc.invalidateQueries({ queryKey: qk.project(vars.id) });
    },
  });
}

export function useDefaultLaunchProfile(projectId: string | undefined) {
  return useQuery({
    queryKey: projectId
      ? qk.defaultLaunchProfile(projectId)
      : ["projects", "_disabled", "launch-profile", "default"],
    queryFn: () =>
      request<ProjectLaunchProfile>(
        `/projects/${encodeURIComponent(projectId!)}/launch-profile/default`,
      ),
    enabled: Boolean(projectId),
  });
}

export function usePatchDefaultLaunchProfile(projectId: string) {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (body: ProjectLaunchProfileInput) =>
      request<ProjectLaunchProfile>(
        `/projects/${encodeURIComponent(projectId)}/launch-profile/default`,
        {
          method: "PATCH",
          body: JSON.stringify(body),
        },
      ),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: qk.defaultLaunchProfile(projectId) });
      qc.invalidateQueries({ queryKey: qk.project(projectId) });
      qc.invalidateQueries({ queryKey: qk.projects() });
    },
  });
}

export function startAuthAutoSetup(
  projectId: string,
  body: AuthSetupRequest = {},
): Promise<AuthSetupStartResponse> {
  return request<AuthSetupStartResponse>(`/projects/${encodeURIComponent(projectId)}/auth/auto-setup`, {
    method: "POST",
    body: JSON.stringify(body),
  });
}

export function getAuthSetupJob(projectId: string, jobId: string): Promise<AuthSetupJobRecord> {
  return request<AuthSetupJobRecord>(
    `/projects/${encodeURIComponent(projectId)}/auth/auto-setup/${encodeURIComponent(jobId)}`,
  );
}

export function useAuthAutoSetup(projectId: string) {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (body: AuthSetupRequest = {}) =>
      startAuthAutoSetup(projectId, body),
    onSuccess: (data) => {
      qc.setQueryData(qk.authSetupJob(projectId, data.job.id), data.job);
    },
  });
}

export function useDeleteProject() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (id: string) =>
      request<{ ok: boolean; message: string }>(`/projects/${encodeURIComponent(id)}`, {
        method: "DELETE",
      }),
    onSuccess: () => invalidateProjectLists(qc),
  });
}

// ---- repos (nested under projects) ----------------------------------------

export function useProjectRepos(projectId: string | undefined) {
  return useQuery({
    queryKey: projectId ? qk.projectRepos(projectId) : ["projects", "_disabled", "repos"],
    queryFn: () => request<RepoRecord[]>(`/projects/${encodeURIComponent(projectId!)}/repos`),
    enabled: Boolean(projectId),
  });
}

/**
 * Aggregates every repo across every project. Used by global views like
 * the findings filter dropdown that pre-date the project-tree refactor.
 * Fans out N+1 calls (one project list + one per project); fine while
 * project counts are small.
 */
export function useAllRepos(enabled = true) {
  return useQuery({
    queryKey: qk.allRepos(),
    queryFn: async () => {
      const projects = await request<ProjectRecord[]>("/projects");
      const lists = await Promise.all(
        projects.map((p) => request<RepoRecord[]>(`/projects/${encodeURIComponent(p.id)}/repos`)),
      );
      return lists.flat();
    },
    enabled,
  });
}

export function useCreateProjectRepo(projectId: string) {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (body: CreateRepoRequest) =>
      request<RepoRecord>(`/projects/${encodeURIComponent(projectId)}/repos`, {
        method: "POST",
        body: JSON.stringify(body),
      }),
    onSuccess: () => invalidateRepoLists(qc, projectId),
  });
}

export function useDeleteProjectRepo(projectId: string) {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (name: string) =>
      request<{ ok: boolean; message: string }>(
        `/projects/${encodeURIComponent(projectId)}/repos/${encodeURIComponent(name)}`,
        { method: "DELETE" },
      ),
    onSuccess: () => invalidateRepoLists(qc, projectId),
  });
}

export function usePatchProjectRepo(projectId: string) {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: ({ name, patch }: { name: string; patch: PatchRepoRequest }) =>
      request<RepoRecord>(
        `/projects/${encodeURIComponent(projectId)}/repos/${encodeURIComponent(name)}`,
        { method: "PATCH", body: JSON.stringify(patch) },
      ),
    onSuccess: () => invalidateRepoLists(qc, projectId),
  });
}

export function useTestProjectRepo(projectId: string) {
  return useMutation({
    mutationFn: (body: TestRepoRequest) =>
      request<TestRepoResponse>(`/projects/${encodeURIComponent(projectId)}/repos/test`, {
        method: "POST",
        body: JSON.stringify(body),
      }),
  });
}

export function useProjectIntegrations(projectId: string | undefined) {
  return useQuery({
    queryKey: projectId
      ? qk.projectIntegrations(projectId)
      : ["projects", "_disabled", "integrations"],
    queryFn: () =>
      request<ProjectIntegrationRecord[]>(
        `/projects/${encodeURIComponent(projectId!)}/integrations`,
      ),
    enabled: Boolean(projectId),
  });
}

export function useCreateProjectIntegration(projectId: string) {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (body: CreateProjectIntegrationRequest) =>
      request<ProjectIntegrationRecord>(`/projects/${encodeURIComponent(projectId)}/integrations`, {
        method: "POST",
        body: JSON.stringify(body),
      }),
    onSuccess: () => qc.invalidateQueries({ queryKey: qk.projectIntegrations(projectId) }),
  });
}

export function usePatchProjectIntegration(projectId: string) {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: ({ id, patch }: { id: string; patch: PatchProjectIntegrationRequest }) =>
      request<ProjectIntegrationRecord>(
        `/projects/${encodeURIComponent(projectId)}/integrations/${encodeURIComponent(id)}`,
        {
          method: "PATCH",
          body: JSON.stringify(patch),
        },
      ),
    onSuccess: () => qc.invalidateQueries({ queryKey: qk.projectIntegrations(projectId) }),
  });
}

export function useDeleteProjectIntegration(projectId: string) {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (id: string) =>
      request<{ ok: boolean; message: string }>(
        `/projects/${encodeURIComponent(projectId)}/integrations/${encodeURIComponent(id)}`,
        { method: "DELETE" },
      ),
    onSuccess: () => qc.invalidateQueries({ queryKey: qk.projectIntegrations(projectId) }),
  });
}

export function useTestProjectIntegration(projectId: string) {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (id: string) =>
      request<TestProjectIntegrationResponse>(
        `/projects/${encodeURIComponent(projectId)}/integrations/${encodeURIComponent(id)}/test`,
        { method: "POST" },
      ),
    onSuccess: () => qc.invalidateQueries({ queryKey: qk.projectIntegrations(projectId) }),
  });
}

export function useTriggerScan(projectId: string) {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (repo?: string) => {
      const query = repo ? `?repo=${encodeURIComponent(repo)}` : "";
      return request<{ run_id: string }>(
        `/projects/${encodeURIComponent(projectId)}/scan${query}`,
        { method: "POST" },
      );
    },
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["runs"] });
    },
  });
}

export function useStartPentest(projectId: string) {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (body: StartPentestRequest) =>
      request<{ run_id: string }>(`/projects/${encodeURIComponent(projectId)}/pentest`, {
        method: "POST",
        body: JSON.stringify(body),
      }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["runs"] });
      qc.invalidateQueries({ queryKey: qk.project(projectId) });
    },
  });
}

export function useRuns(status?: string, projectId?: string, enabled = true) {
  return useQuery({
    queryKey: qk.runs(status, projectId),
    queryFn: () => {
      const params = new URLSearchParams();
      if (status) params.set("status", status);
      if (projectId) params.set("project_id", projectId);
      const query = params.toString();
      return request<RunRecord[]>(`/runs${query ? `?${query}` : ""}`);
    },
    enabled,
  });
}

export function useRun(id: string | undefined) {
  return useQuery({
    queryKey: id ? qk.run(id) : ["runs", "_disabled"],
    queryFn: () => request<RunRecord>(`/runs/${encodeURIComponent(id!)}`),
    enabled: Boolean(id),
  });
}

export function useRunEnvironmentRuns(id: string | undefined) {
  return useQuery({
    queryKey: id ? qk.runEnvironment(id) : ["runs", "_disabled", "environment-runs"],
    queryFn: () =>
      request<EnvironmentRunRecord[]>(`/runs/${encodeURIComponent(id!)}/environment-runs`),
    enabled: Boolean(id),
  });
}

export function useRunVerificationAttempts(id: string | undefined) {
  return useQuery({
    queryKey: id ? qk.runVerificationAttempts(id) : ["runs", "_disabled", "verification-attempts"],
    queryFn: () =>
      request<VerificationAttemptRecord[]>(
        `/runs/${encodeURIComponent(id!)}/verification-attempts`,
      ),
    enabled: Boolean(id),
  });
}

export function useRunVulnerabilities(id: string | undefined) {
  return useQuery({
    queryKey: id ? qk.runVulnerabilities(id) : ["runs", "_disabled", "vulnerabilities"],
    queryFn: () =>
      request<VerifiedVulnerabilityRecord[]>(`/runs/${encodeURIComponent(id!)}/vulnerabilities`),
    enabled: Boolean(id),
  });
}

export function useRunRouteModel(id: string | undefined) {
  return useQuery({
    queryKey: id ? qk.runRouteModel(id) : ["runs", "_disabled", "route-model"],
    queryFn: () => request<RouteModelRecord>(`/runs/${encodeURIComponent(id!)}/route-model`),
    enabled: Boolean(id),
  });
}

export function useRunCandidates(id: string | undefined) {
  return useQuery({
    queryKey: id ? qk.runCandidates(id) : ["runs", "_disabled", "candidates"],
    queryFn: () => request<PentestCandidateRecord[]>(`/runs/${encodeURIComponent(id!)}/candidates`),
    enabled: Boolean(id),
  });
}

export function useVulnerabilities(enabled = true) {
  return useQuery({
    queryKey: qk.vulnerabilities(),
    queryFn: () => request<VerifiedVulnerabilityRecord[]>("/vulnerabilities"),
    enabled,
  });
}

export function useVulnerability(id: string | undefined) {
  return useQuery({
    queryKey: id ? qk.vulnerability(id) : ["vulnerabilities", "_disabled"],
    queryFn: () =>
      request<VerifiedVulnerabilityRecord>(`/vulnerabilities/${encodeURIComponent(id!)}`),
    enabled: Boolean(id),
  });
}

export function useUpdateVulnerabilityStatus() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: ({ id, status }: { id: string; status: string }) =>
      request<VerifiedVulnerabilityRecord>(`/vulnerabilities/${encodeURIComponent(id)}/status`, {
        method: "PATCH",
        body: JSON.stringify({ status } satisfies VulnerabilityStatusPatch),
      }),
    onSuccess: (data, vars) => {
      qc.setQueryData(qk.vulnerability(vars.id), data);
      qc.invalidateQueries({ queryKey: qk.vulnerabilities() });
      qc.invalidateQueries({ queryKey: ["projects"] });
      qc.invalidateQueries({ queryKey: ["runs"] });
    },
  });
}

export function useBulkUpdateVulnerabilityStatus() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (body: BulkVulnerabilityStatusPatch) =>
      request<VerifiedVulnerabilityRecord[]>("/vulnerabilities/status", {
        method: "PATCH",
        body: JSON.stringify(body),
      }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: qk.vulnerabilities() });
      qc.invalidateQueries({ queryKey: ["projects"] });
      qc.invalidateQueries({ queryKey: ["runs"] });
    },
  });
}

export function useProjectVulnerabilities(projectId: string | undefined) {
  return useQuery({
    queryKey: projectId
      ? qk.projectVulnerabilities(projectId)
      : ["projects", "_disabled", "vulnerabilities"],
    queryFn: () =>
      request<VerifiedVulnerabilityRecord[]>(
        `/projects/${encodeURIComponent(projectId!)}/vulnerabilities`,
      ),
    enabled: Boolean(projectId),
  });
}

export function useRunSignals(id: string | undefined, meaningfulOnly = false) {
  return useQuery({
    queryKey: id ? qk.runSignals(id, meaningfulOnly) : ["runs", "_disabled", "signals"],
    queryFn: () => {
      const qs = meaningfulOnly ? "?meaningful_only=true" : "";
      return request<NyxSignalRecord[]>(`/runs/${encodeURIComponent(id!)}/signals${qs}`);
    },
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
 * against the prior run. Accepts the same facet filters as the
 * top-level `/findings` endpoint (minus `run_id`, which is the path
 * parameter, and `include_quarantine`, which is always false for the
 * run-scoped view).
 */
export function useRunFindings(runId: string | undefined, filters: RunFindingsQuery = {}) {
  return useQuery({
    queryKey: runId ? qk.runFindings(runId, filters) : ["runs", "_disabled", "findings"],
    queryFn: () => {
      const search = new URLSearchParams();
      for (const [key, value] of Object.entries(filters)) {
        if (value === undefined || value === null || value === "") continue;
        search.set(key, String(value));
      }
      const qs = search.toString();
      return request<RunFindingsResponse>(
        `/runs/${encodeURIComponent(runId!)}/findings${qs ? `?${qs}` : ""}`,
      );
    },
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

/**
 * Bulk chains for a run, used by the FindingList group-by-chain view to
 * render the chain rationale next to each grouping without N+1-ing the
 * single-chain endpoint per group.
 */
export function useRunChains(runId: string | undefined) {
  return useQuery({
    queryKey: runId ? qk.runChains(runId) : ["runs", "_disabled", "chains"],
    queryFn: () =>
      request<ChainRecord[]>(`/chains?run_id=${encodeURIComponent(runId!)}&include_proposed=true`),
    enabled: Boolean(runId),
  });
}

function invalidateProjectLists(qc: QueryClient) {
  qc.invalidateQueries({ queryKey: qk.projects() });
  qc.invalidateQueries({ queryKey: qk.allRepos() });
}

function invalidateRepoLists(qc: QueryClient, projectId: string) {
  qc.invalidateQueries({ queryKey: qk.projectRepos(projectId) });
  qc.invalidateQueries({ queryKey: qk.allRepos() });
}

// ---- quarantine + traces ---------------------------------------------------

export function useQuarantine(projectId?: string) {
  return useQuery({
    queryKey: qk.quarantine(projectId),
    queryFn: () => {
      const qs = projectId ? `?project_id=${encodeURIComponent(projectId)}` : "";
      return request<QuarantineItem[]>(`/quarantine${qs}`);
    },
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
    queryFn: () => request<AgentTraceRow[]>(`/findings/${encodeURIComponent(id!)}/traces`),
    enabled: Boolean(id),
  });
}

// ---- repro bundles ---------------------------------------------------------

/**
 * Build a per-finding repro bundle on the daemon and return its
 * manifest. The bundle is written under `<state>/bundles/<id>.tar` and
 * persisted in the `repro_bundles` table.
 */
export function useBuildReproBundle() {
  return useMutation({
    mutationFn: (id: string) =>
      request<BundleManifest>(`/findings/${encodeURIComponent(id)}/repro-bundle`, {
        method: "POST",
      }),
  });
}

/**
 * URL the browser can `GET` to download the most-recent bundle. If
 * none exists, the daemon builds one inline. The token is appended as
 * a query parameter because anchor downloads cannot set
 * `Authorization` headers.
 */
export function reproBundleDownloadUrl(id: string): string {
  const token = getAuthToken();
  const qs = token ? `?token=${encodeURIComponent(token)}` : "";
  return `${API_BASE}/findings/${encodeURIComponent(id)}/repro-bundle.tar${qs}`;
}

export function runEventLogDownloadUrl(id: string): string {
  const token = getAuthToken();
  const qs = token ? `?token=${encodeURIComponent(token)}` : "";
  return `${API_BASE}/runs/${encodeURIComponent(id)}/events.jsonl${qs}`;
}

/**
 * Open an EventSource against `/findings/:id/replay` and yield parsed
 * `ReplayEvent` frames. Returns the close handle so the caller can
 * abort mid-stream. Stream ends naturally after the `end` event.
 */
export function startReplayStream(id: string, onEvent: (event: ReplayEvent) => void): () => void {
  const token = getAuthToken();
  const qs = token ? `?token=${encodeURIComponent(token)}` : "";
  const url = `${API_BASE}/findings/${encodeURIComponent(id)}/replay${qs}`;
  // The replay surface uses POST under the hood (it has side effects -
  // spawns a child + writes a replay status row) but EventSource is a
  // GET-only API. Fall back to a tiny fetch-based SSE reader so the
  // verb stays meaningful.
  const ctl = new AbortController();
  void runReplayFetch(url, ctl.signal, onEvent);
  return () => ctl.abort();
}

async function runReplayFetch(
  url: string,
  signal: AbortSignal,
  onEvent: (event: ReplayEvent) => void,
) {
  try {
    const res = await fetch(url, { method: "POST", signal });
    if (!res.ok || !res.body) {
      onEvent({ kind: "error", data: `${res.status} ${res.statusText}` });
      return;
    }
    const reader = res.body.getReader();
    const decoder = new TextDecoder();
    let buf = "";
    while (true) {
      const { value, done } = await reader.read();
      if (done) break;
      buf += decoder.decode(value, { stream: true });
      let idx = buf.indexOf("\n\n");
      while (idx !== -1) {
        const frame = buf.slice(0, idx);
        buf = buf.slice(idx + 2);
        const parsed = parseSseFrame(frame);
        if (parsed) onEvent(parsed);
        idx = buf.indexOf("\n\n");
      }
    }
  } catch (e) {
    if (signal.aborted) return;
    onEvent({ kind: "error", data: String(e) });
  }
}

function parseSseFrame(frame: string): ReplayEvent | null {
  let kind: ReplayEventKind = "stdout";
  const dataLines: string[] = [];
  for (const line of frame.split("\n")) {
    if (line.startsWith("event:")) {
      const v = line.slice(6).trim();
      if (v === "start" || v === "stdout" || v === "stderr" || v === "end" || v === "error") {
        kind = v;
      }
    } else if (line.startsWith("data:")) {
      dataLines.push(line.slice(5).replace(/^ /, ""));
    }
  }
  if (dataLines.length === 0) return null;
  return { kind, data: dataLines.join("\n") };
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

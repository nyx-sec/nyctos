import { ReactNode } from "react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { render, screen, waitFor } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { FindingList } from "./FindingList";
import type {
  FindingWithDiff,
  ProjectRecord,
  RepoRecord,
  RunFindingsResponse,
} from "@/api/client";

function jsonResponse(body: unknown, init: ResponseInit = { status: 200 }) {
  return new Response(JSON.stringify(body), {
    ...init,
    headers: { "content-type": "application/json", ...(init.headers ?? {}) },
  });
}

function wrap(children: ReactNode, route = "/findings?run_id=run-1") {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return (
    <QueryClientProvider client={qc}>
      <MemoryRouter initialEntries={[route]}>{children}</MemoryRouter>
    </QueryClientProvider>
  );
}

function makeFinding(overrides: Partial<FindingWithDiff> = {}): FindingWithDiff {
  return {
    id: "f-1",
    run_id: "run-1",
    repo: "alpha",
    path: "src/handler.py",
    line: 42,
    cap: "SQLi",
    rule: "py.sqli.format",
    severity: "High",
    status: "Open",
    finding_origin: "Static",
    first_seen: 1000,
    last_seen: 2000,
    superseded_by: null,
    triage_state: "Open",
    triage_assigned_to: null,
    verdict_blob: null,
    repro_path: null,
    attack_provenance: null,
    prompt_version: null,
    chain_id: null,
    spec_id: null,
    diff_status: "new",
    ...overrides,
  };
}

const PROJECTS: ProjectRecord[] = [
  {
    id: "p-1",
    name: "alpha-suite",
    description: null,
    target_base_url: null,
    env_config_json: null,
    created_at: 0,
    updated_at: 0,
  },
];

const REPOS: RepoRecord[] = [
  {
    name: "alpha",
    project_id: "p-1",
    source_kind: "git",
    source_url_or_path: "https://example.test/alpha.git",
    branch: null,
    auth_ref: null,
    i_own_this: true,
    last_scan_run_id: null,
    last_scan_finished_at: null,
    created_at: 0,
    updated_at: 0,
  },
];

describe("FindingList full-render", () => {
  beforeEach(() => {
    vi.spyOn(globalThis, "fetch").mockImplementation(async (input) => {
      const url = typeof input === "string" ? input : (input as Request).url;
      if (url === "/api/v1/projects") return jsonResponse(PROJECTS);
      if (url === "/api/v1/projects/p-1/repos") return jsonResponse(REPOS);
      if (url.startsWith("/api/v1/runs/run-1/findings")) {
        const body: RunFindingsResponse = {
          run_id: "run-1",
          prior_run_id: "run-0",
          items: [
            makeFinding({ id: "f-new", diff_status: "new" }),
            makeFinding({
              id: "f-regressed",
              diff_status: "regressed",
              severity: "Critical",
              status: "Verified",
            }),
            makeFinding({
              id: "f-closed",
              diff_status: "closed",
              status: "Closed",
            }),
            makeFinding({ id: "f-unchanged", diff_status: "unchanged" }),
          ],
        };
        return jsonResponse(body);
      }
      if (url.startsWith("/api/v1/chains?run_id=")) return jsonResponse([]);
      throw new Error(`unexpected url ${url}`);
    });
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  it("renders the run-scoped header showing the prior-run comparison", async () => {
    render(wrap(<FindingList />));
    expect(
      await screen.findByText(/Run run-1 compared with run-0/),
    ).toBeInTheDocument();
  });

  it("maps each diff_status to the row chip label", async () => {
    render(wrap(<FindingList />));
    await screen.findByText(/Run run-1 compared with run-0/);

    await waitFor(() => {
      expect(screen.getByText("new")).toBeInTheDocument();
    });
    expect(screen.getByText("regressed")).toBeInTheDocument();
    expect(screen.getByText("closed")).toBeInTheDocument();
    // The "unchanged" diff renders as "-" per DIFF_LABEL.
    expect(screen.getAllByText("-").length).toBeGreaterThan(0);
  });

  it("renders the empty-state copy when the run returns zero findings", async () => {
    vi.restoreAllMocks();
    vi.spyOn(globalThis, "fetch").mockImplementation(async (input) => {
      const url = typeof input === "string" ? input : (input as Request).url;
      if (url === "/api/v1/projects") return jsonResponse([]);
      if (url.startsWith("/api/v1/runs/run-1/findings"))
        return jsonResponse({
          run_id: "run-1",
          prior_run_id: null,
          items: [],
        });
      if (url.startsWith("/api/v1/chains?run_id=")) return jsonResponse([]);
      throw new Error(`unexpected url ${url}`);
    });

    render(wrap(<FindingList />));
    expect(
      await screen.findByText(/produced no findings, or every row is filtered/),
    ).toBeInTheDocument();
  });
});

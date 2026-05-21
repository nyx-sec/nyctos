import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen, waitFor } from "@testing-library/react";
import { ReactNode } from "react";
import { MemoryRouter } from "react-router-dom";
import { afterEach, describe, expect, it, vi } from "vitest";
import type { ChainRecord, RunRecord } from "@/api/client";
import { ChainList } from "./ChainList";

function jsonResponse(body: unknown, init: ResponseInit = { status: 200 }) {
  return new Response(JSON.stringify(body), {
    ...init,
    headers: { "content-type": "application/json", ...(init.headers ?? {}) },
  });
}

function wrap(children: ReactNode, route = "/chains") {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return (
    <QueryClientProvider client={qc}>
      <MemoryRouter initialEntries={[route]}>{children}</MemoryRouter>
    </QueryClientProvider>
  );
}

function makeRun(overrides: Partial<RunRecord> = {}): RunRecord {
  return {
    id: "run-1",
    started_at: 1000,
    finished_at: 2000,
    status: "Succeeded",
    triggered_by: "Manual",
    git_ref: null,
    parent_run_id: null,
    wall_clock_ms: 1000,
    total_ai_spend_usd_micros: 0,
    ...overrides,
  };
}

function makeChain(overrides: Partial<ChainRecord> = {}): ChainRecord {
  return {
    id: "chain-run-1-00-abc-deadbeef",
    run_id: "run-1",
    cross_repo: false,
    member_ids: '["f-a","f-b"]',
    rationale_blob: null,
    attack_provenance: null,
    prompt_version: null,
    ...overrides,
  };
}

describe("ChainList", () => {
  afterEach(() => {
    vi.restoreAllMocks();
  });

  it("falls back to the most recent Succeeded run when the URL has no run_id", async () => {
    const fetchSpy = vi.spyOn(globalThis, "fetch").mockImplementation(async (input) => {
      const url = typeof input === "string" ? input : (input as Request).url;
      if (url === "/api/v1/runs?status=Succeeded") {
        return jsonResponse([makeRun({ id: "run-newest" })]);
      }
      if (url === "/api/v1/chains?run_id=run-newest") {
        return jsonResponse([
          makeChain({
            id: "chain-xrep",
            run_id: "run-newest",
            cross_repo: true,
            rationale_blob: '{"rationale":"cross-repo auth bypass"}',
          }),
        ]);
      }
      throw new Error(`unexpected url ${url}`);
    });

    render(wrap(<ChainList />));

    await waitFor(() => {
      expect(screen.getByText(/Run run-newest — 1 chain, 1 cross-repo/)).toBeInTheDocument();
    });
    expect(screen.getByText("cross-repo")).toBeInTheDocument();
    expect(screen.getByText(/cross-repo auth bypass/)).toBeInTheDocument();
    expect(fetchSpy).toHaveBeenCalledWith("/api/v1/runs?status=Succeeded", expect.any(Object));
  });

  it("renders the empty-state when the run has no chains", async () => {
    vi.spyOn(globalThis, "fetch").mockImplementation(async (input) => {
      const url = typeof input === "string" ? input : (input as Request).url;
      if (url === "/api/v1/runs?status=Succeeded") {
        return jsonResponse([makeRun({ id: "run-empty" })]);
      }
      if (url === "/api/v1/chains?run_id=run-empty") {
        return jsonResponse([]);
      }
      throw new Error(`unexpected url ${url}`);
    });

    render(wrap(<ChainList />));

    expect(await screen.findByText("No chains for this run")).toBeInTheDocument();
  });

  it("renders the no-runs empty-state when no Succeeded runs exist", async () => {
    vi.spyOn(globalThis, "fetch").mockImplementation(async (input) => {
      const url = typeof input === "string" ? input : (input as Request).url;
      if (url === "/api/v1/runs?status=Succeeded") return jsonResponse([]);
      throw new Error(`unexpected url ${url}`);
    });

    render(wrap(<ChainList />));

    expect(await screen.findByText("No completed runs yet")).toBeInTheDocument();
  });

  it("uses the URL run_id when set and respects it over the most-recent fallback", async () => {
    vi.spyOn(globalThis, "fetch").mockImplementation(async (input) => {
      const url = typeof input === "string" ? input : (input as Request).url;
      if (url === "/api/v1/runs?status=Succeeded") {
        return jsonResponse([makeRun({ id: "run-newer" }), makeRun({ id: "run-older" })]);
      }
      if (url === "/api/v1/chains?run_id=run-older") {
        return jsonResponse([makeChain({ id: "chain-pinned", run_id: "run-older" })]);
      }
      throw new Error(`unexpected url ${url}`);
    });

    render(wrap(<ChainList />, "/chains?run_id=run-older"));

    await waitFor(() => {
      expect(screen.getByText(/Run run-older — 1 chain/)).toBeInTheDocument();
    });
  });
});

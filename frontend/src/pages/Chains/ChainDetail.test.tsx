import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen, waitFor } from "@testing-library/react";
import { ReactNode } from "react";
import { MemoryRouter, Route, Routes } from "react-router-dom";
import { afterEach, describe, expect, it, vi } from "vitest";
import type { ChainRecord, FindingRecord } from "@/api/client";
import { ChainDetail } from "./ChainDetail";

function jsonResponse(body: unknown, init: ResponseInit = { status: 200 }) {
  return new Response(JSON.stringify(body), {
    ...init,
    headers: { "content-type": "application/json", ...(init.headers ?? {}) },
  });
}

function wrap(children: ReactNode, path: string) {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return (
    <QueryClientProvider client={qc}>
      <MemoryRouter initialEntries={[path]}>
        <Routes>
          <Route path="/chains/:chainId" element={children} />
        </Routes>
      </MemoryRouter>
    </QueryClientProvider>
  );
}

function makeChain(overrides: Partial<ChainRecord> = {}): ChainRecord {
  return {
    id: "chain-xrep",
    run_id: "run-1",
    cross_repo: true,
    member_ids: '["f-controller","f-sink"]',
    rationale_blob: '{"rationale":"controller in repo-a reaches sink in repo-b"}',
    attack_provenance: "ChainReasoning",
    prompt_version: "chain-reasoning/v1",
    ...overrides,
  };
}

function makeFinding(overrides: Partial<FindingRecord> = {}): FindingRecord {
  return {
    id: "f-controller",
    run_id: "run-1",
    repo: "alpha",
    path: "src/controller.py",
    line: 12,
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
    chain_id: "chain-xrep",
    spec_id: null,
    ...overrides,
  };
}

describe("ChainDetail", () => {
  afterEach(() => {
    vi.restoreAllMocks();
  });

  it("renders the rationale, cross-repo badge, and one row per member", async () => {
    vi.spyOn(globalThis, "fetch").mockImplementation(async (input) => {
      const url = typeof input === "string" ? input : (input as Request).url;
      if (url === "/api/v1/chains/chain-xrep") return jsonResponse(makeChain());
      if (url === "/api/v1/findings/f-controller") {
        return jsonResponse(makeFinding({ id: "f-controller" }));
      }
      if (url === "/api/v1/findings/f-sink") {
        return jsonResponse(
          makeFinding({
            id: "f-sink",
            repo: "beta",
            path: "src/sink.py",
            line: 88,
            cap: "OS_COMMAND",
            rule: "py.oscmd.shell",
          }),
        );
      }
      throw new Error(`unexpected url ${url}`);
    });

    render(wrap(<ChainDetail />, "/chains/chain-xrep"));

    expect(
      await screen.findByText(/controller in repo-a reaches sink in repo-b/),
    ).toBeInTheDocument();
    expect(screen.getByText("cross-repo")).toBeInTheDocument();
    expect(screen.getByText("Members (2)")).toBeInTheDocument();

    await waitFor(() => {
      expect(screen.getByText("alpha")).toBeInTheDocument();
    });
    expect(screen.getByText("src/controller.py:12")).toBeInTheDocument();
    expect(screen.getByText("src/sink.py:88")).toBeInTheDocument();
    expect(screen.getByText("py.oscmd.shell")).toBeInTheDocument();
  });

  it("renders an empty rationale when the blob is missing", async () => {
    vi.spyOn(globalThis, "fetch").mockImplementation(async (input) => {
      const url = typeof input === "string" ? input : (input as Request).url;
      if (url === "/api/v1/chains/chain-bare") {
        return jsonResponse(
          makeChain({
            id: "chain-bare",
            rationale_blob: null,
            member_ids: "[]",
            cross_repo: false,
          }),
        );
      }
      throw new Error(`unexpected url ${url}`);
    });

    render(wrap(<ChainDetail />, "/chains/chain-bare"));

    expect(await screen.findByText(/No rationale text recorded/)).toBeInTheDocument();
    expect(screen.getByText("Members (0)")).toBeInTheDocument();
    expect(screen.getByText("single-repo")).toBeInTheDocument();
    expect(screen.getByText("No member findings")).toBeInTheDocument();
  });

  it("links each member row to the FindingList focus URL", async () => {
    vi.spyOn(globalThis, "fetch").mockImplementation(async (input) => {
      const url = typeof input === "string" ? input : (input as Request).url;
      if (url === "/api/v1/chains/chain-xrep") return jsonResponse(makeChain());
      if (url === "/api/v1/findings/f-controller") {
        return jsonResponse(makeFinding({ id: "f-controller" }));
      }
      if (url === "/api/v1/findings/f-sink") {
        return jsonResponse(
          makeFinding({ id: "f-sink", repo: "beta", path: "src/sink.py", line: 88 }),
        );
      }
      throw new Error(`unexpected url ${url}`);
    });

    render(wrap(<ChainDetail />, "/chains/chain-xrep"));

    await waitFor(() => {
      expect(screen.getByText("src/controller.py:12")).toBeInTheDocument();
    });
    const links = screen.getAllByRole("link").map((node) => node.getAttribute("href"));
    expect(links).toEqual(
      expect.arrayContaining([
        "/findings?run_id=run-1&focus=f-controller",
        "/findings?run_id=run-1&focus=f-sink",
      ]),
    );
  });

  it("renders an error alert when the chain fetch fails", async () => {
    vi.spyOn(globalThis, "fetch").mockImplementation(async () =>
      jsonResponse({ error: { message: "boom" } }, { status: 500 }),
    );

    render(wrap(<ChainDetail />, "/chains/chain-missing"));

    expect(await screen.findByRole("alert", { name: undefined })).toBeInTheDocument();
    expect(screen.getByText(/Failed to load chain/)).toBeInTheDocument();
  });
});

import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { ReactNode } from "react";
import { afterEach, describe, expect, it, vi } from "vitest";
import type { AgentTraceRow, QuarantineItem } from "@/api/client";
import { ToastProvider } from "@/components/Toast";
import { QuarantineList } from "./QuarantineList";

function jsonResponse(body: unknown, init: ResponseInit = { status: 200 }) {
  return new Response(JSON.stringify(body), {
    ...init,
    headers: { "content-type": "application/json", ...(init.headers ?? {}) },
  });
}

function wrap(children: ReactNode) {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return (
    <QueryClientProvider client={qc}>
      <ToastProvider>{children}</ToastProvider>
    </QueryClientProvider>
  );
}

function makeItem(overrides: Partial<QuarantineItem> = {}): QuarantineItem {
  return {
    kind: "candidate",
    id: "cand-abc",
    run_id: "run-1",
    repo: "alpha",
    path: "src/sink.py",
    line: 88,
    cap: "SQLi",
    rule: null,
    severity: null,
    finding_origin: "AI",
    prompt_version: "v3",
    attack_provenance: "AiExploration",
    rationale: "Looks reachable from controller.",
    verdict_blob: null,
    last_seen: null,
    ...overrides,
  };
}

describe("QuarantineList", () => {
  afterEach(() => {
    vi.restoreAllMocks();
  });

  it("renders the empty-state when quarantine returns zero rows", async () => {
    vi.spyOn(globalThis, "fetch").mockImplementation(async (input) => {
      const url = typeof input === "string" ? input : (input as Request).url;
      if (url === "/api/v1/quarantine") return jsonResponse([]);
      throw new Error(`unexpected url ${url}`);
    });

    render(wrap(<QuarantineList />));

    expect(await screen.findByText("Nothing in quarantine")).toBeInTheDocument();
    expect(screen.getByText("0 awaiting review")).toBeInTheDocument();
  });

  it("renders one row per kind with the matching badge label and counts both", async () => {
    const items = [
      makeItem({ kind: "candidate", id: "cand-1", cap: "SQLi" }),
      makeItem({ kind: "finding", id: "f-2", cap: "CMDi", repo: "beta" }),
    ];
    vi.spyOn(globalThis, "fetch").mockImplementation(async (input) => {
      const url = typeof input === "string" ? input : (input as Request).url;
      if (url === "/api/v1/quarantine") return jsonResponse(items);
      throw new Error(`unexpected url ${url}`);
    });

    render(wrap(<QuarantineList />));

    expect(await screen.findByText("2 awaiting review")).toBeInTheDocument();
    expect(screen.getByText("Candidate")).toBeInTheDocument();
    expect(screen.getByText("Finding")).toBeInTheDocument();
    expect(screen.getByText("SQLi")).toBeInTheDocument();
    expect(screen.getByText("CMDi")).toBeInTheDocument();
    // Rationale is lifted from the row's rationale field (no JSON parse needed).
    expect(screen.getAllByText("Looks reachable from controller.").length).toBeGreaterThanOrEqual(
      2,
    );
  });

  it("falls back to the verdict_blob rationale when row.rationale is null", async () => {
    const items = [
      makeItem({
        kind: "finding",
        id: "f-blob",
        rationale: null,
        verdict_blob: JSON.stringify({ rationale: "from blob" }),
      }),
    ];
    vi.spyOn(globalThis, "fetch").mockImplementation(async (input) => {
      const url = typeof input === "string" ? input : (input as Request).url;
      if (url === "/api/v1/quarantine") return jsonResponse(items);
      throw new Error(`unexpected url ${url}`);
    });

    render(wrap(<QuarantineList />));

    expect(await screen.findByText("from blob")).toBeInTheDocument();
  });

  it("POSTs to /promote and surfaces the success toast", async () => {
    const items = [makeItem({ kind: "candidate", id: "cand-promote" })];
    const promoteCalls: string[] = [];
    vi.spyOn(globalThis, "fetch").mockImplementation(async (input, init) => {
      const url = typeof input === "string" ? input : (input as Request).url;
      const method = (init?.method ?? "GET").toUpperCase();
      if (url === "/api/v1/quarantine" && method === "GET") {
        return jsonResponse(items);
      }
      if (url === "/api/v1/quarantine/cand-promote/promote" && method === "POST") {
        promoteCalls.push(url);
        return jsonResponse(items[0]);
      }
      throw new Error(`unexpected ${method} ${url}`);
    });

    render(wrap(<QuarantineList />));
    fireEvent.click(await screen.findByRole("button", { name: "Promote" }));

    await waitFor(() => {
      expect(promoteCalls).toEqual(["/api/v1/quarantine/cand-promote/promote"]);
    });
    expect(await screen.findByText(/Promoted cand-promote into findings\./)).toBeInTheDocument();
  });

  it("confirms before dismiss; cancel aborts the network call", async () => {
    const items = [makeItem({ kind: "candidate", id: "cand-cancel" })];
    const calls: string[] = [];
    vi.spyOn(globalThis, "fetch").mockImplementation(async (input, init) => {
      const url = typeof input === "string" ? input : (input as Request).url;
      const method = (init?.method ?? "GET").toUpperCase();
      calls.push(`${method} ${url}`);
      if (url === "/api/v1/quarantine") return jsonResponse(items);
      throw new Error(`unexpected ${method} ${url}`);
    });
    const confirmSpy = vi.spyOn(window, "confirm").mockReturnValue(false);

    render(wrap(<QuarantineList />));
    fireEvent.click(await screen.findByRole("button", { name: "Dismiss" }));

    expect(confirmSpy).toHaveBeenCalledTimes(1);
    expect(calls.filter((c) => c.includes("dismiss"))).toEqual([]);
  });

  it("POSTs to /dismiss when the confirm dialog is accepted", async () => {
    const items = [makeItem({ kind: "finding", id: "f-dismiss" })];
    const dismissCalls: string[] = [];
    vi.spyOn(globalThis, "fetch").mockImplementation(async (input, init) => {
      const url = typeof input === "string" ? input : (input as Request).url;
      const method = (init?.method ?? "GET").toUpperCase();
      if (url === "/api/v1/quarantine" && method === "GET") {
        return jsonResponse(items);
      }
      if (url === "/api/v1/quarantine/f-dismiss/dismiss" && method === "POST") {
        dismissCalls.push(url);
        return jsonResponse(items[0]);
      }
      throw new Error(`unexpected ${method} ${url}`);
    });
    vi.spyOn(window, "confirm").mockReturnValue(true);

    render(wrap(<QuarantineList />));
    fireEvent.click(await screen.findByRole("button", { name: "Dismiss" }));

    await waitFor(() => {
      expect(dismissCalls).toEqual(["/api/v1/quarantine/f-dismiss/dismiss"]);
    });
    expect(await screen.findByText(/Dismissed f-dismiss\./)).toBeInTheDocument();
  });

  it("opens the detail card when a path link is clicked and renders the trace surface", async () => {
    const items = [makeItem({ kind: "candidate", id: "cand-detail" })];
    const traces: AgentTraceRow[] = [];
    vi.spyOn(globalThis, "fetch").mockImplementation(async (input) => {
      const url = typeof input === "string" ? input : (input as Request).url;
      if (url === "/api/v1/quarantine") return jsonResponse(items);
      if (url === "/api/v1/findings/cand-detail/traces") {
        return jsonResponse(traces);
      }
      throw new Error(`unexpected url ${url}`);
    });

    render(wrap(<QuarantineList />));
    // Open the detail panel by clicking the path link.
    fireEvent.click(await screen.findByText("src/sink.py:88"));

    // The card header lifts the kind and cap.
    expect(await screen.findByText("Candidate · SQLi")).toBeInTheDocument();
    // The AiTraceViewer renders its empty state when traces are zero.
    expect(
      await screen.findByText("No AI calls recorded for this finding yet."),
    ).toBeInTheDocument();
  });
});

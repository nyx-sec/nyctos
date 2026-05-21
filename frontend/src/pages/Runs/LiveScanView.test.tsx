import { ReactNode } from "react";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { act, render, screen, waitFor } from "@testing-library/react";
import { MemoryRouter, Route, Routes } from "react-router-dom";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { LiveScanView } from "./LiveScanView";

// Minimal WebSocket double. Mirrors the FakeWebSocket helper in
// `api/client.test.tsx` but kept local so the hook-level test there
// stays the single owner of the URL-shape contract while this page
// test owns the WS-frame -> per-repo-phase folding contract.
class FakeWebSocket {
  static instances: FakeWebSocket[] = [];
  url: string;
  readyState = 0;
  onopen: ((ev: unknown) => void) | null = null;
  onmessage: ((ev: { data: string }) => void) | null = null;
  onclose: ((ev: unknown) => void) | null = null;
  onerror: ((ev: unknown) => void) | null = null;

  constructor(url: string) {
    this.url = url;
    FakeWebSocket.instances.push(this);
  }

  close() {
    this.readyState = 3;
    this.onclose?.({});
  }

  emit(data: unknown) {
    this.onmessage?.({ data: JSON.stringify(data) });
  }
}

function wrap(children: ReactNode, initial = "/runs/run-1") {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return (
    <QueryClientProvider client={qc}>
      <MemoryRouter initialEntries={[initial]}>
        <Routes>
          <Route path="/runs/:runId" element={children} />
          <Route path="/findings" element={<div>findings-route</div>} />
        </Routes>
      </MemoryRouter>
    </QueryClientProvider>
  );
}

describe("LiveScanView", () => {
  let originalWS: typeof WebSocket;
  beforeEach(() => {
    originalWS = window.WebSocket;
    (window as unknown as { WebSocket: unknown }).WebSocket =
      FakeWebSocket as unknown as typeof WebSocket;
    FakeWebSocket.instances = [];
  });
  afterEach(() => {
    (window as unknown as { WebSocket: unknown }).WebSocket = originalWS;
  });

  it("shows the waiting-for-RunStarted placeholder before any frame arrives", async () => {
    render(wrap(<LiveScanView />));
    expect(await screen.findByText(/Run run-1/)).toBeInTheDocument();
    expect(screen.getByText(/Waiting for RunStarted/)).toBeInTheDocument();
    expect(FakeWebSocket.instances).toHaveLength(1);
  });

  it("folds a RunStarted -> RepoStarted -> RepoStaticDone -> RepoFinished frame sequence into per-repo phases", async () => {
    render(wrap(<LiveScanView />));
    await screen.findByText(/Run run-1/);
    const ws = FakeWebSocket.instances[0];

    act(() =>
      ws.emit({
        kind: "Run",
        data: {
          kind: "RunStarted",
          run_id: "run-1",
          project_id: "p-1",
          repos: ["alpha", "beta"],
          started_at_ms: 1000,
        },
      }),
    );

    expect(await screen.findByText("alpha")).toBeInTheDocument();
    expect(screen.getByText("beta")).toBeInTheDocument();
    const queuedBadges = screen.getAllByText("Queued");
    expect(queuedBadges).toHaveLength(2);

    act(() =>
      ws.emit({
        kind: "Run",
        data: {
          kind: "RepoStarted",
          run_id: "run-1",
          project_id: "p-1",
          repo: "alpha",
          started_at_ms: 1010,
        },
      }),
    );
    expect(await screen.findByText("Static")).toBeInTheDocument();

    act(() =>
      ws.emit({
        kind: "Run",
        data: {
          kind: "RepoStaticDone",
          run_id: "run-1",
          project_id: "p-1",
          repo: "alpha",
          n_diags: 3,
          elapsed_ms: 220,
        },
      }),
    );
    expect(await screen.findByText("Static done")).toBeInTheDocument();
    expect(screen.getByText("3 diag(s)")).toBeInTheDocument();

    act(() =>
      ws.emit({
        kind: "Run",
        data: {
          kind: "RepoFinished",
          run_id: "run-1",
          project_id: "p-1",
          repo: "alpha",
          outcome: "Success",
          elapsed_ms: 420,
        },
      }),
    );
    expect(await screen.findByText("Finished")).toBeInTheDocument();
    expect(screen.getByText("Success")).toBeInTheDocument();
  });

  it("renders the RunFinished tally and unlocks the Open-findings link", async () => {
    render(wrap(<LiveScanView />));
    await screen.findByText(/Run run-1/);
    const ws = FakeWebSocket.instances[0];

    act(() =>
      ws.emit({
        kind: "Run",
        data: {
          kind: "RunStarted",
          run_id: "run-1",
          project_id: "p-1",
          repos: ["alpha"],
          started_at_ms: 0,
        },
      }),
    );

    act(() =>
      ws.emit({
        kind: "Run",
        data: {
          kind: "RunFinished",
          run_id: "run-1",
          project_id: "p-1",
          finished_at_ms: 5000,
          wall_clock_ms: 4321,
          succeeded: 2,
          inconclusive: 1,
          failed: 0,
        },
      }),
    );

    await waitFor(() =>
      expect(
        screen.getByText(/Finished in 4321ms · 2 ok \/ 1 inconclusive \/ 0 failed/),
      ).toBeInTheDocument(),
    );
    expect(screen.getByRole("link", { name: /Open findings/ })).toBeInTheDocument();
  });

  it("surfaces a RepoFailed frame as the failed phase with the daemon message", async () => {
    render(wrap(<LiveScanView />));
    await screen.findByText(/Run run-1/);
    const ws = FakeWebSocket.instances[0];

    act(() =>
      ws.emit({
        kind: "Run",
        data: {
          kind: "RunStarted",
          run_id: "run-1",
          project_id: "p-1",
          repos: ["gamma"],
          started_at_ms: 0,
        },
      }),
    );
    act(() =>
      ws.emit({
        kind: "Run",
        data: {
          kind: "RepoFailed",
          run_id: "run-1",
          project_id: "p-1",
          repo: "gamma",
          message: "static-pass timeout after 600000ms",
          elapsed_ms: 600000,
        },
      }),
    );

    expect(await screen.findByText("Failed")).toBeInTheDocument();
    expect(
      screen.getByText("static-pass timeout after 600000ms"),
    ).toBeInTheDocument();
    // Failed runs emit an error-level log line in the stream.
    expect(
      screen.getByText(/\[gamma\] failed: static-pass timeout after 600000ms/),
    ).toBeInTheDocument();
  });

  it("appends a Lagged frame as a warn log line", async () => {
    render(wrap(<LiveScanView />));
    await screen.findByText(/Run run-1/);
    const ws = FakeWebSocket.instances[0];

    act(() => ws.emit({ kind: "Lagged", skipped: 7 }));
    expect(
      await screen.findByText(/\[lagged\] skipped 7 frame\(s\)/),
    ).toBeInTheDocument();
  });
});

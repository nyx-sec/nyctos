import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { act, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { RepoList } from "./RepoList";
import { applyEvent } from "./repoStatus";
import type { AgentEventLike, RepoRecord } from "@/api/client";

class FakeWebSocket {
  static instances: FakeWebSocket[] = [];
  readyState = 0;
  onopen: ((ev?: Event) => void) | null = null;
  onclose: ((ev?: CloseEvent) => void) | null = null;
  onerror: ((ev?: Event) => void) | null = null;
  onmessage: ((ev: MessageEvent) => void) | null = null;
  url: string;

  constructor(url: string | URL) {
    this.url = url.toString();
    FakeWebSocket.instances.push(this);
    queueMicrotask(() => {
      this.readyState = 1;
      this.onopen?.();
    });
  }

  send() {}
  close() {
    this.readyState = 3;
    this.onclose?.();
  }
}

function withClient(ui: React.ReactElement) {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return (
    <QueryClientProvider client={qc}>
      <MemoryRouter>{ui}</MemoryRouter>
    </QueryClientProvider>
  );
}

const repos: RepoRecord[] = [
  {
    name: "billing",
    source_kind: "local-path",
    source_url_or_path: "/tmp/billing",
    branch: null,
    auth_ref: null,
    i_own_this: true,
    last_scan_run_id: null,
    created_at: 1_000,
    updated_at: 1_000,
  },
];

beforeEach(() => {
  vi.stubGlobal("WebSocket", FakeWebSocket as unknown as typeof WebSocket);
  vi.stubGlobal(
    "fetch",
    vi.fn(async (input: RequestInfo | URL) => {
      const url = typeof input === "string" ? input : input.toString();
      if (url.endsWith("/api/v1/repos")) {
        return new Response(JSON.stringify(repos), {
          status: 200,
          headers: { "Content-Type": "application/json" },
        });
      }
      return new Response("{}", { status: 200 });
    }),
  );
});

afterEach(() => {
  vi.unstubAllGlobals();
  FakeWebSocket.instances.length = 0;
});

describe("RepoList", () => {
  it("renders configured repositories with their type badge and Idle status", async () => {
    render(withClient(<RepoList />));
    await screen.findByText("billing");
    expect(screen.getByText("local-path")).toBeInTheDocument();
    expect(screen.getByText("Idle")).toBeInTheDocument();
  });

  it("opens the add-repo modal when 'Add repo' is clicked", async () => {
    render(withClient(<RepoList />));
    await screen.findByText("billing");
    fireEvent.click(screen.getAllByRole("button", { name: /Add repo/ })[0]);
    expect(await screen.findByRole("dialog")).toBeInTheDocument();
    expect(screen.getByText(/Git URL/)).toBeInTheDocument();
    expect(screen.getByText(/Local path/)).toBeInTheDocument();
  });

  it("Scan-now button is disabled when the row is already Running", async () => {
    render(withClient(<RepoList />));
    await screen.findByText("billing");
    // Simulate a RepoStarted frame arriving through the WebSocket.
    const ws = FakeWebSocket.instances[0];
    await waitFor(() => expect(ws.readyState).toBe(1));
    const frame: AgentEventLike = {
      kind: "Run",
      data: {
        kind: "RepoStarted",
        run_id: "run-1",
        repo: "billing",
        started_at_ms: 1,
      },
    } as AgentEventLike;
    act(() => {
      ws.onmessage?.({ data: JSON.stringify(frame) } as MessageEvent);
    });
    await screen.findByText("Running");
    const scanBtn = screen.getByRole("button", { name: /Scan now/ });
    expect(scanBtn).toBeDisabled();
  });
});

describe("applyEvent", () => {
  it("maps RunStarted → Running for every named repo", () => {
    const next = applyEvent(
      {},
      {
        kind: "Run",
        data: {
          kind: "RunStarted",
          run_id: "r1",
          repos: ["a", "b"],
          started_at_ms: 0,
        },
      } as AgentEventLike,
    );
    expect(next.a.status).toBe("Running");
    expect(next.b.status).toBe("Running");
  });

  it("rolls Running rows back to Idle on RunFinished", () => {
    const seeded = applyEvent(
      {},
      {
        kind: "Run",
        data: {
          kind: "RunStarted",
          run_id: "r1",
          repos: ["a"],
          started_at_ms: 0,
        },
      } as AgentEventLike,
    );
    const next = applyEvent(seeded, {
      kind: "Run",
      data: {
        kind: "RunFinished",
        run_id: "r1",
        finished_at_ms: 1,
        wall_clock_ms: 1,
        succeeded: 1,
        inconclusive: 0,
        failed: 0,
      },
    } as AgentEventLike);
    expect(next.a.status).toBe("Idle");
  });

  it("keeps Done state through RunFinished", () => {
    const after = applyEvent(
      {},
      {
        kind: "Run",
        data: {
          kind: "RepoFinished",
          run_id: "r1",
          repo: "a",
          outcome: "Success",
          elapsed_ms: 5,
        },
      } as AgentEventLike,
    );
    const next = applyEvent(after, {
      kind: "Run",
      data: {
        kind: "RunFinished",
        run_id: "r1",
        finished_at_ms: 6,
        wall_clock_ms: 6,
        succeeded: 1,
        inconclusive: 0,
        failed: 0,
      },
    } as AgentEventLike);
    expect(next.a.status).toBe("Done");
  });
});

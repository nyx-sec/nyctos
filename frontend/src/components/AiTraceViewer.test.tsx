import { ReactNode } from "react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { fireEvent, render, screen } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { AiTraceViewer } from "./AiTraceViewer";
import type { AgentTraceRow } from "@/api/client";

function jsonResponse(body: unknown, init: ResponseInit = { status: 200 }) {
  return new Response(JSON.stringify(body), {
    ...init,
    headers: { "content-type": "application/json", ...(init.headers ?? {}) },
  });
}

function wrap(children: ReactNode) {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return <QueryClientProvider client={qc}>{children}</QueryClientProvider>;
}

function makeRow(overrides: Partial<AgentTraceRow> = {}): AgentTraceRow {
  return {
    id: "trace-1",
    finding_id: "f-1",
    task_kind: "PayloadSynthesis",
    runtime_name: "anthropic",
    model: "claude-sonnet-4-6",
    prompt_version: "payload_synthesis@v3",
    conversation_jsonl_path: null,
    tokens_in: 1200,
    tokens_out: 450,
    cost_usd_micros: 12_345,
    cache_hits: 1,
    cache_misses: 0,
    duration_ms: 980,
    started_at: 1_700_000_000_000,
    finished_at: 1_700_000_001_000,
    ...overrides,
  };
}

describe("AiTraceViewer", () => {
  afterEach(() => {
    vi.restoreAllMocks();
  });

  it("renders the empty-state when traces are zero", async () => {
    vi.spyOn(globalThis, "fetch").mockResolvedValue(jsonResponse([]));

    render(wrap(<AiTraceViewer findingId="f-1" />));

    expect(
      await screen.findByText("No AI calls recorded for this finding yet."),
    ).toBeInTheDocument();
  });

  it("renders the singular turn header and total cost when one row is returned", async () => {
    vi.spyOn(globalThis, "fetch").mockResolvedValue(
      jsonResponse([makeRow({ cost_usd_micros: 1_000_000 })]),
    );

    render(wrap(<AiTraceViewer findingId="f-1" />));

    expect(await screen.findByText("AI conversation")).toBeInTheDocument();
    // Singular "1 turn" copy + cost rendered to 6 decimals.
    expect(screen.getByText(/1 turn ·/)).toBeInTheDocument();
    expect(screen.getByText("$1.000000")).toBeInTheDocument();
  });

  it("renders the plural header when multiple rows are returned", async () => {
    vi.spyOn(globalThis, "fetch").mockResolvedValue(
      jsonResponse([
        makeRow({ id: "t1", cost_usd_micros: 500_000 }),
        makeRow({ id: "t2", cost_usd_micros: 500_000, task_kind: "Exploration" }),
      ]),
    );

    render(wrap(<AiTraceViewer findingId="f-1" />));

    expect(await screen.findByText(/2 turns ·/)).toBeInTheDocument();
    // Both task-kind badges land in the list.
    expect(screen.getByText("PayloadSynthesis")).toBeInTheDocument();
    expect(screen.getByText("Exploration")).toBeInTheDocument();
  });

  it("expands a turn card on click and shows the per-row meta fields", async () => {
    vi.spyOn(globalThis, "fetch").mockResolvedValue(
      jsonResponse([
        makeRow({
          conversation_jsonl_path: "/var/state/traces/run-1/t1.jsonl",
        }),
      ]),
    );

    render(wrap(<AiTraceViewer findingId="f-1" />));

    const toggle = await screen.findByRole("button", { expanded: false });
    fireEvent.click(toggle);

    // After expansion the dl meta rows are reachable.
    expect(screen.getByText("Trace id")).toBeInTheDocument();
    expect(screen.getByText("trace-1")).toBeInTheDocument();
    expect(screen.getByText("Tokens in")).toBeInTheDocument();
    expect(screen.getByText("1200")).toBeInTheDocument();
    expect(screen.getByText("Cache hits / misses")).toBeInTheDocument();
    expect(screen.getByText("1 / 0")).toBeInTheDocument();
    // JSONL path row stamps the captured location.
    expect(
      screen.getByText("/var/state/traces/run-1/t1.jsonl"),
    ).toBeInTheDocument();
  });

  it("surfaces an unspecified model with an italic placeholder", async () => {
    vi.spyOn(globalThis, "fetch").mockResolvedValue(
      jsonResponse([makeRow({ model: "" })]),
    );

    render(wrap(<AiTraceViewer findingId="f-1" />));

    fireEvent.click(await screen.findByRole("button", { expanded: false }));
    expect(screen.getByText("unspecified")).toBeInTheDocument();
  });

  it("renders an error alert when the query rejects", async () => {
    vi.spyOn(globalThis, "fetch").mockResolvedValue(
      new Response(JSON.stringify({ error: { message: "boom" } }), {
        status: 500,
        headers: { "content-type": "application/json" },
      }),
    );

    render(wrap(<AiTraceViewer findingId="f-1" />));

    expect(await screen.findByRole("alert")).toHaveTextContent(
      /Failed to load trace/,
    );
  });
});

import { ReactNode } from "react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { fireEvent, render, screen } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { FindingDetail } from "./FindingDetail";
import type { FindingRecord } from "@/api/client";

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
      <MemoryRouter>{children}</MemoryRouter>
    </QueryClientProvider>
  );
}

function makeFinding(overrides: Partial<FindingRecord> = {}): FindingRecord {
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
    ...overrides,
  };
}

describe("FindingDetail", () => {
  afterEach(() => {
    vi.restoreAllMocks();
  });

  beforeEach(() => {
    Object.defineProperty(navigator, "clipboard", {
      configurable: true,
      value: { writeText: vi.fn().mockResolvedValue(undefined) },
    });
  });

  it("renders the location header, badges, and meta fields for a basic finding", async () => {
    const finding = makeFinding({
      verdict_blob: JSON.stringify({ message: "sink reached via tainted format string" }),
    });
    vi.spyOn(globalThis, "fetch").mockResolvedValue(jsonResponse(finding));

    render(wrap(<FindingDetail id="f-1" onClose={() => {}} />));

    // Subtitle stamps `cap · rule`.
    expect(await screen.findByText(/SQLi · py.sqli.format/)).toBeInTheDocument();
    // Location row stamps the file path next to the repo.
    expect(screen.getByText("src/handler.py")).toBeInTheDocument();
    // verdict_blob.message is lifted into the location section (and
    // mirrored by the CodeExcerpt fallback when no source_excerpt is
    // recorded yet, so two nodes match).
    expect(
      screen.getAllByText("sink reached via tainted format string").length,
    ).toBeGreaterThanOrEqual(1);
    // Provenance row carries the badge trio.
    expect(screen.getByText("High")).toBeInTheDocument();
    expect(screen.getByText("Open")).toBeInTheDocument();
    expect(screen.getByText("Static")).toBeInTheDocument();
    // No flow_steps recorded yet → muted fallback copy.
    expect(
      screen.getByText("No flow steps recorded for this finding."),
    ).toBeInTheDocument();
  });

  it("renders flow steps from verdict_blob.flow_steps and copies path:line on click", async () => {
    const finding = makeFinding({
      verdict_blob: JSON.stringify({
        flow_steps: [
          { path: "src/controller.py", line: 12, message: "user input" },
          { path: "src/sink.py", line: 88 },
        ],
      }),
    });
    vi.spyOn(globalThis, "fetch").mockResolvedValue(jsonResponse(finding));

    render(wrap(<FindingDetail id="f-1" onClose={() => {}} />));

    // The flow-step button does not carry an aria-label; query by its
    // title attribute instead so the assertion matches both the
    // accessible-name fallback and the visible text content.
    const stepButton = (await screen.findByTitle(
      "Copy src/controller.py:12",
    )) as HTMLButtonElement;
    fireEvent.click(stepButton);
    expect(navigator.clipboard.writeText).toHaveBeenCalledWith(
      "src/controller.py:12",
    );
    expect(
      await screen.findByText("Copied src/controller.py:12 to clipboard."),
    ).toBeInTheDocument();
  });

  it("calls onClose when the close button is clicked", async () => {
    vi.spyOn(globalThis, "fetch").mockResolvedValue(jsonResponse(makeFinding()));
    const onClose = vi.fn();
    render(wrap(<FindingDetail id="f-1" onClose={onClose} />));

    await screen.findByText(/SQLi · py.sqli.format/);
    fireEvent.click(screen.getByRole("button", { name: "Close detail panel" }));
    expect(onClose).toHaveBeenCalledTimes(1);
  });

  it("renders a verified badge when repro_path is set", async () => {
    const finding = makeFinding({
      repro_path: "/var/state/repro/f-1",
    });
    vi.spyOn(globalThis, "fetch").mockResolvedValue(jsonResponse(finding));
    render(wrap(<FindingDetail id="f-1" onClose={() => {}} />));

    expect(await screen.findByText("verified")).toBeInTheDocument();
    expect(screen.getByText("/var/state/repro/f-1")).toBeInTheDocument();
  });
});

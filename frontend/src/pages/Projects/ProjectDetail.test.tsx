import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { ReactNode } from "react";
import { MemoryRouter, Route, Routes } from "react-router-dom";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { ProjectDetail } from "./ProjectDetail";

class FakeWebSocket {
  static instances: FakeWebSocket[] = [];
  url: string;
  readyState = 0;
  onclose: ((ev: unknown) => void) | null = null;

  constructor(url: string) {
    this.url = url;
    FakeWebSocket.instances.push(this);
  }

  close() {
    this.readyState = 3;
    this.onclose?.({});
  }
}

function jsonResponse(body: unknown, init: ResponseInit = { status: 200 }) {
  return new Response(JSON.stringify(body), {
    ...init,
    headers: { "content-type": "application/json", ...(init.headers ?? {}) },
  });
}

function wrap(children: ReactNode, initial = "/projects/proj-1") {
  const qc = new QueryClient({
    defaultOptions: { queries: { retry: false }, mutations: { retry: false } },
  });
  return (
    <QueryClientProvider client={qc}>
      <MemoryRouter initialEntries={[initial]}>
        <Routes>
          <Route path="/projects/:projectId" element={children} />
          <Route path="/runs/:runId" element={<div>run detail</div>} />
        </Routes>
      </MemoryRouter>
    </QueryClientProvider>
  );
}

function readyProject() {
  return {
    id: "proj-1",
    name: "Demo App",
    description: null,
    target_base_url: "http://localhost:3000",
    env_config_json: null,
    runtime_profile: null,
    default_launch_profile: {
      id: "profile-1",
      project_id: "proj-1",
      name: "local",
      mode: "already-running",
      build_steps: [],
      start_steps: [],
      stop_steps: [],
      health_checks: [],
      target_urls: ["http://localhost:3000"],
      env_refs: [],
      working_dirs: [],
      readiness: "Ready",
      created_at: 1,
      updated_at: 1,
      is_default: true,
    },
    created_at: 1,
    updated_at: 1,
  };
}

function repos() {
  return [
    {
      id: "repo-1",
      name: "web",
      project_id: "proj-1",
      source_kind: "LocalPath",
      source_url_or_path: "/tmp/web",
      branch: null,
      auth_ref: null,
      i_own_this: true,
      last_scan_run_id: null,
      last_scan_finished_at: null,
      created_at: 1,
      updated_at: 1,
    },
  ];
}

describe("ProjectDetail", () => {
  let originalWS: typeof WebSocket;

  beforeEach(() => {
    originalWS = window.WebSocket;
    (window as unknown as { WebSocket: unknown }).WebSocket =
      FakeWebSocket as unknown as typeof WebSocket;
    FakeWebSocket.instances = [];
  });

  afterEach(() => {
    (window as unknown as { WebSocket: unknown }).WebSocket = originalWS;
    vi.restoreAllMocks();
  });

  it("opens Start pentest safety options and posts the selected exploit policy", async () => {
    const pentestBodies: unknown[] = [];
    vi.spyOn(globalThis, "fetch").mockImplementation(async (input, init) => {
      const url = typeof input === "string" ? input : (input as Request).url;
      if (url === "/api/v1/projects/proj-1") return jsonResponse(readyProject());
      if (url === "/api/v1/projects/proj-1/repos") return jsonResponse(repos());
      if (url === "/api/v1/projects/proj-1/vulnerabilities") return jsonResponse([]);
      if (url === "/api/v1/projects/proj-1/pentest") {
        pentestBodies.push(JSON.parse(String(init?.body)));
        return jsonResponse({ run_id: "run-1" });
      }
      throw new Error(`unexpected url ${url}`);
    });

    render(wrap(<ProjectDetail />));

    expect(await screen.findByRole("heading", { name: "Demo App" })).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: "Start pentest" }));

    expect(screen.getByRole("dialog", { name: "Start pentest" })).toBeInTheDocument();
    const exploitMode = screen.getByLabelText(/Exploit mode/) as HTMLInputElement;
    const browserChecks = screen.getByLabelText(/Browser verification/) as HTMLInputElement;
    const stateChanging = screen.getByLabelText(/State-changing probes/) as HTMLInputElement;
    expect(exploitMode.checked).toBe(false);
    expect(browserChecks.checked).toBe(false);
    expect(stateChanging).toBeDisabled();

    fireEvent.click(browserChecks);
    fireEvent.click(exploitMode);
    expect(stateChanging).not.toBeDisabled();
    fireEvent.click(stateChanging);
    fireEvent.click(screen.getByRole("button", { name: "Start with exploit mode" }));

    await waitFor(() =>
      expect(pentestBodies).toEqual([
        {
          exploit_mode_enabled: true,
          allow_state_changing_live_probes: true,
          browser_checks_enabled: true,
          business_logic_template_ids: [],
        },
      ]),
    );
  });
});

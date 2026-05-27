import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { ReactNode } from "react";
import { MemoryRouter, Route, Routes } from "react-router-dom";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { ToastProvider } from "@/components/Toast";
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
      <ToastProvider>
        <MemoryRouter initialEntries={[initial]}>
          <Routes>
            <Route path="/projects/:projectId" element={children} />
            <Route path="/projects/:projectId/repos" element={<ProjectDetail view="repos" />} />
            <Route path="/projects/:projectId/runs/:runId" element={<div>run detail</div>} />
            <Route path="/runs/:runId" element={<div>run detail</div>} />
          </Routes>
        </MemoryRouter>
      </ToastProvider>
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
      seed_steps: [],
      reset_steps: [],
      login_steps: [],
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
    vi.useRealTimers();
    vi.restoreAllMocks();
  });

  it("opens Start pentest safety options and posts the selected exploit policy", async () => {
    const pentestBodies: unknown[] = [];
    vi.spyOn(globalThis, "fetch").mockImplementation(async (input, init) => {
      const url = typeof input === "string" ? input : (input as Request).url;
      if (url === "/api/v1/projects/proj-1") return jsonResponse(readyProject());
      if (url === "/api/v1/projects/proj-1/repos") return jsonResponse(repos());
      if (url === "/api/v1/projects/proj-1/vulnerabilities") return jsonResponse([]);
      if (url === "/api/v1/projects/proj-1/integrations") return jsonResponse([]);
      if (url === "/api/v1/projects/proj-1/setup/ai") return jsonResponse({ jobs: [] });
      if (url.startsWith("/api/v1/runs?")) return jsonResponse([]);
      if (url === "/api/v1/projects/proj-1/pentest") {
        pentestBodies.push(JSON.parse(String(init?.body)));
        return jsonResponse({ run_id: "run-1" });
      }
      throw new Error(`unexpected url ${url}`);
    });

    render(wrap(<ProjectDetail />));

    expect(await screen.findByRole("heading", { name: "Demo App" })).toBeInTheDocument();
    expect(screen.getAllByRole("button", { name: "Start pentest" })).toHaveLength(1);
    fireEvent.click(screen.getByRole("button", { name: "Start pentest" }));

    expect(screen.getByRole("dialog", { name: "Start pentest" })).toBeInTheDocument();
    const exploitMode = screen.getByLabelText(/Exploit mode/) as HTMLInputElement;
    const browserChecks = screen.getByLabelText(/Browser verification/) as HTMLInputElement;
    const researchMode = screen.getByLabelText(/Vuln research mode/) as HTMLInputElement;
    const unsafeAttackAgent = screen.getByLabelText(/Unsafe attack agent/) as HTMLInputElement;
    const stateChanging = screen.getByLabelText(/State-changing probes/) as HTMLInputElement;
    expect(exploitMode.checked).toBe(false);
    expect(browserChecks.checked).toBe(false);
    expect(researchMode.checked).toBe(false);
    expect(unsafeAttackAgent.checked).toBe(false);
    expect(stateChanging).toBeDisabled();

    fireEvent.click(browserChecks);
    fireEvent.click(researchMode);
    fireEvent.click(unsafeAttackAgent);
    fireEvent.click(exploitMode);
    expect(stateChanging).not.toBeDisabled();
    fireEvent.click(stateChanging);
    fireEvent.click(screen.getByRole("button", { name: "Start full-depth pentest" }));

    await waitFor(() =>
      expect(pentestBodies).toEqual([
        {
          exploit_mode_enabled: true,
          allow_state_changing_live_probes: true,
          browser_checks_enabled: true,
          research_mode_enabled: true,
          unsafe_attack_agent_enabled: true,
          business_logic_template_ids: [],
        },
      ]),
    );
  });

  it("keeps Start pentest primary and moves AI setup into readiness", async () => {
    vi.spyOn(globalThis, "fetch").mockImplementation(async (input) => {
      const url = typeof input === "string" ? input : (input as Request).url;
      if (url === "/api/v1/projects/proj-1") return jsonResponse(readyProject());
      if (url === "/api/v1/projects/proj-1/repos") return jsonResponse(repos());
      if (url === "/api/v1/projects/proj-1/vulnerabilities") return jsonResponse([]);
      if (url === "/api/v1/projects/proj-1/integrations") return jsonResponse([]);
      if (url === "/api/v1/projects/proj-1/setup/ai") return jsonResponse({ jobs: [] });
      if (url.startsWith("/api/v1/runs?")) return jsonResponse([]);
      throw new Error(`unexpected url ${url}`);
    });

    render(wrap(<ProjectDetail />));

    const title = await screen.findByRole("heading", { name: "Demo App" });
    const projectHeader = title.closest(".page-header");
    expect(projectHeader).not.toBeNull();
    if (!projectHeader) throw new Error("missing project header");

    const startPentest = screen.getByRole("button", { name: "Start pentest" });
    expect(projectHeader).toContainElement(startPentest);
    expect(startPentest).toHaveClass("btn--primary");

    const aiSetup = screen.getByRole("button", { name: "AI setup" });
    expect(projectHeader).not.toContainElement(aiSetup);
    expect(aiSetup).toHaveClass("btn--sm");
    expect(aiSetup.closest(".project-readiness__header-actions")).not.toBeNull();
  });

  it("updates Start pentest copy as options are selected", async () => {
    vi.spyOn(globalThis, "fetch").mockImplementation(async (input) => {
      const url = typeof input === "string" ? input : (input as Request).url;
      if (url === "/api/v1/projects/proj-1") return jsonResponse(readyProject());
      if (url === "/api/v1/projects/proj-1/repos") return jsonResponse(repos());
      if (url === "/api/v1/projects/proj-1/vulnerabilities") return jsonResponse([]);
      if (url === "/api/v1/projects/proj-1/integrations") return jsonResponse([]);
      if (url === "/api/v1/projects/proj-1/setup/ai") return jsonResponse({ jobs: [] });
      if (url.startsWith("/api/v1/runs?")) return jsonResponse([]);
      throw new Error(`unexpected url ${url}`);
    });

    render(wrap(<ProjectDetail />));

    expect(await screen.findByRole("heading", { name: "Demo App" })).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: "Start pentest" }));

    expect(screen.getByRole("button", { name: "Start safe pentest" })).toBeInTheDocument();
    expect(screen.getByText(/Safe mode is the default/)).toBeInTheDocument();

    fireEvent.click(screen.getByLabelText(/Browser verification/));
    expect(
      screen.getByRole("button", { name: "Start browser-verified pentest" }),
    ).toBeInTheDocument();
    expect(
      screen.getByText(/Playwright-backed browser verification is enabled/),
    ).toBeInTheDocument();

    fireEvent.click(screen.getByLabelText(/Vuln research mode/));
    expect(
      screen.getByRole("button", { name: "Start browser research pentest" }),
    ).toBeInTheDocument();
    expect(screen.getByText(/Browser checks and research mode/)).toBeInTheDocument();

    fireEvent.click(screen.getByLabelText(/Unsafe attack agent/));
    expect(
      screen.getByRole("button", { name: "Start guided attack-agent run" }),
    ).toBeInTheDocument();
    expect(screen.getByText(/will guide the unsafe local attack agent/)).toBeInTheDocument();

    fireEvent.click(screen.getByLabelText(/Exploit mode/));
    expect(screen.getByRole("button", { name: "Start guided exploit attack" })).toBeInTheDocument();
    expect(screen.getByText(/state-changing probes stay blocked/)).toBeInTheDocument();

    fireEvent.click(screen.getByLabelText(/State-changing probes/));
    expect(screen.getByRole("button", { name: "Start full-depth pentest" })).toBeInTheDocument();
    expect(
      screen.getByText(/Research, browser verification, exploit planning/),
    ).toBeInTheDocument();
  });

  it("sends AI setup to repositories with guidance when no repo is linked", async () => {
    vi.spyOn(globalThis, "fetch").mockImplementation(async (input) => {
      const url = typeof input === "string" ? input : (input as Request).url;
      if (url === "/api/v1/projects/proj-1") return jsonResponse(readyProject());
      if (url === "/api/v1/projects/proj-1/repos") return jsonResponse([]);
      if (url === "/api/v1/projects/proj-1/vulnerabilities") return jsonResponse([]);
      if (url === "/api/v1/projects/proj-1/integrations") return jsonResponse([]);
      if (url === "/api/v1/projects/proj-1/setup/ai") return jsonResponse({ jobs: [] });
      if (url.startsWith("/api/v1/runs?")) return jsonResponse([]);
      throw new Error(`unexpected url ${url}`);
    });

    render(wrap(<ProjectDetail />));

    expect(await screen.findByRole("heading", { name: "Demo App" })).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: "AI setup" }));

    expect(await screen.findByRole("heading", { name: "Repositories" })).toBeInTheDocument();
    expect(await screen.findByText("Add a repository to use AI setup mode.")).toBeInTheDocument();
    expect(screen.getByText("No repositories yet")).toBeInTheDocument();
  });

  it("autosaves environment edits with lifecycle hooks last", async () => {
    const patchRequests: Array<{ url: string; body: Record<string, unknown> }> = [];
    vi.spyOn(globalThis, "fetch").mockImplementation(async (input, init) => {
      const url = typeof input === "string" ? input : (input as Request).url;
      const method = init?.method ?? "GET";
      if (url === "/api/v1/projects/proj-1" && method === "GET") {
        return jsonResponse(readyProject());
      }
      if (url === "/api/v1/projects/proj-1/repos") return jsonResponse(repos());
      if (url === "/api/v1/projects/proj-1/vulnerabilities") return jsonResponse([]);
      if (url === "/api/v1/projects/proj-1/integrations") return jsonResponse([]);
      if (url === "/api/v1/projects/proj-1/setup/ai") return jsonResponse({ jobs: [] });
      if (url.startsWith("/api/v1/runs?")) return jsonResponse([]);
      if (url === "/api/v1/launch-target/test") {
        return jsonResponse({ ok: true, url: "http://localhost:3000", message: "Reachable" });
      }
      if (url === "/api/v1/projects/proj-1" && method === "PATCH") {
        const body = JSON.parse(String(init?.body)) as Record<string, unknown>;
        patchRequests.push({ url, body });
        return jsonResponse({ ...readyProject(), runtime_profile: body.runtime_profile ?? null });
      }
      if (url === "/api/v1/projects/proj-1/launch-profile/default" && method === "PATCH") {
        const body = JSON.parse(String(init?.body)) as Record<string, unknown>;
        patchRequests.push({ url, body });
        return jsonResponse({
          ...readyProject().default_launch_profile,
          ...body,
          updated_at: 2,
        });
      }
      throw new Error(`unexpected url ${url}`);
    });

    render(wrap(<ProjectDetail view="environments" />));

    expect(await screen.findByText("Launch Profile")).toBeInTheDocument();
    fireEvent.click(screen.getByText("Lifecycle hooks"));
    fireEvent.click(screen.getByRole("button", { name: "Add seed command" }));
    fireEvent.click(screen.getByText("Lifecycle hooks"));
    const seedCommand = screen.getByLabelText("Seed command 1");
    fireEvent.focus(seedCommand);
    fireEvent.change(seedCommand, {
      target: { value: "npm run seed:test" },
    });
    expect(patchRequests).toHaveLength(0);
    fireEvent.blur(seedCommand, { relatedTarget: document.body });

    await waitFor(() => expect(patchRequests).toHaveLength(2), { timeout: 2_000 });
    expect(patchRequests.map((request) => request.url)).toEqual([
      "/api/v1/projects/proj-1",
      "/api/v1/projects/proj-1/launch-profile/default",
    ]);
    expect(patchRequests[0].body).toMatchObject({
      runtime_profile: { target_base_url: "http://localhost:3000" },
    });
    expect(patchRequests[1].body).toMatchObject({
      seed_steps: [{ command: "npm run seed:test" }],
    });
    expect(await screen.findByText("Autosaved")).toBeInTheDocument();
  });

  it("keeps open environment sections while typing before autosave", async () => {
    const patchRequests: Array<{ url: string; body: Record<string, unknown> }> = [];
    vi.spyOn(globalThis, "fetch").mockImplementation(async (input, init) => {
      const url = typeof input === "string" ? input : (input as Request).url;
      const method = init?.method ?? "GET";
      if (url === "/api/v1/projects/proj-1" && method === "GET") {
        return jsonResponse(readyProject());
      }
      if (url === "/api/v1/projects/proj-1/repos") return jsonResponse(repos());
      if (url === "/api/v1/projects/proj-1/vulnerabilities") return jsonResponse([]);
      if (url === "/api/v1/projects/proj-1/integrations") return jsonResponse([]);
      if (url === "/api/v1/projects/proj-1/setup/ai") return jsonResponse({ jobs: [] });
      if (url.startsWith("/api/v1/runs?")) return jsonResponse([]);
      if (url === "/api/v1/launch-target/test") {
        return jsonResponse({ ok: true, url: "http://localhost:3000", message: "Reachable" });
      }
      if (url === "/api/v1/projects/proj-1" && method === "PATCH") {
        const body = JSON.parse(String(init?.body)) as Record<string, unknown>;
        patchRequests.push({ url, body });
        return jsonResponse({ ...readyProject(), runtime_profile: body.runtime_profile ?? null });
      }
      if (url === "/api/v1/projects/proj-1/launch-profile/default" && method === "PATCH") {
        const body = JSON.parse(String(init?.body)) as Record<string, unknown>;
        patchRequests.push({ url, body });
        return jsonResponse({
          ...readyProject().default_launch_profile,
          ...body,
          updated_at: 2,
        });
      }
      throw new Error(`unexpected url ${url}`);
    });

    render(wrap(<ProjectDetail view="environments" />));

    expect(await screen.findByText("Launch Profile")).toBeInTheDocument();
    fireEvent.click(screen.getByText("Environment"));
    const environmentDetails = screen.getByText("Environment").closest("details");
    const envFile = screen.getByLabelText("Env file path");
    fireEvent.focus(envFile);
    fireEvent.change(envFile, { target: { value: "." } });

    expect(environmentDetails).toHaveAttribute("open");
    expect(patchRequests).toHaveLength(0);

    fireEvent.change(envFile, { target: { value: ".env.dev" } });
    expect(environmentDetails).toHaveAttribute("open");
    fireEvent.blur(envFile, { relatedTarget: document.body });

    await waitFor(() => expect(patchRequests).toHaveLength(2), { timeout: 2_000 });
    expect(patchRequests[1].body).toMatchObject({
      env_refs: [{ kind: "env-file", value: ".env.dev", secret: true }],
    });
    expect(environmentDetails).toHaveAttribute("open");
  });
});

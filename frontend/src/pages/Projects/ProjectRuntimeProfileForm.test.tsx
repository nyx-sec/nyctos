import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { ReactNode, useState } from "react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { AuthSetupJobsProvider } from "@/components/AuthSetupJobs";
import { ToastProvider } from "@/components/Toast";
import { ProjectAddModal } from "./ProjectAddModal";
import {
  emptyRuntimeProfileDraft,
  launchProfileFromDraft,
  ProjectRuntimeProfileForm,
  type RuntimeProfileDraft,
  runtimeProfileFromDraft,
} from "./ProjectRuntimeProfileForm";

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
      <ToastProvider>
        <AuthSetupJobsProvider>{children}</AuthSetupJobsProvider>
      </ToastProvider>
    </QueryClientProvider>
  );
}

function FormHarness() {
  const [draft, setDraft] = useState<RuntimeProfileDraft>(() => emptyRuntimeProfileDraft());
  return wrap(<ProjectRuntimeProfileForm value={draft} onChange={setDraft} />);
}

function AuthSetupHarness() {
  const [draft, setDraft] = useState<RuntimeProfileDraft>(() =>
    emptyRuntimeProfileDraft("http://localhost:3000"),
  );
  return wrap(
    <ProjectRuntimeProfileForm value={draft} onChange={setDraft} projectId="proj-auth" />,
  );
}

describe("ProjectRuntimeProfileForm", () => {
  afterEach(() => {
    vi.restoreAllMocks();
  });

  it("adds command rows and serializes trimmed profile fields", () => {
    const draft = emptyRuntimeProfileDraft();
    draft.target_base_url = " http://localhost:3000 ";
    draft.readiness_kind = "custom-url";
    draft.health_check_url = " http://localhost:3000/health ";
    draft.allowed_hosts = "localhost\n127.0.0.1, localhost";
    draft.env_file = " .env.test ";
    draft.timeout_seconds = "300";
    draft.build_commands = [
      {
        command: " npm ci ",
        repo_name: " web ",
        working_directory: "",
        timeout_seconds: "120",
      },
    ];
    draft.start_commands = [
      {
        command: " npm run dev ",
        repo_name: " web ",
        working_directory: " apps/web ",
        timeout_seconds: "",
      },
    ];
    draft.env_vars = [{ name: " NODE_ENV ", value: " test ", secret: false }];

    expect(runtimeProfileFromDraft(draft)).toEqual({
      build_commands: [{ command: "npm ci", repo_name: "web", timeout_seconds: 120 }],
      start_commands: [{ command: "npm run dev", repo_name: "web", working_directory: "apps/web" }],
      health_check_url: "http://localhost:3000/health",
      target_base_url: "http://localhost:3000",
      allowed_hosts: ["localhost", "127.0.0.1"],
      env_vars: [{ name: "NODE_ENV", value: "test", secret: false }],
      auth_profiles: [],
      env_file: ".env.test",
      timeout_seconds: 300,
    });
  });

  it("serializes auth profile metadata without raw secrets", () => {
    const draft = emptyRuntimeProfileDraft("http://localhost:3000");
    draft.auth_profiles = [
      {
        role: " user_a ",
        mode: "header_injection",
        label: "",
        session_cache_ttl_seconds: "600",
        session_import_path: "",
        login_url: " /login ",
        username: " alice@example.test ",
        username_env: "",
        login_email_env: "",
        password_env: " NYCTOS_USER_A_PASSWORD ",
        cookie_env: "",
        bearer_token_env: " NYCTOS_USER_A_TOKEN ",
        headers: [{ name: " X-Test-Role ", value_env: " NYCTOS_USER_A_ROLE " }],
        otp_source_kind: "manual",
        otp_mailbox_url: "",
        otp_email_env: "",
        otp_subject_contains: "",
        otp_body_regex: "",
        post_login_assertion: "",
        post_login_assertions: [{ kind: "cookie_exists", value: " sid ", status: "" }],
        custom_command: "",
        owned_objects: [
          {
            name: " project ",
            id: " proj-user-a-1 ",
            route: " /api/projects/{id} ",
            marker: " owned-by-a ",
          },
        ],
      },
    ];

    expect(runtimeProfileFromDraft(draft)?.auth_profiles).toEqual([
      {
        role: "user_a",
        mode: "header_injection",
        session_cache_ttl_seconds: 600,
        login_url: "/login",
        username: "alice@example.test",
        password_env: "NYCTOS_USER_A_PASSWORD",
        bearer_token_env: "NYCTOS_USER_A_TOKEN",
        headers: [{ name: "X-Test-Role", value_env: "NYCTOS_USER_A_ROLE" }],
        post_login_assertions: [{ kind: "cookie_exists", value: "sid" }],
        owned_objects: [
          {
            name: "project",
            id: "proj-user-a-1",
            route: "/api/projects/{id}",
            marker: "owned-by-a",
          },
        ],
      },
    ]);
  });

  it("serializes launch environment as references only", () => {
    const draft = emptyRuntimeProfileDraft("http://localhost:3000");
    draft.env_file = " .env.dev ";
    draft.env_vars = [{ name: " NODE_ENV ", value: "ignored", secret: false }];

    expect(launchProfileFromDraft(draft)?.env_refs).toEqual([
      { kind: "env-file", value: ".env.dev", secret: true },
      { kind: "env-var", value: "NODE_ENV", secret: false },
    ]);
  });

  it("keeps launch commands optional and lets the operator add one", () => {
    render(<FormHarness />);

    fireEvent.click(screen.getByRole("radio", { name: "Start project" }));
    fireEvent.click(screen.getByText("Launch commands"));
    fireEvent.click(screen.getByRole("button", { name: "Add setup command" }));
    fireEvent.change(screen.getByLabelText("Setup command 1"), {
      target: { value: "npm run build" },
    });

    expect(screen.getByDisplayValue("npm run build")).toBeInTheDocument();
  });

  it("auto-tests a typed app URL through the daemon", async () => {
    vi.spyOn(globalThis, "fetch").mockImplementation(async (_input, init) => {
      const body = init?.body ? JSON.parse(String(init.body)) : {};
      return jsonResponse({
        ok: true,
        url: body.url,
        message: "Reachable in 12ms",
        status: 200,
        elapsed_ms: 12,
      });
    });

    render(<FormHarness />);

    fireEvent.change(screen.getByLabelText("App URL"), {
      target: { value: "http://localhost:3000" },
    });

    expect(await screen.findByText("Reachable", {}, { timeout: 2_000 })).toBeInTheDocument();
    expect(screen.getByText("Reachable in 12ms")).toBeInTheDocument();
  });

  it("runs auth setup from the roles panel and applies returned profiles", async () => {
    const requests: unknown[] = [];
    const completedResult = {
      project: {
        id: "proj-auth",
        name: "auth-app",
        description: null,
        target_base_url: "http://localhost:3000",
        env_config_json: null,
        default_launch_profile: null,
        runtime_profile: {
          build_commands: [],
          start_commands: [],
          target_base_url: "http://localhost:3000",
          allowed_hosts: [],
          env_vars: [
            { name: "NYCTOS_USER_A_USERNAME", value: "user-a@example.test", secret: false },
            { name: "NYCTOS_USER_A_PASSWORD", value: "user-a-pass", secret: true },
          ],
          auth_profiles: [
            {
              role: "user_a",
              mode: "ai_auto",
              login_url: "/api/auth/login",
              username_env: "NYCTOS_USER_A_USERNAME",
              password_env: "NYCTOS_USER_A_PASSWORD",
              headers: [],
              post_login_assertions: [],
              owned_objects: [
                {
                  name: "project",
                  id: "proj-user-a-1",
                  route: "/api/projects/{id}",
                  marker: "owned-by-a",
                },
              ],
            },
          ],
        },
        created_at: 1,
        updated_at: 2,
      },
      roles: ["user_a"],
      login_paths: ["/api/auth/login"],
      object_routes: ["/api/projects/:id"],
      agent_used: true,
      verification: {
        status: "verified",
        checks: ["/api/auth/login route found"],
        warnings: [],
      },
      profiles_added: 1,
      profiles_updated: 0,
      message: "Auth setup saved 1 role profile from 1 inspected source file.",
    };
    vi.spyOn(globalThis, "fetch").mockImplementation(async (input, init) => {
      const url = String(input);
      const body = init?.body ? JSON.parse(String(init.body)) : {};
      if (url.includes("/launch-target/test")) {
        return jsonResponse({ ok: true, url: body.url, message: "Reachable", status: 200 });
      }
      if (url.includes("/auth/auto-setup/job-1")) {
        return jsonResponse({
          id: "job-1",
          project_id: "proj-auth",
          status: "succeeded",
          phase: "complete",
          message: completedResult.message,
          started_at: 1,
          finished_at: 2,
          events: [
            { at: 1, phase: "queued", message: "Auth setup queued." },
            { at: 2, phase: "complete", message: completedResult.message },
          ],
          result: completedResult,
        });
      }
      requests.push(body);
      return jsonResponse({
        job: {
          id: "job-1",
          project_id: "proj-auth",
          status: "queued",
          phase: "queued",
          message: "Auth setup queued.",
          started_at: 1,
          events: [{ at: 1, phase: "queued", message: "Auth setup queued." }],
        },
      });
    });

    render(<AuthSetupHarness />);

    fireEvent.click(screen.getByText("Auth profiles"));
    fireEvent.click(screen.getByRole("button", { name: "Explore repo" }));

    expect(await screen.findByDisplayValue("user_a")).toBeInTheDocument();
    expect(screen.getByDisplayValue("/api/auth/login")).toBeInTheDocument();
    expect(screen.getAllByDisplayValue("NYCTOS_USER_A_USERNAME").length).toBeGreaterThan(1);
    expect(screen.getAllByDisplayValue("NYCTOS_USER_A_PASSWORD").length).toBeGreaterThan(1);
    expect(screen.getByDisplayValue("user-a-pass")).toBeInTheDocument();
    expect(screen.getByDisplayValue("proj-user-a-1")).toBeInTheDocument();
    expect(screen.getAllByText(/Auth setup saved 1 role profile/).length).toBeGreaterThan(0);
    expect(requests[0]).toMatchObject({ target_base_url: "http://localhost:3000" });
  });

  it("opens the new-project modal without immediate validation noise", () => {
    render(wrap(<ProjectAddModal onClose={() => {}} onAdded={() => {}} />));

    expect(screen.getByRole("dialog", { name: "New project" })).toBeInTheDocument();
    expect(screen.queryByText("Name is required")).not.toBeInTheDocument();
  });

  it("posts the typed launch profile from the new-project modal", async () => {
    const requests: unknown[] = [];
    vi.spyOn(globalThis, "fetch").mockImplementation(async (_input, init) => {
      const url = String(_input);
      const body = init?.body ? JSON.parse(String(init.body)) : {};
      if (url.includes("/launch-target/test")) {
        return jsonResponse({
          ok: true,
          url: body.url,
          message: "Reachable in 12ms",
          status: 200,
          elapsed_ms: 12,
        });
      }
      requests.push(body);
      return jsonResponse({
        id: "proj-acme",
        name: body.name,
        description: body.description ?? null,
        target_base_url: body.target_base_url ?? null,
        env_config_json: null,
        runtime_profile: body.runtime_profile ?? null,
        default_launch_profile: body.default_launch_profile ?? null,
        created_at: 1,
        updated_at: 1,
      });
    });
    const onAdded = vi.fn();

    render(wrap(<ProjectAddModal onClose={() => {}} onAdded={onAdded} />));

    fireEvent.change(screen.getByPlaceholderText("acme-app"), { target: { value: "acme" } });
    fireEvent.change(screen.getByLabelText("App URL"), {
      target: { value: "http://localhost:3000" },
    });
    fireEvent.click(screen.getByRole("button", { name: "Create project" }));

    await waitFor(() =>
      expect(onAdded).toHaveBeenCalledWith(
        expect.objectContaining({ id: "proj-acme", name: "acme" }),
      ),
    );
    expect(requests.find((body) => (body as { name?: string }).name === "acme")).toMatchObject({
      name: "acme",
      target_base_url: "http://localhost:3000",
      default_launch_profile: {
        mode: "already-running",
        build_steps: [],
        start_steps: [],
        health_checks: [{ kind: "http", url: "http://localhost:3000" }],
        target_urls: ["http://localhost:3000"],
        env_refs: [],
      },
    });
  });
});

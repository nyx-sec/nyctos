import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { ReactNode, useState } from "react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { ProjectAddModal } from "./ProjectAddModal";
import {
  emptyRuntimeProfileDraft,
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
  return <QueryClientProvider client={qc}>{children}</QueryClientProvider>;
}

function FormHarness() {
  const [draft, setDraft] = useState<RuntimeProfileDraft>(() => emptyRuntimeProfileDraft());
  return <ProjectRuntimeProfileForm value={draft} onChange={setDraft} />;
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
      },
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

    await waitFor(() => expect(onAdded).toHaveBeenCalledWith("acme"));
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

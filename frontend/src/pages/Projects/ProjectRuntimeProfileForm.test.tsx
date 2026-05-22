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
    draft.health_check_url = " http://localhost:3000/health ";
    draft.allowed_hosts = "localhost\n127.0.0.1, localhost";
    draft.env_file = " .env.test ";
    draft.timeout_seconds = "300";
    draft.build_commands[0] = {
      command: " npm ci ",
      repo_name: " web ",
      working_directory: "",
      timeout_seconds: "120",
    };
    draft.start_commands[0] = {
      command: " npm run dev ",
      repo_name: " web ",
      working_directory: " apps/web ",
      timeout_seconds: "",
    };
    draft.env_vars[0] = { name: " NODE_ENV ", value: " test ", secret: false };

    expect(runtimeProfileFromDraft(draft)).toEqual({
      build_commands: [{ command: "npm ci", repo_name: "web", timeout_seconds: 120 }],
      start_commands: [{ command: "npm run dev", repo_name: "web", working_directory: "apps/web" }],
      health_check_url: "http://localhost:3000/health",
      target_base_url: "http://localhost:3000",
      allowed_hosts: ["localhost", "127.0.0.1"],
      env_vars: [{ name: "NODE_ENV", value: "test", secret: false }],
      env_file: ".env.test",
      timeout_seconds: 300,
    });
  });

  it("lets the operator add a second build command row", () => {
    render(<FormHarness />);

    fireEvent.click(screen.getAllByRole("button", { name: "Add command" })[0]);
    fireEvent.change(screen.getByLabelText("Build command 2"), {
      target: { value: "npm run build" },
    });

    expect(screen.getByDisplayValue("npm run build")).toBeInTheDocument();
  });

  it("posts the typed launch profile from the new-project modal", async () => {
    const requests: unknown[] = [];
    vi.spyOn(globalThis, "fetch").mockImplementation(async (_input, init) => {
      const body = init?.body ? JSON.parse(String(init.body)) : {};
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
    fireEvent.change(screen.getByLabelText("Runtime target base URL"), {
      target: { value: "http://localhost:3000" },
    });
    fireEvent.change(screen.getByLabelText("Health check URL"), {
      target: { value: "http://localhost:3000/health" },
    });
    fireEvent.change(screen.getByLabelText("Build command 1"), {
      target: { value: "npm ci" },
    });
    fireEvent.change(screen.getByLabelText("Start command 1"), {
      target: { value: "npm run dev" },
    });
    fireEvent.change(screen.getByLabelText("Env file path"), { target: { value: ".env.test" } });
    fireEvent.click(screen.getByRole("button", { name: "Create project" }));

    await waitFor(() => expect(onAdded).toHaveBeenCalledWith("acme"));
    expect(requests[0]).toMatchObject({
      name: "acme",
      target_base_url: "http://localhost:3000",
      default_launch_profile: {
        build_steps: [{ command: "npm ci" }],
        start_steps: [{ command: "npm run dev" }],
        health_checks: [{ kind: "http", url: "http://localhost:3000/health" }],
        target_urls: ["http://localhost:3000"],
        env_refs: [{ kind: "env-file", value: ".env.test", secret: true }],
      },
    });
  });
});

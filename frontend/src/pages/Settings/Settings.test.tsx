import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { Settings } from "./Settings";

interface RecordedCall {
  url: string;
  method: string;
  body: string | null;
}

let recorded: RecordedCall[];
let statusPayload: Record<string, unknown>;
let doctorPayload: { checks: { name: string; passed: boolean; message: string }[] };

function defaultStatus(): Record<string, unknown> {
  return {
    complete: true,
    config_path: "/tmp/nyx-agent.toml",
    ai_runtime: "none",
    ai_provider: null,
    ai_model: null,
    ai_api_base: null,
    default_run_budget_usd_micros: null,
    sandbox_backend: "auto",
    sandbox_enabled: true,
    sandbox_allow_network: false,
    ui_listen_addr: "127.0.0.1:8765",
    ui_open_browser: true,
    log_level: "info",
    state_dir: null,
    max_parallel_scans: 4,
    scan_timeout_secs: 600,
  };
}

function renderSettings() {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={qc}>
      <Settings />
    </QueryClientProvider>,
  );
}

async function waitForSettings() {
  await screen.findByText("AI runtime");
}

describe("Settings page", () => {
  beforeEach(() => {
    window.localStorage.clear();
    recorded = [];
    statusPayload = defaultStatus();
    doctorPayload = { checks: [] };
    vi.stubGlobal(
      "fetch",
      vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
        const url = typeof input === "string" ? input : input.toString();
        const method = (init?.method ?? "GET").toUpperCase();
        const body =
          typeof init?.body === "string" ? init.body : init?.body ? String(init.body) : null;
        recorded.push({ url, method, body });
        if (url.endsWith("/setup/status")) {
          return new Response(JSON.stringify(statusPayload), {
            status: 200,
            headers: { "content-type": "application/json" },
          });
        }
        if (url.endsWith("/setup/doctor")) {
          return new Response(JSON.stringify(doctorPayload), {
            status: 200,
            headers: { "content-type": "application/json" },
          });
        }
        if (url.endsWith("/setup") && method === "POST") {
          return new Response(JSON.stringify({ ok: true, config_path: "/tmp/nyx-agent.toml" }), {
            status: 200,
            headers: { "content-type": "application/json" },
          });
        }
        return new Response("{}", {
          status: 200,
          headers: { "content-type": "application/json" },
        });
      }),
    );
  });

  afterEach(() => {
    window.localStorage.clear();
    vi.unstubAllGlobals();
  });

  it("renders daemon runtime, backend, and local configuration details", async () => {
    statusPayload = {
      ...defaultStatus(),
      ai_runtime: "claude-code",
      ai_provider: "claude-code",
      ai_model: "opus",
      ai_effort: "high",
      ai_context_window: 1000000,
      sandbox_backend: "birdcage",
      ui_listen_addr: "127.0.0.1:9999",
      ui_open_browser: false,
      log_level: "debug",
      state_dir: "/tmp/nyx-agent-state",
      max_parallel_scans: 7,
      scan_timeout_secs: 42,
    };

    renderSettings();
    await waitForSettings();

    expect(screen.getAllByText(/Claude Code CLI/).length).toBeGreaterThan(0);
    expect(screen.getAllByText("opus").length).toBeGreaterThan(0);
    expect(screen.getAllByText("High").length).toBeGreaterThan(0);
    expect(screen.getAllByText("1M tokens").length).toBeGreaterThan(0);
    expect(screen.getAllByText("Birdcage").length).toBeGreaterThan(0);
    expect(screen.getByText("127.0.0.1:9999")).toBeInTheDocument();
    expect(screen.getAllByText("Unlimited").length).toBeGreaterThan(0);
    expect(screen.getByText("7 parallel / 42s")).toBeInTheDocument();
    expect(screen.getByText("/tmp/nyx-agent-state")).toBeInTheDocument();
  });

  it("renders Off when the advanced preference is unset", async () => {
    renderSettings();
    await waitForSettings();

    const toggle = screen.getByLabelText("Show advanced UI") as HTMLInputElement;
    expect(toggle.checked).toBe(false);
    expect(screen.getByText("Off")).toBeInTheDocument();
  });

  it("renders On when localStorage carries the opt-in", async () => {
    window.localStorage.setItem("nyx.advanced", "1");
    renderSettings();
    await waitForSettings();

    const toggle = screen.getByLabelText("Show advanced UI") as HTMLInputElement;
    expect(toggle.checked).toBe(true);
    expect(screen.getByText("On")).toBeInTheDocument();
  });

  it("flips the advanced toggle and persists the new value to localStorage", async () => {
    renderSettings();
    await waitForSettings();
    const toggle = screen.getByLabelText("Show advanced UI") as HTMLInputElement;
    expect(toggle.checked).toBe(false);

    fireEvent.click(toggle);

    expect(toggle.checked).toBe(true);
    expect(window.localStorage.getItem("nyx.advanced")).toBe("1");
    expect(screen.getByText("On")).toBeInTheDocument();

    fireEvent.click(toggle);
    expect(toggle.checked).toBe(false);
    expect(window.localStorage.getItem("nyx.advanced")).toBe("0");
    expect(screen.getByText("Off")).toBeInTheDocument();
  });

  it("saves updated AI runtime and sandbox backend selections", async () => {
    renderSettings();
    await waitForSettings();

    fireEvent.click(screen.getByRole("radio", { name: /Claude Code CLI/i }));
    fireEvent.change(screen.getByLabelText("Model"), {
      target: { value: "opus" },
    });
    fireEvent.change(screen.getByLabelText("Effort"), {
      target: { value: "high" },
    });
    fireEvent.change(screen.getByLabelText("Context window"), {
      target: { value: "1000000" },
    });
    fireEvent.click(screen.getByRole("radio", { name: /Docker/i }));
    fireEvent.click(screen.getByRole("button", { name: "Save changes" }));

    await waitFor(() => {
      expect(
        recorded.find((call) => call.method === "POST" && call.url.endsWith("/setup")),
      ).toBeDefined();
    });
    const submit = recorded.find((call) => call.method === "POST" && call.url.endsWith("/setup"))!;
    expect(JSON.parse(submit.body!)).toEqual({
      ai_runtime: "claude-code",
      ai_model: "opus",
      ai_effort: "high",
      ai_context_window: 1000000,
      default_run_budget_usd_micros: null,
      sandbox_backend: "docker",
      i_own_this: true,
    });
  });

  it("saves Codex CLI as an all-in-one runtime without API keys", async () => {
    renderSettings();
    await waitForSettings();

    fireEvent.click(screen.getByRole("radio", { name: /Codex CLI/i }));
    fireEvent.click(screen.getByRole("button", { name: "Save changes" }));

    await waitFor(() => {
      expect(
        recorded.find((call) => call.method === "POST" && call.url.endsWith("/setup")),
      ).toBeDefined();
    });
    const submit = recorded.find((call) => call.method === "POST" && call.url.endsWith("/setup"))!;
    expect(JSON.parse(submit.body!)).toEqual({
      ai_runtime: "codex",
      ai_model: null,
      ai_effort: null,
      ai_context_window: null,
      default_run_budget_usd_micros: null,
      sandbox_backend: "auto",
      i_own_this: true,
    });
  });

  it("lets the operator enable and save an AI budget cap", async () => {
    renderSettings();
    await waitForSettings();

    fireEvent.click(screen.getByLabelText("Limit AI budget"));
    fireEvent.change(screen.getByLabelText("Budget per run (USD)"), {
      target: { value: "42.50" },
    });
    fireEvent.click(screen.getByRole("button", { name: "Save changes" }));

    const submit = await waitFor(() => {
      const call = recorded.find((call) => call.method === "POST" && call.url.endsWith("/setup"));
      expect(call).toBeDefined();
      return call!;
    });
    expect(JSON.parse(submit.body!)).toMatchObject({
      default_run_budget_usd_micros: 42_500_000,
    });
  });

  it("runs diagnostics from a standalone system checks section", async () => {
    statusPayload = {
      ...defaultStatus(),
      ai_runtime: "claude-code",
      ai_provider: "claude-code",
    };
    doctorPayload = {
      checks: [
        { name: "state-dir", passed: true, message: "state directory writable" },
        { name: "ai-claude-code", passed: true, message: "claude binary on PATH" },
        { name: "sandbox", passed: true, message: "Backend will be chosen at scan time" },
      ],
    };
    renderSettings();
    await waitForSettings();

    expect(screen.getByText("Checks")).toBeInTheDocument();
    expect(screen.getByText("No checks yet.")).toBeInTheDocument();

    fireEvent.click(screen.getByRole("button", { name: "Run checks" }));

    expect(await screen.findByText("ai-claude-code")).toBeInTheDocument();
    expect(screen.getByText("state directory writable")).toBeInTheDocument();
    await waitFor(() => {
      expect(
        recorded.find((call) => call.method === "POST" && call.url.endsWith("/setup/doctor")),
      ).toBeDefined();
    });
    const doctorCall = recorded.find(
      (call) => call.method === "POST" && call.url.endsWith("/setup/doctor"),
    )!;
    expect(JSON.parse(doctorCall.body!)).toEqual({
      ai_runtime: "claude-code",
      sandbox_backend: "auto",
    });
  });

  it("sends an unsaved Anthropic key to diagnostics without saving it", async () => {
    doctorPayload = {
      checks: [{ name: "ai-anthropic", passed: true, message: "provided for this check" }],
    };
    renderSettings();
    await waitForSettings();

    fireEvent.click(screen.getByRole("radio", { name: /Anthropic API/i }));
    fireEvent.change(screen.getByLabelText("Anthropic API key"), {
      target: { value: "sk-ant-test" },
    });
    fireEvent.click(screen.getByRole("button", { name: "Run checks" }));

    expect(await screen.findByText("ai-anthropic")).toBeInTheDocument();
    const doctorCall = await waitFor(() => {
      const call = recorded.find(
        (call) => call.method === "POST" && call.url.endsWith("/setup/doctor"),
      );
      expect(call).toBeDefined();
      return call!;
    });
    expect(JSON.parse(doctorCall.body!)).toEqual({
      ai_runtime: "anthropic",
      anthropic_api_key: "sk-ant-test",
      sandbox_backend: "auto",
    });
    expect(recorded.some((call) => call.method === "POST" && call.url.endsWith("/setup"))).toBe(
      false,
    );
  });

  it("requires a local LLM URL before saving that runtime", async () => {
    renderSettings();
    await waitForSettings();

    fireEvent.click(screen.getByRole("radio", { name: /Local OpenAI-compatible/i }));
    expect(screen.getByRole("button", { name: "Save changes" })).toBeDisabled();
    expect(
      screen.getByText("Enter a local OpenAI-compatible URL before saving."),
    ).toBeInTheDocument();

    fireEvent.change(screen.getByLabelText("OpenAI-compatible URL"), {
      target: { value: "http://127.0.0.1:1234/v1" },
    });
    fireEvent.click(screen.getByRole("button", { name: "Save changes" }));

    await waitFor(() => {
      expect(
        recorded.find((call) => call.method === "POST" && call.url.endsWith("/setup")),
      ).toBeDefined();
    });
    const submit = recorded.find((call) => call.method === "POST" && call.url.endsWith("/setup"))!;
    expect(JSON.parse(submit.body!)).toEqual({
      ai_runtime: "local-llm",
      default_run_budget_usd_micros: null,
      local_llm_url: "http://127.0.0.1:1234/v1",
      sandbox_backend: "auto",
      i_own_this: true,
    });
  });
});

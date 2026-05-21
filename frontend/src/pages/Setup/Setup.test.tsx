import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { SetupWizard } from "./index";

interface RecordedCall {
  url: string;
  method: string;
  body: string | null;
}

let recorded: RecordedCall[];
let doctorPayload: { checks: { name: string; passed: boolean; message: string }[] };

function renderWizard() {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={qc}>
      <MemoryRouter>
        <SetupWizard />
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

function attestAndContinue() {
  fireEvent.click(
    screen.getByLabelText(/I confirm that I own or am authorised to scan every repository/i),
  );
  fireEvent.click(screen.getByRole("button", { name: "Continue" }));
}

beforeEach(() => {
  recorded = [];
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
        return new Response(
          JSON.stringify({
            complete: false,
            config_path: "/tmp/nyctos.toml",
            ai_runtime: "none",
            sandbox_backend: "auto",
          }),
          { status: 200, headers: { "content-type": "application/json" } },
        );
      }
      if (url.endsWith("/setup/doctor")) {
        return new Response(JSON.stringify(doctorPayload), {
          status: 200,
          headers: { "content-type": "application/json" },
        });
      }
      if (url.endsWith("/setup") && method === "POST") {
        return new Response(JSON.stringify({ ok: true, config_path: "/tmp/nyctos.toml" }), {
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

describe("SetupWizard", () => {
  it("renders the three-step stepper and disables Continue until attestation is checked", async () => {
    renderWizard();
    expect(await screen.findByText("Welcome")).toBeInTheDocument();
    expect(screen.getByText("AI runtime")).toBeInTheDocument();
    expect(screen.getByText("Sandbox")).toBeInTheDocument();

    const cont = screen.getByRole("button", { name: "Continue" });
    expect(cont).toBeDisabled();

    fireEvent.click(
      screen.getByLabelText(/I confirm that I own or am authorised to scan every repository/i),
    );
    expect(cont).toBeEnabled();
  });

  it("renders the Anthropic API key field only when the anthropic runtime is picked, and gates Continue on a non-empty key", async () => {
    renderWizard();
    await screen.findByText("Welcome");
    attestAndContinue();
    await screen.findByText("Pick an AI runtime");

    // None selected by default: Continue is enabled.
    expect(screen.getByRole("button", { name: "Continue" })).toBeEnabled();
    expect(screen.queryByLabelText("Anthropic API key")).toBeNull();

    fireEvent.click(screen.getByRole("radio", { name: /Anthropic API/i }));
    const keyInput = await screen.findByLabelText("Anthropic API key");
    expect(keyInput).toBeInTheDocument();
    expect(keyInput).toHaveAttribute("type", "password");

    // Blank key blocks advance.
    expect(screen.getByRole("button", { name: "Continue" })).toBeDisabled();

    fireEvent.change(keyInput, { target: { value: "sk-ant-test" } });
    expect(screen.getByRole("button", { name: "Continue" })).toBeEnabled();
  });

  it("renders the local-llm URL + bearer token fields only when the local-llm runtime is picked, and gates Continue on a non-empty URL", async () => {
    renderWizard();
    await screen.findByText("Welcome");
    attestAndContinue();
    await screen.findByText("Pick an AI runtime");

    fireEvent.click(screen.getByRole("radio", { name: /Local OpenAI-compatible runtime/i }));
    const urlInput = await screen.findByLabelText("OpenAI-compatible URL");
    const tokenInput = screen.getByLabelText("Bearer token (optional)");
    expect(urlInput).toBeInTheDocument();
    expect(tokenInput).toHaveAttribute("type", "password");

    expect(screen.getByRole("button", { name: "Continue" })).toBeDisabled();

    fireEvent.change(urlInput, { target: { value: "http://127.0.0.1:1234/v1" } });
    expect(screen.getByRole("button", { name: "Continue" })).toBeEnabled();
  });

  it("renders each DoctorCheck shape (passed and failed) on the Sandbox step after Run checks", async () => {
    doctorPayload = {
      checks: [
        { name: "claude on PATH", passed: true, message: "/usr/local/bin/claude" },
        {
          name: "docker daemon",
          passed: false,
          message: "daemon not reachable on /var/run/docker.sock",
        },
      ],
    };
    renderWizard();
    await screen.findByText("Welcome");
    attestAndContinue();
    await screen.findByText("Pick an AI runtime");
    fireEvent.click(screen.getByRole("button", { name: "Continue" }));
    await screen.findByText("Pick a sandbox backend");

    expect(screen.queryByText("claude on PATH")).toBeNull();

    fireEvent.click(screen.getByRole("button", { name: "Run checks" }));

    const passedRow = await screen.findByText("claude on PATH");
    expect(passedRow.closest("li")).toHaveClass("setup-doctor__row");
    expect(passedRow.closest("li")?.className).toMatch(/\bok\b/);
    expect(screen.getByText("/usr/local/bin/claude")).toBeInTheDocument();

    const failedRow = screen.getByText("docker daemon");
    expect(failedRow.closest("li")?.className).toMatch(/\bfail\b/);
    expect(screen.getByText("daemon not reachable on /var/run/docker.sock")).toBeInTheDocument();
  });

  it("posts the expected body to /setup when Finish setup is clicked", async () => {
    renderWizard();
    await screen.findByText("Welcome");
    attestAndContinue();
    await screen.findByText("Pick an AI runtime");

    fireEvent.click(screen.getByRole("radio", { name: /Anthropic API/i }));
    fireEvent.change(await screen.findByLabelText("Anthropic API key"), {
      target: { value: "sk-ant-test" },
    });
    fireEvent.click(screen.getByRole("button", { name: "Continue" }));
    await screen.findByText("Pick a sandbox backend");

    fireEvent.click(screen.getByRole("radio", { name: /Birdcage \(macOS Seatbelt\)/i }));
    fireEvent.click(screen.getByRole("button", { name: "Finish setup" }));

    await waitFor(() => {
      expect(
        recorded.find((c) => c.method === "POST" && c.url.endsWith("/setup") && c.body !== null),
      ).toBeDefined();
    });
    const submit = recorded.find(
      (c) => c.method === "POST" && c.url.endsWith("/setup") && c.body !== null,
    )!;
    const payload = JSON.parse(submit.body!);
    expect(payload).toEqual({
      ai_runtime: "anthropic",
      anthropic_api_key: "sk-ant-test",
      sandbox_backend: "birdcage",
      i_own_this: true,
    });
  });
});

import { describe, it, expect, beforeEach, vi } from "vitest";
import { render, screen, fireEvent } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { SetupWizard } from "./index";

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

beforeEach(() => {
  vi.stubGlobal(
    "fetch",
    vi.fn(async (input: RequestInfo | URL) => {
      const url = typeof input === "string" ? input : input.toString();
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
      return new Response("{}", { status: 200 });
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
      screen.getByLabelText(
        /I confirm that I own or am authorised to scan every repository/i,
      ),
    );
    expect(cont).toBeEnabled();
  });
});

import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen } from "@testing-library/react";
import type { ReactNode } from "react";
import { MemoryRouter } from "react-router-dom";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { ProjectRecord } from "@/api/client";
import { AppLayout } from "./AppLayout";

function setAdvancedPref(value: "on" | "off") {
  if (value === "off") {
    window.localStorage.removeItem("nyx.advanced");
  } else {
    window.localStorage.setItem("nyx.advanced", "1");
  }
}

function jsonResponse(body: unknown, init: ResponseInit = { status: 200 }) {
  return new Response(JSON.stringify(body), {
    ...init,
    headers: { "content-type": "application/json", ...(init.headers ?? {}) },
  });
}

function renderLayout({
  route,
  setupComplete,
  projects = [],
  children = <span />,
}: {
  route: string;
  setupComplete?: boolean;
  projects?: ProjectRecord[];
  children?: ReactNode;
}) {
  vi.spyOn(globalThis, "fetch").mockImplementation(async (input) => {
    const url = typeof input === "string" ? input : (input as Request).url;
    if (url === "/api/v1/projects") return jsonResponse(projects);
    throw new Error(`unexpected url ${url}`);
  });
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={qc}>
      <MemoryRouter initialEntries={[route]}>
        <AppLayout setupComplete={setupComplete}>{children}</AppLayout>
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

describe("AppLayout", () => {
  beforeEach(() => {
    setAdvancedPref("off");
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  it("renders the brand, the post-setup nav links, and child content", () => {
    renderLayout({ route: "/projects", children: <div data-testid="child">child content</div> });

    expect(screen.getByRole("img", { name: "Nyctos" })).toBeInTheDocument();
    for (const label of ["Pentest Runs", "Vulnerabilities", "Settings"]) {
      expect(screen.getByRole("link", { name: new RegExp(label) })).toBeInTheDocument();
    }
    expect(screen.queryByRole("link", { name: /^Projects$/ })).toBeNull();
    expect(screen.queryByRole("link", { name: /Setup/ })).toBeNull();
    expect(screen.queryByRole("link", { name: /Legacy Findings/ })).toBeNull();
    expect(screen.queryByRole("link", { name: /Raw Chains/ })).toBeNull();
    expect(screen.queryByRole("link", { name: /Candidate Queue/ })).toBeNull();
    expect(screen.getByTestId("child")).toHaveTextContent("child content");
    expect(screen.queryByText("Daemon ready")).not.toBeInTheDocument();
  });

  it("keeps setup in navigation until first-launch setup is complete", () => {
    renderLayout({ route: "/setup", setupComplete: false });

    expect(screen.getByRole("link", { name: /Setup/ })).toBeInTheDocument();
  });

  it("labels run detail routes as a pentest run", () => {
    renderLayout({ route: "/runs/run-1" });

    expect(screen.getByText("Pentest Run")).toBeInTheDocument();
  });

  it("reveals debug surfaces when advanced mode is enabled", () => {
    setAdvancedPref("on");
    renderLayout({ route: "/projects" });
    expect(screen.getByRole("link", { name: /Legacy Findings/ })).toBeInTheDocument();
    expect(screen.getByRole("link", { name: /Raw Chains/ })).toBeInTheDocument();
    expect(screen.getByRole("link", { name: /Candidate Queue/ })).toBeInTheDocument();
  });

  it("highlights the current route", () => {
    renderLayout({ route: "/vulnerabilities" });
    const vulnerabilities = screen.getByRole("link", { name: /Vulnerabilities/ });
    expect(vulnerabilities.getAttribute("aria-current")).toBe("page");
  });

  it("switches to project-scoped navigation inside a project", async () => {
    renderLayout({
      route: "/projects/project-1/vulnerabilities",
      projects: [
        {
          id: "project-1",
          name: "calcom",
          description: null,
          target_base_url: null,
          env_config_json: null,
          runtime_profile: null,
          default_launch_profile: null,
          created_at: 1,
          updated_at: 1,
        },
      ],
    });

    expect(await screen.findByRole("combobox", { name: "Switch project" })).toHaveValue(
      "project-1",
    );
    expect(screen.getByRole("link", { name: /Overview/ })).toHaveAttribute(
      "href",
      "/projects/project-1",
    );
    expect(screen.getByRole("link", { name: /Pentest Runs/ })).toHaveAttribute(
      "href",
      "/projects/project-1/runs",
    );
    expect(screen.getByRole("link", { name: /Repositories/ })).toHaveAttribute(
      "href",
      "/projects/project-1/repos",
    );
    expect(screen.getByRole("link", { name: /Environments/ })).toHaveAttribute(
      "href",
      "/projects/project-1/environments",
    );
    expect(screen.getByRole("link", { name: /Vulnerabilities/ })).toHaveAttribute(
      "aria-current",
      "page",
    );
  });
});

import { render, screen } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { beforeEach, describe, expect, it } from "vitest";
import { AppLayout } from "./AppLayout";

function setAdvancedPref(value: "on" | "off") {
  if (value === "off") {
    window.localStorage.removeItem("nyx.advanced");
  } else {
    window.localStorage.setItem("nyx.advanced", "1");
  }
}

describe("AppLayout", () => {
  beforeEach(() => {
    setAdvancedPref("off");
  });

  it("renders the brand, the post-setup nav links, and child content", () => {
    render(
      <MemoryRouter initialEntries={["/projects"]}>
        <AppLayout>
          <div data-testid="child">child content</div>
        </AppLayout>
      </MemoryRouter>,
    );

    expect(screen.getByRole("img", { name: "Nyx" })).toBeInTheDocument();
    for (const label of ["Projects", "Pentest Runs", "Vulnerabilities", "Settings"]) {
      expect(screen.getByRole("link", { name: new RegExp(label) })).toBeInTheDocument();
    }
    expect(screen.queryByRole("link", { name: /Setup/ })).toBeNull();
    expect(screen.queryByRole("link", { name: /Legacy Findings/ })).toBeNull();
    expect(screen.queryByRole("link", { name: /Raw Chains/ })).toBeNull();
    expect(screen.queryByRole("link", { name: /Candidate Queue/ })).toBeNull();
    expect(screen.getByTestId("child")).toHaveTextContent("child content");
    expect(screen.getByText("Daemon ready")).toBeInTheDocument();
  });

  it("keeps setup in navigation until first-launch setup is complete", () => {
    render(
      <MemoryRouter initialEntries={["/setup"]}>
        <AppLayout setupComplete={false}>
          <span />
        </AppLayout>
      </MemoryRouter>,
    );

    expect(screen.getByRole("link", { name: /Setup/ })).toBeInTheDocument();
  });

  it("reveals debug surfaces when advanced mode is enabled", () => {
    setAdvancedPref("on");
    render(
      <MemoryRouter initialEntries={["/projects"]}>
        <AppLayout>
          <span />
        </AppLayout>
      </MemoryRouter>,
    );
    expect(screen.getByRole("link", { name: /Legacy Findings/ })).toBeInTheDocument();
    expect(screen.getByRole("link", { name: /Raw Chains/ })).toBeInTheDocument();
    expect(screen.getByRole("link", { name: /Candidate Queue/ })).toBeInTheDocument();
  });

  it("highlights the current route", () => {
    render(
      <MemoryRouter initialEntries={["/vulnerabilities"]}>
        <AppLayout>
          <span />
        </AppLayout>
      </MemoryRouter>,
    );
    const vulnerabilities = screen.getByRole("link", { name: /Vulnerabilities/ });
    expect(vulnerabilities.getAttribute("aria-current")).toBe("page");
  });
});

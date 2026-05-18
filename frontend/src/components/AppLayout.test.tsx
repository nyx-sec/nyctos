import { beforeEach, describe, expect, it } from "vitest";
import { render, screen } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
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

  it("renders the brand, the default nav links, and child content", () => {
    render(
      <MemoryRouter initialEntries={["/projects"]}>
        <AppLayout>
          <div data-testid="child">child content</div>
        </AppLayout>
      </MemoryRouter>,
    );

    expect(screen.getByRole("img", { name: "Nyx" })).toBeInTheDocument();
    for (const label of ["Setup", "Projects", "Runs", "Findings", "Chains", "Settings"]) {
      expect(screen.getByRole("link", { name: new RegExp(label) })).toBeInTheDocument();
    }
    // Phase 24: Quarantine is hidden until Settings → Show advanced is on.
    expect(screen.queryByRole("link", { name: /Quarantine/ })).toBeNull();
    expect(screen.getByTestId("child")).toHaveTextContent("child content");
    expect(screen.getByText("Daemon ready")).toBeInTheDocument();
  });

  it("reveals Quarantine when advanced mode is enabled", () => {
    setAdvancedPref("on");
    render(
      <MemoryRouter initialEntries={["/projects"]}>
        <AppLayout>
          <span />
        </AppLayout>
      </MemoryRouter>,
    );
    expect(screen.getByRole("link", { name: /Quarantine/ })).toBeInTheDocument();
  });

  it("highlights the current route", () => {
    render(
      <MemoryRouter initialEntries={["/findings"]}>
        <AppLayout>
          <span />
        </AppLayout>
      </MemoryRouter>,
    );
    const findings = screen.getByRole("link", { name: /Findings/ });
    expect(findings.getAttribute("aria-current")).toBe("page");
  });
});

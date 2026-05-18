import { describe, expect, it } from "vitest";
import { render, screen } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { AppLayout } from "./AppLayout";

describe("AppLayout", () => {
  it("renders the brand, every nav link, and child content", () => {
    render(
      <MemoryRouter initialEntries={["/repos"]}>
        <AppLayout>
          <div data-testid="child">child content</div>
        </AppLayout>
      </MemoryRouter>,
    );

    expect(screen.getByRole("img", { name: "Nyx" })).toBeInTheDocument();
    for (const label of [
      "Setup",
      "Repos",
      "Runs",
      "Findings",
      "Chains",
      "Quarantine",
      "Settings",
    ]) {
      expect(screen.getByRole("link", { name: new RegExp(label) })).toBeInTheDocument();
    }
    expect(screen.getByTestId("child")).toHaveTextContent("child content");
    expect(screen.getByText("Daemon ready")).toBeInTheDocument();
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

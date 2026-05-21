import { describe, expect, it } from "vitest";
import { render, screen } from "@testing-library/react";

import { Badge } from "./Badge";
import { Button } from "./Button";
import { Card } from "./Card";
import { CodeExcerpt } from "./CodeExcerpt";
import { EmptyState } from "./EmptyState";
import { Spinner } from "./Spinner";

describe("Button", () => {
  it("defaults to type=button so it never submits an enclosing form", () => {
    render(<Button>save</Button>);
    const btn = screen.getByRole("button", { name: "save" });
    expect(btn).toHaveAttribute("type", "button");
    expect(btn.className.split(" ")).toEqual(["btn"]);
  });

  it("merges variant + size + caller className without dropping any", () => {
    render(
      <Button variant="danger" size="sm" className="row-action">
        delete
      </Button>,
    );
    const btn = screen.getByRole("button", { name: "delete" });
    expect(btn.className.split(" ").sort()).toEqual(
      ["btn", "btn--danger", "btn--sm", "row-action"].sort(),
    );
  });

  it("honours an explicit type override", () => {
    render(<Button type="submit">go</Button>);
    expect(screen.getByRole("button", { name: "go" })).toHaveAttribute("type", "submit");
  });
});

describe("Card", () => {
  it("omits the header chrome when no title / subtitle / actions are supplied", () => {
    render(
      <Card>
        <p data-testid="body">body</p>
      </Card>,
    );
    expect(screen.getByTestId("body")).toBeInTheDocument();
    // The header chrome's heading is the only h2 the component ever emits.
    expect(screen.queryByRole("heading", { level: 2 })).toBeNull();
  });

  it("renders title, subtitle, and actions in the header when provided", () => {
    render(
      <Card
        title="Latest run"
        subtitle="finished 1m ago"
        actions={<button type="button">Rerun</button>}
      >
        <div>body</div>
      </Card>,
    );
    expect(screen.getByRole("heading", { level: 2, name: "Latest run" })).toBeInTheDocument();
    expect(screen.getByText("finished 1m ago")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Rerun" })).toBeInTheDocument();
    expect(screen.getByText("body")).toBeInTheDocument();
  });
});

describe("Badge", () => {
  it("defaults to the neutral tone (no tone class)", () => {
    render(<Badge>new</Badge>);
    const badge = screen.getByText("new");
    expect(badge.className).toBe("badge");
  });

  it("maps each tone to its modifier class", () => {
    const tones = ["success", "warning", "danger", "info", "accent"] as const;
    for (const tone of tones) {
      render(<Badge tone={tone}>{tone}</Badge>);
      expect(screen.getByText(tone).className.split(" ")).toContain(`badge--${tone}`);
    }
  });
});

describe("CodeExcerpt", () => {
  it("renders one row per line and flags the highlight modifier", () => {
    render(
      <CodeExcerpt
        lines={[
          { lineno: 12, code: "const x = 1;" },
          { lineno: 13, code: "// pwned", highlight: true },
        ]}
      />,
    );
    expect(screen.getByText("12")).toBeInTheDocument();
    expect(screen.getByText("const x = 1;")).toBeInTheDocument();
    const highlightedCode = screen.getByText("// pwned");
    const row = highlightedCode.closest(".code-excerpt__line");
    expect(row?.className).toContain("code-excerpt__line--highlight");
  });
});

describe("EmptyState", () => {
  it("renders title and optional body + actions", () => {
    render(
      <EmptyState
        title="No findings yet"
        body="Trigger a scan to see results."
        actions={<button type="button">Scan now</button>}
      />,
    );
    expect(
      screen.getByRole("heading", { level: 3, name: "No findings yet" }),
    ).toBeInTheDocument();
    expect(screen.getByText("Trigger a scan to see results.")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Scan now" })).toBeInTheDocument();
  });
});

describe("Spinner", () => {
  it("renders a role=status node with a default aria-label", () => {
    render(<Spinner />);
    const spinner = screen.getByRole("status");
    expect(spinner).toHaveAttribute("aria-label", "Loading");
    expect(spinner.className).toBe("spinner");
  });

  it("applies the lg modifier and honours a custom label", () => {
    render(<Spinner size="lg" label="Replaying" />);
    const spinner = screen.getByRole("status");
    expect(spinner).toHaveAttribute("aria-label", "Replaying");
    expect(spinner.className.split(" ")).toContain("spinner--lg");
  });
});

import { fireEvent, render, screen } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { Settings } from "./Settings";

describe("Settings page", () => {
  beforeEach(() => {
    window.localStorage.clear();
  });
  afterEach(() => {
    window.localStorage.clear();
  });

  it("renders Off when the advanced preference is unset", () => {
    render(<Settings />);
    const toggle = screen.getByLabelText("Show advanced UI") as HTMLInputElement;
    expect(toggle.checked).toBe(false);
    expect(screen.getByText("Off")).toBeInTheDocument();
  });

  it("renders On when localStorage carries the opt-in", () => {
    window.localStorage.setItem("nyx.advanced", "1");
    render(<Settings />);
    const toggle = screen.getByLabelText("Show advanced UI") as HTMLInputElement;
    expect(toggle.checked).toBe(true);
    expect(screen.getByText("On")).toBeInTheDocument();
  });

  it("flips the toggle and persists the new value to localStorage", () => {
    render(<Settings />);
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
});

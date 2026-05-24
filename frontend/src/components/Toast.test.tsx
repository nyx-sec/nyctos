import { act, fireEvent, render, screen } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { ToastProvider, useToast } from "./Toast";

function ToastHarness() {
  const { showToast } = useToast();
  return (
    <button
      type="button"
      onClick={() => showToast("Saved environment.", { tone: "success", durationMs: 1_000 })}
    >
      Notify
    </button>
  );
}

describe("ToastProvider", () => {
  afterEach(() => {
    vi.useRealTimers();
  });

  it("auto-dismisses notifications after their duration", async () => {
    vi.useFakeTimers();
    render(
      <ToastProvider>
        <ToastHarness />
      </ToastProvider>,
    );

    fireEvent.click(screen.getByRole("button", { name: "Notify" }));

    expect(screen.getByRole("status")).toHaveTextContent("Saved environment.");

    act(() => {
      vi.advanceTimersByTime(1_000);
    });

    expect(screen.queryByText("Saved environment.")).not.toBeInTheDocument();
  });

  it("lets operators dismiss notifications immediately", async () => {
    render(
      <ToastProvider>
        <ToastHarness />
      </ToastProvider>,
    );

    fireEvent.click(screen.getByRole("button", { name: "Notify" }));
    expect(await screen.findByText("Saved environment.")).toBeInTheDocument();

    fireEvent.click(screen.getByRole("button", { name: "Dismiss notification" }));

    expect(screen.queryByText("Saved environment.")).not.toBeInTheDocument();
  });
});

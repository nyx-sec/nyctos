import { fireEvent, render, screen } from "@testing-library/react";
import { beforeEach, describe, expect, it } from "vitest";
import { COMMUNITY_EDITION_NOTICE, CommunityEditionNotice } from "./CommunityEditionNotice";

describe("CommunityEditionNotice", () => {
  beforeEach(() => {
    window.localStorage.clear();
  });

  it("shows the community license notice on initial launch", () => {
    render(<CommunityEditionNotice />);

    expect(screen.getByRole("dialog", { name: "Community Edition" })).toBeInTheDocument();
    expect(screen.getByText(/AGPLv3-or-later/i)).toBeInTheDocument();
    expect(screen.getByText(/paid support/i)).toBeInTheDocument();
    expect(COMMUNITY_EDITION_NOTICE).toContain("nyctos.dev/pricing");
    expect(screen.getByRole("link", { name: "nyctos.dev/pricing" })).toHaveAttribute(
      "href",
      "https://nyctos.dev/pricing",
    );
  });

  it("stays dismissed after the operator acknowledges it", () => {
    const { rerender } = render(<CommunityEditionNotice />);

    fireEvent.click(screen.getByRole("button", { name: "Got it" }));
    expect(screen.queryByRole("dialog", { name: "Community Edition" })).not.toBeInTheDocument();

    rerender(<CommunityEditionNotice />);
    expect(screen.queryByRole("dialog", { name: "Community Edition" })).not.toBeInTheDocument();
  });
});

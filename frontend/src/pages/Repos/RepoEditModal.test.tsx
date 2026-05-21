import { describe, expect, it } from "vitest";
import { buildPatch } from "./RepoEditModal";

const baseInitial = {
  source_url_or_path: "https://github.com/org/billing.git",
  branch: "main",
  auth_ref: "token-env:GH_TOKEN",
};

describe("RepoEditModal.buildPatch", () => {
  it("returns null when no field differs from the initial values", () => {
    const out = buildPatch({
      tab: "url",
      initialKind: "git",
      initial: baseInitial,
      next: { ...baseInitial },
    });
    expect(out).toBeNull();
  });

  it("trims and forwards source_url_or_path changes", () => {
    const out = buildPatch({
      tab: "url",
      initialKind: "git",
      initial: baseInitial,
      next: {
        ...baseInitial,
        source_url_or_path: "  https://github.com/org/billing-v2.git  ",
      },
    });
    expect(out).toEqual({
      source_url_or_path: "https://github.com/org/billing-v2.git",
    });
  });

  it("emits null for branch when the operator clears it", () => {
    const out = buildPatch({
      tab: "url",
      initialKind: "git",
      initial: baseInitial,
      next: { ...baseInitial, branch: "" },
    });
    expect(out).toEqual({ branch: null });
  });

  it("emits a string for branch when set on a previously empty value", () => {
    const out = buildPatch({
      tab: "url",
      initialKind: "git",
      initial: { ...baseInitial, branch: "" },
      next: { ...baseInitial, branch: "release/2026" },
    });
    expect(out).toEqual({ branch: "release/2026" });
  });

  it("emits null for auth_ref when cleared and a string when changed", () => {
    expect(
      buildPatch({
        tab: "url",
        initialKind: "git",
        initial: baseInitial,
        next: { ...baseInitial, auth_ref: "" },
      }),
    ).toEqual({ auth_ref: null });
    expect(
      buildPatch({
        tab: "url",
        initialKind: "git",
        initial: baseInitial,
        next: { ...baseInitial, auth_ref: "ssh-key:/home/me/.ssh/id" },
      }),
    ).toEqual({ auth_ref: "ssh-key:/home/me/.ssh/id" });
  });

  it("switches source_kind when the tab flips and clears auth_ref on local-path", () => {
    const out = buildPatch({
      tab: "path",
      initialKind: "git",
      initial: baseInitial,
      next: {
        source_url_or_path: "/Users/me/code/billing",
        branch: "main",
        auth_ref: "token-env:GH_TOKEN",
      },
    });
    expect(out).toEqual({
      source_kind: "local-path",
      source_url_or_path: "/Users/me/code/billing",
      auth_ref: null,
    });
  });

  it("does not stamp source_kind when the tab matches the initial kind", () => {
    const out = buildPatch({
      tab: "path",
      initialKind: "local-path",
      initial: {
        source_url_or_path: "/Users/me/code/billing",
        branch: "",
        auth_ref: "",
      },
      next: {
        source_url_or_path: "/Users/me/code/billing-v2",
        branch: "",
        auth_ref: "",
      },
    });
    expect(out).toEqual({ source_url_or_path: "/Users/me/code/billing-v2" });
  });
});

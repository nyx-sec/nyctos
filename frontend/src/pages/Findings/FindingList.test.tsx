import { describe, expect, it } from "vitest";
import type { ChainRecord } from "@/api/client";
import { buildChainSummaryIndex, chainLabelFor, extractChainRationale } from "./FindingList";

function makeChain(overrides: Partial<ChainRecord> = {}): ChainRecord {
  return {
    id: "chain-abc",
    run_id: "run-1",
    cross_repo: false,
    member_ids: "[]",
    rationale_blob: null,
    attack_provenance: null,
    prompt_version: null,
    ...overrides,
  };
}

describe("FindingList chain summary helpers", () => {
  it("extractChainRationale parses {rationale: ...} envelope", () => {
    expect(extractChainRationale('{"rationale":"controller reaches sink"}')).toBe(
      "controller reaches sink",
    );
  });

  it("extractChainRationale falls back to the raw blob when the envelope is unexpected", () => {
    expect(extractChainRationale("plain text")).toBe("plain text");
  });

  it("extractChainRationale returns null for empty / nullish input", () => {
    expect(extractChainRationale(null)).toBeNull();
    expect(extractChainRationale("")).toBeNull();
  });

  it("buildChainSummaryIndex keys by chain id and surfaces cross_repo", () => {
    const chains = [
      makeChain({
        id: "chain-xrep",
        cross_repo: true,
        rationale_blob: '{"rationale":"x-repo flow"}',
      }),
      makeChain({ id: "chain-flat", rationale_blob: null }),
    ];
    const index = buildChainSummaryIndex(chains);
    expect(index.get("chain-xrep")).toEqual({
      rationale: "x-repo flow",
      crossRepo: true,
    });
    expect(index.get("chain-flat")).toEqual({
      rationale: null,
      crossRepo: false,
    });
  });

  it("chainLabelFor falls back to a shortened id when no summary is loaded", () => {
    expect(chainLabelFor("chain-abcdef0123456789", undefined)).toBe("Chain abcdef012345…");
  });

  it("chainLabelFor appends a cross-repo tag and the rationale preview when available", () => {
    expect(
      chainLabelFor("chain-abcd", {
        rationale: "controller in repo-a reaches sink in repo-b",
        crossRepo: true,
      }),
    ).toBe("Chain abcd (cross-repo) — controller in repo-a reaches sink in repo-b");
  });

  it("chainLabelFor truncates a long rationale to the preview window", () => {
    const long = "x".repeat(200);
    const label = chainLabelFor("chain-abcd", {
      rationale: long,
      crossRepo: false,
    });
    expect(label.startsWith("Chain abcd — ")).toBe(true);
    expect(label.endsWith("…")).toBe(true);
    expect(label.length).toBeLessThan(200);
  });
});

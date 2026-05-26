/**
 * `ChainRecord.member_ids` is persisted as a JSON-serialised string
 * array on the wire (see `crates/nyctos/src/ai_pipeline.rs::apply_chain_outcome`).
 * Parse it defensively: when the blob is malformed or non-array, return
 * an empty list rather than throwing; the chain detail page renders an
 * empty-state in that case.
 */
export function parseMemberIds(blob: string | null | undefined): string[] {
  if (!blob) return [];
  let parsed: unknown;
  try {
    parsed = JSON.parse(blob);
  } catch {
    return [];
  }
  if (!Array.isArray(parsed)) return [];
  return parsed.filter((v): v is string => typeof v === "string");
}

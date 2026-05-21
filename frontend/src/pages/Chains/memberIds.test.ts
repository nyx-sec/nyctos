import { describe, expect, it } from "vitest";
import { parseMemberIds } from "./memberIds";

describe("parseMemberIds", () => {
  it("parses a JSON string array verbatim", () => {
    expect(parseMemberIds('["f-a","f-b","f-c"]')).toEqual(["f-a", "f-b", "f-c"]);
  });

  it("returns an empty array for null / empty input", () => {
    expect(parseMemberIds(null)).toEqual([]);
    expect(parseMemberIds("")).toEqual([]);
    expect(parseMemberIds(undefined)).toEqual([]);
  });

  it("returns an empty array for malformed JSON", () => {
    expect(parseMemberIds("{not-json")).toEqual([]);
  });

  it("returns an empty array when the blob is not an array", () => {
    expect(parseMemberIds('{"foo":"bar"}')).toEqual([]);
    expect(parseMemberIds('"single-string"')).toEqual([]);
    expect(parseMemberIds("42")).toEqual([]);
  });

  it("filters out non-string entries from a mixed array", () => {
    expect(parseMemberIds('["f-a",42,null,"f-b"]')).toEqual(["f-a", "f-b"]);
  });
});

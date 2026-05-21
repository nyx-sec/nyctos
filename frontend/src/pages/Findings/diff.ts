import type { FindingDiffStatus } from "@/api/client";
import type { BadgeTone } from "@/components/Badge";

export const DIFF_TONE: Record<FindingDiffStatus, BadgeTone> = {
  new: "info",
  regressed: "warning",
  closed: "neutral",
  unchanged: "neutral",
};

export const DIFF_LABEL: Record<FindingDiffStatus, string> = {
  new: "new",
  regressed: "regressed",
  closed: "closed",
  unchanged: "-",
};

export const SEVERITY_TONE: Record<string, BadgeTone> = {
  Critical: "danger",
  High: "danger",
  Medium: "warning",
  Low: "neutral",
  Info: "neutral",
};

export const STATUS_TONE: Record<string, BadgeTone> = {
  Open: "info",
  Verified: "danger",
  Quarantine: "neutral",
  Closed: "neutral",
};

export const ORIGIN_TONE: Record<string, BadgeTone> = {
  Static: "accent",
  AI: "info",
  Manual: "neutral",
};

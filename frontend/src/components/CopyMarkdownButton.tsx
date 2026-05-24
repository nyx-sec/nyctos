import { useCallback, useEffect, useRef, useState } from "react";
import type { MouseEvent } from "react";

type CopyStatus = "idle" | "working" | "copied" | "failed";

export interface CopyMarkdownButtonProps {
  getMarkdown: () => string | Promise<string>;
  label?: string;
  className?: string;
  title?: string;
  stopPropagation?: boolean;
  iconOnly?: boolean;
}

const RESET_MS = 1600;

function CopyIcon() {
  return (
    <svg viewBox="0 0 18 18" aria-hidden="true">
      <rect x="6.5" y="6.5" width="8" height="8" rx="1.4" />
      <path d="M11.5 6.5V4.8c0-.8-.6-1.4-1.4-1.4H4.8c-.8 0-1.4.6-1.4 1.4v5.3c0 .8.6 1.4 1.4 1.4h1.7" />
    </svg>
  );
}

function CheckIcon() {
  return (
    <svg viewBox="0 0 18 18" aria-hidden="true">
      <path d="m3.5 9.3 3.2 3.2 7.8-8" />
    </svg>
  );
}

function FailIcon() {
  return (
    <svg viewBox="0 0 18 18" aria-hidden="true">
      <path d="m5 5 8 8" />
      <path d="m13 5-8 8" />
    </svg>
  );
}

export function CopyMarkdownButton({
  getMarkdown,
  label = "Copy",
  className,
  title,
  stopPropagation,
  iconOnly,
}: CopyMarkdownButtonProps) {
  const [status, setStatus] = useState<CopyStatus>("idle");
  const timeoutRef = useRef<number | null>(null);

  useEffect(() => {
    return () => {
      if (timeoutRef.current !== null) {
        window.clearTimeout(timeoutRef.current);
      }
    };
  }, []);

  const resetLater = useCallback(() => {
    if (timeoutRef.current !== null) {
      window.clearTimeout(timeoutRef.current);
    }
    timeoutRef.current = window.setTimeout(() => {
      setStatus("idle");
      timeoutRef.current = null;
    }, RESET_MS);
  }, []);

  const onClick = useCallback(
    async (event: MouseEvent<HTMLButtonElement>) => {
      if (stopPropagation) event.stopPropagation();
      if (status === "working") return;
      if (!navigator.clipboard?.writeText) {
        setStatus("failed");
        resetLater();
        return;
      }
      setStatus("working");
      try {
        await navigator.clipboard.writeText(await getMarkdown());
        setStatus("copied");
      } catch {
        setStatus("failed");
      }
      resetLater();
    },
    [getMarkdown, resetLater, status, stopPropagation],
  );

  const display =
    status === "working"
      ? "Copying..."
      : status === "copied"
        ? "Copied"
        : status === "failed"
          ? "Copy failed"
          : label;
  const classes = [
    "copy-markdown-button",
    iconOnly ? "copy-markdown-button--icon" : "",
    `copy-markdown-button--${status}`,
    className ?? "",
  ]
    .filter(Boolean)
    .join(" ");

  return (
    <button
      type="button"
      className={classes}
      title={title ?? display}
      aria-label={iconOnly ? display : undefined}
      disabled={status === "working"}
      onClick={onClick}
    >
      {status === "copied" ? <CheckIcon /> : status === "failed" ? <FailIcon /> : <CopyIcon />}
      {!iconOnly && <span>{display}</span>}
    </button>
  );
}

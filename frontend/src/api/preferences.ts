/**
 * Operator UI preferences persisted to `localStorage`.
 */

import { useCallback, useEffect, useState } from "react";

const KEY = "nyx.advanced";

/**
 * Read the persisted "show advanced" preference. The default is
 * `false`; only operators who explicitly opt in see raw/debug
 * surfaces such as Quarantine.
 */
function readAdvanced(): boolean {
  if (typeof window === "undefined") return false;
  try {
    return window.localStorage.getItem(KEY) === "1";
  } catch {
    return false;
  }
}

function writeAdvanced(value: boolean): void {
  if (typeof window === "undefined") return;
  try {
    window.localStorage.setItem(KEY, value ? "1" : "0");
    // Broadcast within the tab so peer hooks pick up the change
    // without waiting for a `storage` event (which only fires
    // cross-tab).
    window.dispatchEvent(new CustomEvent("nyx-prefs-changed"));
  } catch {
    // localStorage may be disabled (private mode / sandboxed iframe);
    // the in-memory state still reflects the change.
  }
}

export function useAdvancedMode(): [boolean, (next: boolean) => void] {
  const [enabled, setEnabled] = useState<boolean>(() => readAdvanced());

  useEffect(() => {
    const reload = () => setEnabled(readAdvanced());
    window.addEventListener("nyx-prefs-changed", reload);
    window.addEventListener("storage", reload);
    return () => {
      window.removeEventListener("nyx-prefs-changed", reload);
      window.removeEventListener("storage", reload);
    };
  }, []);

  const update = useCallback((next: boolean) => {
    writeAdvanced(next);
    setEnabled(next);
  }, []);

  return [enabled, update];
}

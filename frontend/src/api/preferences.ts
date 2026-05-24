/**
 * Operator UI preferences persisted to `localStorage`.
 */

import { useCallback, useEffect, useState } from "react";

const ADVANCED_KEY = "nyx.advanced";
const ACTIVE_PROJECT_KEY = "nyx.active_project_id";
const PREFS_CHANGED_EVENT = "nyx-prefs-changed";

/**
 * Read the persisted "show advanced" preference. The default is
 * `false`; only operators who explicitly opt in see raw/debug
 * surfaces such as Quarantine.
 */
function readAdvanced(): boolean {
  if (typeof window === "undefined") return false;
  try {
    return window.localStorage.getItem(ADVANCED_KEY) === "1";
  } catch {
    return false;
  }
}

function writeAdvanced(value: boolean): void {
  if (typeof window === "undefined") return;
  try {
    window.localStorage.setItem(ADVANCED_KEY, value ? "1" : "0");
    broadcastPrefsChanged();
  } catch {
    // localStorage may be disabled (private mode / sandboxed iframe);
    // the in-memory state still reflects the change.
  }
}

export function useAdvancedMode(): [boolean, (next: boolean) => void] {
  const [enabled, setEnabled] = useState<boolean>(() => readAdvanced());

  useEffect(() => {
    const reload = () => setEnabled(readAdvanced());
    window.addEventListener(PREFS_CHANGED_EVENT, reload);
    window.addEventListener("storage", reload);
    return () => {
      window.removeEventListener(PREFS_CHANGED_EVENT, reload);
      window.removeEventListener("storage", reload);
    };
  }, []);

  const update = useCallback((next: boolean) => {
    writeAdvanced(next);
    setEnabled(next);
  }, []);

  return [enabled, update];
}

function readActiveProjectId(): string | undefined {
  if (typeof window === "undefined") return undefined;
  try {
    return window.localStorage.getItem(ACTIVE_PROJECT_KEY) ?? undefined;
  } catch {
    return undefined;
  }
}

function writeActiveProjectId(projectId: string | undefined): void {
  if (typeof window === "undefined") return;
  try {
    if (projectId) {
      window.localStorage.setItem(ACTIVE_PROJECT_KEY, projectId);
    } else {
      window.localStorage.removeItem(ACTIVE_PROJECT_KEY);
    }
    broadcastPrefsChanged();
  } catch {
    // localStorage may be unavailable; callers still update in-memory state.
  }
}

function broadcastPrefsChanged(): void {
  if (typeof window === "undefined") return;
  // Broadcast within the tab so peer hooks pick up the change without
  // waiting for a `storage` event, which only fires cross-tab.
  window.dispatchEvent(new CustomEvent(PREFS_CHANGED_EVENT));
}

export function useActiveProjectPreference(): [
  string | undefined,
  (next: string | undefined) => void,
] {
  const [projectId, setProjectId] = useState<string | undefined>(() => readActiveProjectId());

  useEffect(() => {
    const reload = () => setProjectId(readActiveProjectId());
    window.addEventListener(PREFS_CHANGED_EVENT, reload);
    window.addEventListener("storage", reload);
    return () => {
      window.removeEventListener(PREFS_CHANGED_EVENT, reload);
      window.removeEventListener("storage", reload);
    };
  }, []);

  const update = useCallback((next: string | undefined) => {
    writeActiveProjectId(next);
    setProjectId(next);
  }, []);

  return [projectId, update];
}

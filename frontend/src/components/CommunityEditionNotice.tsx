import { useEffect, useState } from "react";
import { Button } from "@/components/Button";

const STORAGE_KEY = "nyctos.communityEditionNoticeDismissed";

export const COMMUNITY_EDITION_NOTICE =
  "You are using Nyctos Community Edition under AGPLv3-or-later. Commercial licenses, paid support, and enterprise terms are available at nyctos.dev/pricing.";
const NOTICE_PREFIX =
  "You are using Nyctos Community Edition under AGPLv3-or-later. Commercial licenses, paid support, and enterprise terms are available at";

function noticeWasDismissed(): boolean {
  try {
    return window.localStorage.getItem(STORAGE_KEY) === "1";
  } catch {
    return false;
  }
}

function rememberDismissal() {
  try {
    window.localStorage.setItem(STORAGE_KEY, "1");
  } catch {
    // Storage can be unavailable in hardened browser contexts.
  }
}

export function CommunityEditionNotice() {
  const [open, setOpen] = useState(() => !noticeWasDismissed());

  useEffect(() => {
    if (!open) return;

    function onKey(e: KeyboardEvent) {
      if (e.key === "Escape") close();
    }

    document.addEventListener("keydown", onKey);
    return () => document.removeEventListener("keydown", onKey);
  }, [open]);

  if (!open) return null;

  function close() {
    rememberDismissal();
    setOpen(false);
  }

  return (
    <div
      className="modal-backdrop community-edition-notice__backdrop"
      role="dialog"
      aria-modal="true"
      aria-labelledby="community-edition-notice-title"
      onClick={(e) => {
        if (e.target === e.currentTarget) close();
      }}
    >
      <div className="modal community-edition-notice">
        <header className="modal__header community-edition-notice__header">
          <h2 id="community-edition-notice-title" className="modal__title">
            Community Edition
          </h2>
          <button type="button" className="modal__close" aria-label="Close" onClick={close}>
            ×
          </button>
        </header>
        <div className="modal__body community-edition-notice__body">
          <p>
            {NOTICE_PREFIX}{" "}
            <a href="https://nyctos.dev/pricing" target="_blank" rel="noreferrer">
              nyctos.dev/pricing
            </a>
            .
          </p>
        </div>
        <footer className="modal__footer">
          <Button type="button" variant="danger" onClick={close}>
            Got it
          </Button>
        </footer>
      </div>
    </div>
  );
}

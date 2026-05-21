import { useAdvancedMode } from "@/api/preferences";
import { Card } from "@/components/Card";

/**
 * Operator settings surface. Phase 24 ships a single "Show advanced"
 * toggle that controls whether the Quarantine page and other Phase
 * 24+ advanced affordances appear in the sidebar. Further per-tab
 * settings (token rotation, pricing, sandbox tuning) land in later
 * phases.
 */
export function Settings() {
  const [advanced, setAdvanced] = useAdvancedMode();

  return (
    <div className="settings-page">
      <Card>
        <section className="settings-page__section">
          <header className="settings-page__row">
            <div>
              <h3 className="settings-page__row-title">Show advanced</h3>
              <p className="settings-page__row-help">
                Reveals Quarantine and other advanced surfaces in the sidebar. Quarantine holds
                findings that need manual confirmation before they move into Findings.
              </p>
            </div>
            <label className="settings-page__toggle">
              <input
                type="checkbox"
                checked={advanced}
                onChange={(e) => setAdvanced(e.target.checked)}
                aria-label="Show advanced UI"
              />
              <span>{advanced ? "On" : "Off"}</span>
            </label>
          </header>
        </section>
      </Card>
    </div>
  );
}

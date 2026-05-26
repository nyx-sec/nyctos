import { SetupFormState } from "./index";

interface Props {
  form: SetupFormState;
  update: (patch: Partial<SetupFormState>) => void;
}

export function WelcomeStep({ form, update }: Props) {
  return (
    <div className="setup-step__body">
      <h3>Welcome to Nyx Agent</h3>
      <p>
        Nyx Agent runs locally, scans repositories you add, and stores findings under{" "}
        <code>~/.local/share/nyx-agent/</code>.
      </p>
      <h4>Ownership attestation</h4>
      <p>Only add apps and repositories you own or have permission to test.</p>
      <label className="setup-checkbox">
        <input
          type="checkbox"
          checked={form.iOwnThis}
          onChange={(e) => update({ iOwnThis: e.target.checked })}
        />
        <span>
          I confirm that I own or am authorised to scan every repository I add to this install.
        </span>
      </label>
    </div>
  );
}

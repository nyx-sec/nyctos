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
        Nyx Agent runs as a local daemon on this machine. It clones (or links to)
        repositories you own, runs static and dynamic analysis against them, and
        keeps every finding under <code>~/.local/share/nyx-agent/</code>. Nothing
        leaves the box unless you point an AI runtime at a remote provider in the
        next step.
      </p>
      <h4>Ownership attestation</h4>
      <p>
        Before the agent will ingest a repository it requires an explicit
        attestation that you own it (or have the owner&rsquo;s permission to scan).
        Scanning unauthorised systems is illegal in most jurisdictions.
      </p>
      <label className="setup-checkbox">
        <input
          type="checkbox"
          checked={form.iOwnThis}
          onChange={(e) => update({ iOwnThis: e.target.checked })}
        />
        <span>
          I confirm that I own or am authorised to scan every repository I add to
          this install.
        </span>
      </label>
    </div>
  );
}

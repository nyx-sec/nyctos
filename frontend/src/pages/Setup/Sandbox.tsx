import { DoctorCheck, SandboxBackendChoice } from "@/api/client";
import { Button } from "@/components/Button";
import { Spinner } from "@/components/Spinner";
import { SetupFormState } from "./index";

interface Props {
  form: SetupFormState;
  update: (patch: Partial<SetupFormState>) => void;
  doctorChecks: DoctorCheck[];
  doctorRunning: boolean;
  doctorError: string | null;
  onRunDoctor: () => void;
}

const CHOICES: { value: SandboxBackendChoice; label: string; body: string }[] = [
  {
    value: "auto",
    label: "Auto",
    body: "Pick the strongest backend available on this host at scan time.",
  },
  {
    value: "process",
    label: "Process",
    body: "No kernel isolation. Static-pass only. Works everywhere.",
  },
  {
    value: "birdcage",
    label: "Birdcage (macOS Seatbelt)",
    body: "macOS only. Sandboxed scan process with a curated Seatbelt profile.",
  },
  {
    value: "libkrun",
    label: "libkrun microVM",
    body: "Linux only. Lightweight KVM-backed microVM.",
  },
  {
    value: "firecracker",
    label: "Firecracker microVM",
    body: "Linux only. AWS Firecracker microVM.",
  },
  {
    value: "docker",
    label: "Docker container",
    body: "Cross-platform. Requires a running docker daemon.",
  },
];

export function SandboxStep({
  form,
  update,
  doctorChecks,
  doctorRunning,
  doctorError,
  onRunDoctor,
}: Props) {
  return (
    <div className="setup-step__body">
      <h3>Pick a sandbox backend</h3>
      <p>
        The sandbox isolates dynamic / repro runs from the host. The static pass runs in-process
        regardless of backend choice.
      </p>
      <div className="setup-choices">
        {CHOICES.map((choice) => (
          <label
            key={choice.value}
            className={`setup-choice${form.sandboxBackend === choice.value ? " selected" : ""}`}
          >
            <input
              type="radio"
              name="sandbox-backend"
              checked={form.sandboxBackend === choice.value}
              onChange={() => update({ sandboxBackend: choice.value })}
            />
            <div>
              <span className="setup-choice__title">{choice.label}</span>
              <span className="setup-choice__body">{choice.body}</span>
            </div>
          </label>
        ))}
      </div>

      <div className="setup-doctor">
        <div className="setup-doctor__header">
          <h4>Doctor</h4>
          <Button variant="ghost" onClick={onRunDoctor} disabled={doctorRunning}>
            {doctorRunning ? <Spinner /> : "Run checks"}
          </Button>
        </div>
        {doctorError && (
          <p className="setup-error" role="alert">
            {doctorError}
          </p>
        )}
        {doctorChecks.length === 0 ? (
          <p className="setup-hint">
            Run the checks to verify that the runtime + backend you picked are usable on this host
            before committing the config.
          </p>
        ) : (
          <ul className="setup-doctor__list">
            {doctorChecks.map((check) => (
              <li key={check.name} className={`setup-doctor__row${check.passed ? " ok" : " fail"}`}>
                <span aria-hidden="true">{check.passed ? "✓" : "✗"}</span>
                <div>
                  <strong>{check.name}</strong>
                  <p>{check.message}</p>
                </div>
              </li>
            ))}
          </ul>
        )}
      </div>
    </div>
  );
}

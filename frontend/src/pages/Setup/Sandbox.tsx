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
    body: "Choose at scan time.",
  },
  {
    value: "process",
    label: "Process",
    body: "No kernel isolation.",
  },
  {
    value: "birdcage",
    label: "Birdcage (macOS Seatbelt)",
    body: "macOS Seatbelt.",
  },
  {
    value: "libkrun",
    label: "libkrun microVM",
    body: "Linux microVM.",
  },
  {
    value: "firecracker",
    label: "Firecracker microVM",
    body: "Linux microVM.",
  },
  {
    value: "docker",
    label: "Docker container",
    body: "Container sandbox.",
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
      <p>Used for dynamic verification and repro runs.</p>
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
          <p className="setup-hint">Run checks before saving.</p>
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

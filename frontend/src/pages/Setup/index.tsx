import { useState } from "react";
import { useNavigate } from "react-router-dom";
import {
  AiRuntimeChoice,
  SandboxBackendChoice,
  useDoctor,
  useSetupStatus,
  useSubmitSetup,
} from "@/api/client";
import { Button } from "@/components/Button";
import { Card } from "@/components/Card";
import { Spinner } from "@/components/Spinner";
import { AiRuntimeStep } from "./AiRuntime";
import { SandboxStep } from "./Sandbox";
import { WelcomeStep } from "./Welcome";

export interface SetupFormState {
  iOwnThis: boolean;
  aiRuntime: AiRuntimeChoice;
  anthropicApiKey: string;
  localLlmUrl: string;
  localLlmToken: string;
  sandboxBackend: SandboxBackendChoice;
}

const INITIAL: SetupFormState = {
  iOwnThis: false,
  aiRuntime: "none",
  anthropicApiKey: "",
  localLlmUrl: "",
  localLlmToken: "",
  sandboxBackend: "auto",
};

const STEP_LABELS = ["Welcome", "AI runtime", "Sandbox"] as const;

export function SetupWizard() {
  const navigate = useNavigate();
  const status = useSetupStatus();
  const submit = useSubmitSetup();
  const doctor = useDoctor();
  const [step, setStep] = useState(0);
  const [form, setForm] = useState<SetupFormState>(INITIAL);

  function update(patch: Partial<SetupFormState>) {
    setForm((cur) => ({ ...cur, ...patch }));
  }

  async function runDoctor() {
    await doctor.mutateAsync({
      ai_runtime: form.aiRuntime,
      anthropic_api_key:
        form.aiRuntime === "anthropic" && form.anthropicApiKey.trim()
          ? form.anthropicApiKey.trim()
          : undefined,
      local_llm_url:
        form.aiRuntime === "local-llm" && form.localLlmUrl.trim()
          ? form.localLlmUrl.trim()
          : undefined,
      local_llm_token:
        form.aiRuntime === "local-llm" && form.localLlmToken.trim()
          ? form.localLlmToken.trim()
          : undefined,
      sandbox_backend: form.sandboxBackend,
    });
  }

  async function commit() {
    await submit.mutateAsync({
      ai_runtime: form.aiRuntime,
      anthropic_api_key:
        form.aiRuntime === "anthropic" ? form.anthropicApiKey || undefined : undefined,
      local_llm_url: form.aiRuntime === "local-llm" ? form.localLlmUrl || undefined : undefined,
      local_llm_token: form.aiRuntime === "local-llm" ? form.localLlmToken || undefined : undefined,
      sandbox_backend: form.sandboxBackend,
      i_own_this: form.iOwnThis,
    });
    navigate("/projects", { replace: true });
  }

  return (
    <Card
      title="First-launch setup"
      subtitle={status.data?.config_path ? `Writes ${status.data.config_path}` : undefined}
    >
      <ol className="setup-stepper" aria-label="Setup progress">
        {STEP_LABELS.map((label, idx) => (
          <li
            key={label}
            className={`setup-stepper__item${idx === step ? " active" : ""}${idx < step ? " done" : ""}`}
            aria-current={idx === step ? "step" : undefined}
          >
            <span className="setup-stepper__dot">{idx + 1}</span>
            <span>{label}</span>
          </li>
        ))}
      </ol>

      <div className="setup-step">
        {step === 0 && <WelcomeStep form={form} update={update} />}
        {step === 1 && <AiRuntimeStep form={form} update={update} />}
        {step === 2 && (
          <SandboxStep
            form={form}
            update={update}
            doctorChecks={doctor.data?.checks ?? []}
            doctorRunning={doctor.isPending}
            doctorError={doctor.error ? String(doctor.error) : null}
            onRunDoctor={runDoctor}
          />
        )}
      </div>

      <div className="setup-actions">
        <Button
          variant="ghost"
          onClick={() => setStep((s) => Math.max(0, s - 1))}
          disabled={step === 0 || submit.isPending}
        >
          Back
        </Button>
        {step < 2 ? (
          <Button
            variant="primary"
            onClick={() => setStep((s) => s + 1)}
            disabled={!canAdvance(step, form)}
          >
            Continue
          </Button>
        ) : (
          <Button
            variant="primary"
            onClick={commit}
            disabled={!canCommit(form) || submit.isPending}
          >
            {submit.isPending ? <Spinner /> : "Finish setup"}
          </Button>
        )}
      </div>

      {submit.error && (
        <p className="setup-error" role="alert">
          {String(submit.error)}
        </p>
      )}
    </Card>
  );
}

function canAdvance(step: number, form: SetupFormState): boolean {
  if (step === 0) return form.iOwnThis;
  if (step === 1) {
    if (form.aiRuntime === "anthropic") return form.anthropicApiKey.trim().length > 0;
    if (form.aiRuntime === "local-llm") return form.localLlmUrl.trim().length > 0;
    return true;
  }
  return true;
}

function canCommit(form: SetupFormState): boolean {
  return form.iOwnThis && canAdvance(1, form);
}

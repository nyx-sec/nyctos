import { useEffect, useState } from "react";
import { useDoctor, useSetupStatus, useSubmitSetup } from "@/api/client";
import type { AiRuntimeChoice, SandboxBackendChoice, SetupStatusResponse } from "@/api/client";
import { useAdvancedMode } from "@/api/preferences";
import { Badge } from "@/components/Badge";
import { Button } from "@/components/Button";
import { Card } from "@/components/Card";
import { Spinner } from "@/components/Spinner";

const AI_CHOICES: { value: AiRuntimeChoice; label: string; body: string }[] = [
  {
    value: "none",
    label: "None",
    body: "Static-pass only. AI triage and candidate generation stay off.",
  },
  {
    value: "anthropic",
    label: "Anthropic API",
    body: "Hosted Claude models using a key stored in the OS keychain.",
  },
  {
    value: "local-llm",
    label: "Local OpenAI-compatible",
    body: "LM Studio, Ollama, vLLM, or another local /v1 endpoint.",
  },
  {
    value: "claude-code",
    label: "Claude Code CLI",
    body: "Uses an installed claude binary on this host.",
  },
];

const BACKEND_CHOICES: { value: SandboxBackendChoice; label: string; body: string }[] = [
  {
    value: "auto",
    label: "Auto",
    body: "Pick the strongest available backend at scan time.",
  },
  {
    value: "process",
    label: "Process",
    body: "No kernel isolation. Always available.",
  },
  {
    value: "birdcage",
    label: "Birdcage",
    body: "macOS Seatbelt profile for local sandboxing.",
  },
  {
    value: "docker",
    label: "Docker",
    body: "Container fallback when Docker is running.",
  },
  {
    value: "libkrun",
    label: "libkrun",
    body: "Linux KVM-backed microVM backend.",
  },
  {
    value: "firecracker",
    label: "Firecracker",
    body: "Linux Firecracker microVM backend.",
  },
];

const AI_VALUES = AI_CHOICES.map((choice) => choice.value);
const BACKEND_VALUES = BACKEND_CHOICES.map((choice) => choice.value);

export function Settings() {
  const status = useSetupStatus();
  const submit = useSubmitSetup();
  const doctor = useDoctor();
  const [advanced, setAdvanced] = useAdvancedMode();
  const [aiRuntime, setAiRuntime] = useState<AiRuntimeChoice>("none");
  const [sandboxBackend, setSandboxBackend] = useState<SandboxBackendChoice>("auto");
  const [anthropicApiKey, setAnthropicApiKey] = useState("");
  const [localLlmUrl, setLocalLlmUrl] = useState("");
  const [localLlmToken, setLocalLlmToken] = useState("");
  const [savedMessage, setSavedMessage] = useState<string | null>(null);

  useEffect(() => {
    if (!status.data) return;
    setAiRuntime(coerceAiRuntime(status.data.ai_runtime));
    setSandboxBackend(coerceSandboxBackend(status.data.sandbox_backend));
    setLocalLlmUrl(status.data.ai_api_base ?? "");
    setAnthropicApiKey("");
    setLocalLlmToken("");
  }, [status.data]);

  if (status.isPending) {
    return (
      <div className="settings-page">
        <Card>
          <div className="settings-page__pending">
            <Spinner size="lg" />
          </div>
        </Card>
      </div>
    );
  }

  if (status.error) {
    return (
      <div className="settings-page">
        <Card title="Settings">
          <p className="settings-page__error" role="alert">
            {String(status.error)}
          </p>
        </Card>
      </div>
    );
  }

  const data = status.data;
  const currentRuntime = coerceAiRuntime(data?.ai_runtime);
  const currentBackend = coerceSandboxBackend(data?.sandbox_backend);
  const validationMessage = validateRuntimeForm(
    aiRuntime,
    currentRuntime,
    anthropicApiKey,
    localLlmUrl,
  );
  const dirty = hasChanges(data, currentRuntime, currentBackend, {
    aiRuntime,
    sandboxBackend,
    anthropicApiKey,
    localLlmUrl,
    localLlmToken,
  });
  const canSave = dirty && !validationMessage && !submit.isPending;

  async function saveSettings() {
    setSavedMessage(null);
    const body: {
      ai_runtime: AiRuntimeChoice;
      anthropic_api_key?: string;
      local_llm_url?: string;
      local_llm_token?: string;
      sandbox_backend: SandboxBackendChoice;
      i_own_this: boolean;
    } = {
      ai_runtime: aiRuntime,
      sandbox_backend: sandboxBackend,
      i_own_this: true,
    };
    if (aiRuntime === "anthropic" && anthropicApiKey.trim()) {
      body.anthropic_api_key = anthropicApiKey.trim();
    }
    if (aiRuntime === "local-llm") {
      body.local_llm_url = localLlmUrl.trim();
      if (localLlmToken.trim()) {
        body.local_llm_token = localLlmToken.trim();
      }
    }
    await submit.mutateAsync(body);
    setSavedMessage("Settings saved.");
  }

  async function runDoctor() {
    await doctor.mutateAsync({
      ai_runtime: aiRuntime,
      anthropic_api_key:
        aiRuntime === "anthropic" && anthropicApiKey.trim() ? anthropicApiKey.trim() : undefined,
      local_llm_url: aiRuntime === "local-llm" ? localLlmUrl.trim() || undefined : undefined,
      local_llm_token:
        aiRuntime === "local-llm" && localLlmToken.trim() ? localLlmToken.trim() : undefined,
      sandbox_backend: sandboxBackend,
    });
  }

  function chooseAiRuntime(next: AiRuntimeChoice) {
    setAiRuntime(next);
    doctor.reset();
  }

  function chooseSandboxBackend(next: SandboxBackendChoice) {
    setSandboxBackend(next);
    doctor.reset();
  }

  return (
    <div className="settings-page">
      <Card
        title="Settings"
        subtitle={data?.config_path ? data.config_path : "Daemon configuration"}
        actions={
          <Badge tone={data?.complete ? "success" : "warning"}>
            {data?.complete ? "Configured" : "Setup pending"}
          </Badge>
        }
      >
        <div className="settings-summary-grid" aria-label="Current settings">
          <SummaryTile
            label="AI agent"
            value={runtimeLabel(data?.ai_runtime)}
            detail={runtimeDetail(data)}
          />
          <SummaryTile
            label="Backend"
            value={backendLabel(data?.sandbox_backend)}
            detail={sandboxDetail(data)}
          />
          <SummaryTile
            label="API"
            value={data?.ui_listen_addr ?? "127.0.0.1:8765"}
            detail={data?.ui_open_browser === false ? "Browser launch off" : "Browser launch on"}
          />
          <SummaryTile label="Scan limits" value={scanLimit(data)} detail={stateDetail(data)} />
        </div>
      </Card>

      <Card
        title="System Checks"
        subtitle="Verifies the state directory, selected AI agent, and selected sandbox backend."
        actions={
          <Button variant="ghost" onClick={runDoctor} disabled={doctor.isPending}>
            {doctor.isPending ? <Spinner /> : "Run checks"}
          </Button>
        }
      >
        {doctor.error && (
          <p className="settings-page__error" role="alert">
            {String(doctor.error)}
          </p>
        )}
        {doctor.data?.checks.length ? (
          <ul className="settings-doctor__list">
            {doctor.data.checks.map((check) => (
              <li
                key={check.name}
                className={`settings-doctor__row${check.passed ? " ok" : " fail"}`}
              >
                <span aria-hidden="true">{check.passed ? "✓" : "✗"}</span>
                <div>
                  <strong>{check.name}</strong>
                  <p>{check.message}</p>
                </div>
              </li>
            ))}
          </ul>
        ) : (
          <p className="settings-page__hint">No checks have been run for the current selection.</p>
        )}
      </Card>

      <Card title="AI Agent" subtitle="Runtime used for AI triage, generation, and exploration.">
        <div className="settings-choice-grid">
          {AI_CHOICES.map((choice) => (
            <label
              className={`settings-choice${aiRuntime === choice.value ? " selected" : ""}`}
              key={choice.value}
            >
              <input
                type="radio"
                name="settings-ai-runtime"
                checked={aiRuntime === choice.value}
                onChange={() => chooseAiRuntime(choice.value)}
              />
              <span>
                <span className="settings-choice__title">{choice.label}</span>
                <span className="settings-choice__body">{choice.body}</span>
              </span>
            </label>
          ))}
        </div>

        {aiRuntime === "anthropic" && (
          <div className="settings-form-grid">
            <div className="setup-field">
              <label htmlFor="settings-anthropic-key">Anthropic API key</label>
              <input
                id="settings-anthropic-key"
                type="password"
                autoComplete="off"
                placeholder={
                  currentRuntime === "anthropic" ? "Leave blank to keep current key" : "sk-ant-..."
                }
                value={anthropicApiKey}
                onChange={(e) => setAnthropicApiKey(e.target.value)}
              />
            </div>
            <p className="settings-page__hint">
              Keys are written to the OS keychain and never stored in <code>nyctos.toml</code>.
            </p>
          </div>
        )}

        {aiRuntime === "local-llm" && (
          <div className="settings-form-grid settings-form-grid--two">
            <div className="setup-field">
              <label htmlFor="settings-local-llm-url">OpenAI-compatible URL</label>
              <input
                id="settings-local-llm-url"
                type="url"
                placeholder="http://127.0.0.1:1234/v1"
                value={localLlmUrl}
                onChange={(e) => setLocalLlmUrl(e.target.value)}
              />
            </div>
            <div className="setup-field">
              <label htmlFor="settings-local-llm-token">Bearer token</label>
              <input
                id="settings-local-llm-token"
                type="password"
                autoComplete="off"
                placeholder="Leave blank to keep current token"
                value={localLlmToken}
                onChange={(e) => setLocalLlmToken(e.target.value)}
              />
            </div>
          </div>
        )}
      </Card>

      <Card title="Backend" subtitle="Sandbox backend used by dynamic verification and repro runs.">
        <div className="settings-choice-grid settings-choice-grid--backend">
          {BACKEND_CHOICES.map((choice) => (
            <label
              className={`settings-choice${sandboxBackend === choice.value ? " selected" : ""}`}
              key={choice.value}
            >
              <input
                type="radio"
                name="settings-sandbox-backend"
                checked={sandboxBackend === choice.value}
                onChange={() => chooseSandboxBackend(choice.value)}
              />
              <span>
                <span className="settings-choice__title">{choice.label}</span>
                <span className="settings-choice__body">{choice.body}</span>
              </span>
            </label>
          ))}
        </div>
      </Card>

      <Card title="Local Settings" subtitle="Preferences and local daemon details for this host.">
        <section className="settings-page__section">
          <header className="settings-page__row">
            <div>
              <h3 className="settings-page__row-title">Advanced UI</h3>
              <p className="settings-page__row-help">
                Reveals raw findings, chains, and quarantine views in the sidebar.
              </p>
            </div>
            <label className="settings-page__toggle">
              <input
                type="checkbox"
                checked={advanced}
                onChange={(e) => setAdvanced(e.target.checked)}
                aria-label="Show advanced UI"
              />
              <span className="settings-page__switch" aria-hidden="true">
                <span />
              </span>
              <span>{advanced ? "On" : "Off"}</span>
            </label>
          </header>
        </section>
        <dl className="settings-kv">
          <div>
            <dt>Config file</dt>
            <dd>{data?.config_path ? <code>{data.config_path}</code> : "-"}</dd>
          </div>
          <div>
            <dt>State directory</dt>
            <dd>{data?.state_dir ? <code>{data.state_dir}</code> : "Default"}</dd>
          </div>
          <div>
            <dt>Log level</dt>
            <dd>{data?.log_level ?? "info"}</dd>
          </div>
          <div>
            <dt>Sandbox network</dt>
            <dd>{data?.sandbox_allow_network ? "Allowed" : "Blocked"}</dd>
          </div>
        </dl>
      </Card>

      <div className="settings-actions">
        <div className="settings-actions__status">
          {validationMessage && <span>{validationMessage}</span>}
          {submit.error && (
            <span className="settings-page__error" role="alert">
              {String(submit.error)}
            </span>
          )}
          {savedMessage && <span>{savedMessage}</span>}
        </div>
        <Button variant="primary" onClick={saveSettings} disabled={!canSave}>
          {submit.isPending ? <Spinner /> : "Save changes"}
        </Button>
      </div>
    </div>
  );
}

function SummaryTile({ label, value, detail }: { label: string; value: string; detail: string }) {
  return (
    <div className="settings-summary-tile">
      <span className="settings-summary-tile__label">{label}</span>
      <strong>{value}</strong>
      <span>{detail}</span>
    </div>
  );
}

function coerceAiRuntime(value: string | undefined): AiRuntimeChoice {
  return AI_VALUES.includes(value as AiRuntimeChoice) ? (value as AiRuntimeChoice) : "none";
}

function coerceSandboxBackend(value: string | undefined): SandboxBackendChoice {
  return BACKEND_VALUES.includes(value as SandboxBackendChoice)
    ? (value as SandboxBackendChoice)
    : "auto";
}

function runtimeLabel(value: string | undefined): string {
  return AI_CHOICES.find((choice) => choice.value === value)?.label ?? value ?? "None";
}

function backendLabel(value: string | undefined): string {
  return BACKEND_CHOICES.find((choice) => choice.value === value)?.label ?? value ?? "Auto";
}

function runtimeDetail(data: SetupStatusResponse | undefined): string {
  if (!data || data.ai_runtime === "none") return "Static-pass only";
  if (data.ai_runtime === "local-llm") return data.ai_api_base ?? "Local endpoint";
  return data.ai_model ?? data.ai_provider ?? "Configured";
}

function sandboxDetail(data: SetupStatusResponse | undefined): string {
  if (!data?.sandbox_enabled) return "Disabled";
  return data.sandbox_allow_network ? "Network allowed" : "Network blocked";
}

function stateDetail(data: SetupStatusResponse | undefined): string {
  return data?.state_dir ? "Custom state directory" : "Default state directory";
}

function scanLimit(data: SetupStatusResponse | undefined): string {
  const scans = data?.max_parallel_scans ?? 4;
  const timeout = data?.scan_timeout_secs ?? 600;
  return `${scans} parallel / ${timeout}s`;
}

function validateRuntimeForm(
  aiRuntime: AiRuntimeChoice,
  currentRuntime: AiRuntimeChoice,
  anthropicApiKey: string,
  localLlmUrl: string,
): string | null {
  if (
    aiRuntime === "anthropic" &&
    currentRuntime !== "anthropic" &&
    anthropicApiKey.trim().length === 0
  ) {
    return "Enter an Anthropic API key before switching runtimes.";
  }
  if (aiRuntime === "local-llm" && localLlmUrl.trim().length === 0) {
    return "Enter a local OpenAI-compatible URL before saving.";
  }
  return null;
}

function hasChanges(
  data: SetupStatusResponse | undefined,
  currentRuntime: AiRuntimeChoice,
  currentBackend: SandboxBackendChoice,
  form: {
    aiRuntime: AiRuntimeChoice;
    sandboxBackend: SandboxBackendChoice;
    anthropicApiKey: string;
    localLlmUrl: string;
    localLlmToken: string;
  },
): boolean {
  return (
    form.aiRuntime !== currentRuntime ||
    form.sandboxBackend !== currentBackend ||
    (form.aiRuntime === "anthropic" && form.anthropicApiKey.trim().length > 0) ||
    (form.aiRuntime === "local-llm" &&
      (form.localLlmUrl.trim() !== (data?.ai_api_base ?? "") ||
        form.localLlmToken.trim().length > 0))
  );
}

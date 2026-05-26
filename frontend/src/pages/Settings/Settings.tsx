import { type ReactNode, useEffect, useState } from "react";
import type { AiRuntimeChoice, SandboxBackendChoice, SetupStatusResponse } from "@/api/client";
import { useDoctor, useSetupStatus, useSubmitSetup } from "@/api/client";
import { useAdvancedMode } from "@/api/preferences";
import { Button } from "@/components/Button";
import { Card } from "@/components/Card";
import { PageHeader, PageShell } from "@/components/Page";
import { Spinner } from "@/components/Spinner";
import { useToast } from "@/components/Toast";

const AI_CHOICES: { value: AiRuntimeChoice; label: string; body: string }[] = [
  {
    value: "none",
    label: "Static engine",
    body: "No model access required.",
  },
  {
    value: "local-llm",
    label: "Local OpenAI-compatible",
    body: "Your local /v1 endpoint.",
  },
  {
    value: "anthropic",
    label: "Anthropic API (BYOK)",
    body: "Direct API key in the OS keychain.",
  },
  {
    value: "claude-code",
    label: "Claude Code CLI (optional)",
    body: "Uses your installed CLI.",
  },
  {
    value: "codex",
    label: "Codex CLI (optional)",
    body: "Uses your installed CLI.",
  },
];

const BACKEND_CHOICES: { value: SandboxBackendChoice; label: string; body: string }[] = [
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
    label: "Birdcage",
    body: "macOS Seatbelt.",
  },
  {
    value: "docker",
    label: "Docker",
    body: "Container sandbox.",
  },
  {
    value: "libkrun",
    label: "libkrun",
    body: "Linux microVM.",
  },
  {
    value: "firecracker",
    label: "Firecracker",
    body: "Linux microVM.",
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
  const [budgetEnabled, setBudgetEnabled] = useState(false);
  const [budgetUsd, setBudgetUsd] = useState("25");
  const { showToast } = useToast();

  useEffect(() => {
    if (!status.data) return;
    setAiRuntime(coerceAiRuntime(status.data.ai_runtime));
    setSandboxBackend(coerceSandboxBackend(status.data.sandbox_backend));
    setLocalLlmUrl(status.data.ai_api_base ?? "");
    setAnthropicApiKey("");
    setLocalLlmToken("");
    const budgetMicros = status.data.default_run_budget_usd_micros;
    setBudgetEnabled(typeof budgetMicros === "number" && budgetMicros > 0);
    setBudgetUsd(
      typeof budgetMicros === "number" && budgetMicros > 0 ? formatBudgetInput(budgetMicros) : "25",
    );
  }, [status.data]);

  if (status.isPending) {
    return (
      <PageShell className="settings-page">
        <Card>
          <div className="settings-page__pending">
            <Spinner size="lg" />
          </div>
        </Card>
      </PageShell>
    );
  }

  if (status.error) {
    return (
      <PageShell className="settings-page">
        <Card title="Settings">
          <p className="settings-page__error" role="alert">
            {String(status.error)}
          </p>
        </Card>
      </PageShell>
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
    budgetEnabled,
    budgetUsd,
  );
  const dirty = hasChanges(data, currentRuntime, currentBackend, {
    aiRuntime,
    sandboxBackend,
    anthropicApiKey,
    localLlmUrl,
    localLlmToken,
    budgetEnabled,
    budgetUsd,
  });
  const canSave = dirty && !validationMessage && !submit.isPending;

  async function saveSettings() {
    const body: {
      ai_runtime: AiRuntimeChoice;
      anthropic_api_key?: string;
      local_llm_url?: string;
      local_llm_token?: string;
      default_run_budget_usd_micros?: number | null;
      sandbox_backend: SandboxBackendChoice;
      i_own_this: boolean;
    } = {
      ai_runtime: aiRuntime,
      default_run_budget_usd_micros: budgetEnabled ? budgetUsdToMicros(budgetUsd) : null,
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
    showToast("Settings saved.", { tone: "success" });
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
    <PageShell size="wide" className="settings-page">
      <PageHeader
        title="Settings"
        meta={data?.config_path ? <code>{data.config_path}</code> : "Local daemon configuration"}
      />

      <dl className="settings-summary-list" aria-label="Current settings">
        <SummaryItem label="AI" value={runtimeLabel(data?.ai_runtime)} />
        <SummaryItem label="Backend" value={backendLabel(data?.sandbox_backend)} />
        <SummaryItem label="Budget" value={budgetSummary(data)} />
      </dl>

      <div className="settings-panel">
        <SettingsSection
          title="Checks"
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
            <p className="settings-page__hint">No checks yet.</p>
          )}
        </SettingsSection>

        <SettingsSection title="AI runtime">
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
                    currentRuntime === "anthropic"
                      ? "Leave blank to keep current key"
                      : "sk-ant-..."
                  }
                  value={anthropicApiKey}
                  onChange={(e) => setAnthropicApiKey(e.target.value)}
                />
              </div>
              <p className="settings-page__hint">
                Official BYOK path. Keys are written to the OS keychain and never stored in{" "}
                <code>nyx-agent.toml</code>.
              </p>
            </div>
          )}

          {aiRuntime === "none" && (
            <p className="settings-page__hint">
              Static scans, route mapping, live checks, evidence storage, and triage stay enabled.
            </p>
          )}

          {aiRuntime === "local-llm" && (
            <>
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
              <p className="settings-page__hint">
                Local one-shot helpers use <code>/chat/completions</code>. Set{" "}
                <code>[ai].model</code> in config if your server requires a specific model id.
              </p>
            </>
          )}

          {(aiRuntime === "claude-code" || aiRuntime === "codex") && (
            <p className="settings-page__hint">
              Optional local CLI adapter. Nyx Agent does not include or resell model access; use
              only with provider-authorized credentials and terms.
            </p>
          )}
        </SettingsSection>

        <SettingsSection title="Backend">
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
        </SettingsSection>

        <SettingsSection title="Budget">
          <section className="settings-page__section">
            <header className="settings-page__row">
              <div>
                <h3 className="settings-page__row-title">Run budget cap</h3>
              </div>
              <label className="settings-page__toggle">
                <input
                  type="checkbox"
                  checked={budgetEnabled}
                  onChange={(e) => setBudgetEnabled(e.target.checked)}
                  aria-label="Limit AI budget"
                />
                <span className="settings-page__switch" aria-hidden="true">
                  <span />
                </span>
                <span>{budgetEnabled ? "Limited" : "Unlimited"}</span>
              </label>
            </header>
            {budgetEnabled && (
              <div className="settings-budget-row">
                <div className="setup-field">
                  <label htmlFor="settings-ai-budget-usd">Budget per run (USD)</label>
                  <input
                    id="settings-ai-budget-usd"
                    type="number"
                    min="0.01"
                    step="0.01"
                    inputMode="decimal"
                    value={budgetUsd}
                    onChange={(e) => setBudgetUsd(e.target.value)}
                  />
                </div>
              </div>
            )}
          </section>
        </SettingsSection>

        <SettingsSection title="Local">
          <section className="settings-page__section">
            <header className="settings-page__row">
              <div>
                <h3 className="settings-page__row-title">Advanced UI</h3>
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
              <dt>API</dt>
              <dd>{data?.ui_listen_addr ?? "127.0.0.1:8765"}</dd>
            </div>
            <div>
              <dt>Sandbox network</dt>
              <dd>{data?.sandbox_allow_network ? "Allowed" : "Blocked"}</dd>
            </div>
            <div>
              <dt>Scan limits</dt>
              <dd>{scanLimit(data)}</dd>
            </div>
          </dl>
        </SettingsSection>
      </div>

      <div className="settings-actions">
        <div className="settings-actions__status">
          {validationMessage && <span>{validationMessage}</span>}
          {submit.error && (
            <span className="settings-page__error" role="alert">
              {String(submit.error)}
            </span>
          )}
        </div>
        <Button variant="primary" onClick={saveSettings} disabled={!canSave}>
          {submit.isPending ? <Spinner /> : "Save changes"}
        </Button>
      </div>
    </PageShell>
  );
}

function SummaryItem({ label, value }: { label: string; value: string }) {
  return (
    <div>
      <dt>{label}</dt>
      <dd>{value}</dd>
    </div>
  );
}

interface SettingsSectionProps {
  title: string;
  subtitle?: string;
  actions?: ReactNode;
  children: ReactNode;
}

function SettingsSection({ title, subtitle, actions, children }: SettingsSectionProps) {
  const titleId = `settings-section-${title.toLowerCase().replace(/[^a-z0-9]+/g, "-")}`;
  return (
    <section className="settings-section" aria-labelledby={titleId}>
      <div className="settings-section__header">
        <div>
          <h2 id={titleId}>{title}</h2>
          {subtitle && <p>{subtitle}</p>}
        </div>
        {actions && <div className="settings-section__actions">{actions}</div>}
      </div>
      <div className="settings-section__content">{children}</div>
    </section>
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

function budgetSummary(data: SetupStatusResponse | undefined): string {
  const micros = data?.default_run_budget_usd_micros;
  return typeof micros === "number" && micros > 0 ? formatBudgetUsd(micros) : "Unlimited";
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
  budgetEnabled: boolean,
  budgetUsd: string,
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
  if (budgetEnabled && budgetUsdToMicros(budgetUsd) <= 0) {
    return "Enter an AI budget greater than $0.";
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
    budgetEnabled: boolean;
    budgetUsd: string;
  },
): boolean {
  const currentBudget = data?.default_run_budget_usd_micros;
  const currentBudgetEnabled = typeof currentBudget === "number" && currentBudget > 0;
  const nextBudget = form.budgetEnabled ? budgetUsdToMicros(form.budgetUsd) : null;
  return (
    form.aiRuntime !== currentRuntime ||
    form.sandboxBackend !== currentBackend ||
    form.budgetEnabled !== currentBudgetEnabled ||
    (form.budgetEnabled && nextBudget !== currentBudget) ||
    (form.aiRuntime === "anthropic" && form.anthropicApiKey.trim().length > 0) ||
    (form.aiRuntime === "local-llm" &&
      (form.localLlmUrl.trim() !== (data?.ai_api_base ?? "") ||
        form.localLlmToken.trim().length > 0))
  );
}

function budgetUsdToMicros(value: string): number {
  const parsed = Number(value);
  if (!Number.isFinite(parsed) || parsed <= 0) return 0;
  return Math.round(parsed * 1_000_000);
}

function formatBudgetInput(micros: number): string {
  return (micros / 1_000_000).toFixed(2).replace(/\.00$/, "");
}

function formatBudgetUsd(micros: number): string {
  return `$${(micros / 1_000_000).toFixed(2)}`;
}

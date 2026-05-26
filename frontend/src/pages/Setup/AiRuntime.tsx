import { AiRuntimeChoice } from "@/api/client";
import { SetupFormState } from "./index";

interface Props {
  form: SetupFormState;
  update: (patch: Partial<SetupFormState>) => void;
}

const CHOICES: { value: AiRuntimeChoice; label: string; body: string }[] = [
  {
    value: "none",
    label: "Static engine (recommended)",
    body: "No model access required.",
  },
  {
    value: "local-llm",
    label: "Local OpenAI-compatible runtime",
    body: "Your local /v1 endpoint.",
  },
  {
    value: "anthropic",
    label: "Anthropic API (BYOK)",
    body: "Direct API key in the OS keychain.",
  },
  {
    value: "codex",
    label: "Codex CLI (optional)",
    body: "Uses your installed CLI.",
  },
  {
    value: "claude-code",
    label: "Claude Code CLI (optional)",
    body: "Uses your installed CLI.",
  },
];

export function AiRuntimeStep({ form, update }: Props) {
  return (
    <div className="setup-step__body">
      <h3>Pick an AI runtime</h3>
      <p>Start with the static engine, then add a local endpoint or BYOK provider later.</p>
      <div className="setup-choices">
        {CHOICES.map((choice) => (
          <label
            key={choice.value}
            className={`setup-choice${form.aiRuntime === choice.value ? " selected" : ""}`}
          >
            <input
              type="radio"
              name="ai-runtime"
              checked={form.aiRuntime === choice.value}
              onChange={() => update({ aiRuntime: choice.value })}
            />
            <div>
              <span className="setup-choice__title">{choice.label}</span>
              <span className="setup-choice__body">{choice.body}</span>
            </div>
          </label>
        ))}
      </div>

      {form.aiRuntime === "anthropic" && (
        <div className="setup-field">
          <label htmlFor="anthropic-key">Anthropic API key</label>
          <input
            id="anthropic-key"
            type="password"
            autoComplete="off"
            placeholder="sk-ant-..."
            value={form.anthropicApiKey}
            onChange={(e) => update({ anthropicApiKey: e.target.value })}
          />
          <p className="setup-hint">Official BYOK path. Stored in the OS keychain.</p>
        </div>
      )}

      {form.aiRuntime === "none" && (
        <div className="setup-field">
          <p>
            Static scans, route mapping, live checks, evidence storage, and triage stay enabled.
          </p>
        </div>
      )}

      {form.aiRuntime === "local-llm" && (
        <>
          <div className="setup-field">
            <label htmlFor="local-llm-url">OpenAI-compatible URL</label>
            <input
              id="local-llm-url"
              type="url"
              placeholder="http://127.0.0.1:1234/v1"
              value={form.localLlmUrl}
              onChange={(e) => update({ localLlmUrl: e.target.value })}
            />
          </div>
          <div className="setup-field">
            <label htmlFor="local-llm-token">Bearer token (optional)</label>
            <input
              id="local-llm-token"
              type="password"
              autoComplete="off"
              value={form.localLlmToken}
              onChange={(e) => update({ localLlmToken: e.target.value })}
            />
            <p className="setup-hint">
              Optional. Stored in the OS keychain. Set <code>[ai].model</code> in config if your
              server requires a specific model id.
            </p>
          </div>
        </>
      )}

      {form.aiRuntime === "claude-code" && (
        <div className="setup-field">
          <p>
            Nyctos will look for <code>claude</code> on <code>$PATH</code>.
          </p>
          <p className="setup-hint">
            Optional local adapter. Nyctos does not include or resell model access; use only with
            provider-authorized credentials and terms.
          </p>
        </div>
      )}

      {form.aiRuntime === "codex" && (
        <div className="setup-field">
          <p>
            Nyctos will look for <code>codex</code> on <code>$PATH</code>.
          </p>
          <p className="setup-hint">
            Optional local adapter. Nyctos does not include or resell model access; use only with
            provider-authorized credentials and terms.
          </p>
        </div>
      )}
    </div>
  );
}

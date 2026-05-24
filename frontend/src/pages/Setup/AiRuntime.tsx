import { AiRuntimeChoice } from "@/api/client";
import { SetupFormState } from "./index";

interface Props {
  form: SetupFormState;
  update: (patch: Partial<SetupFormState>) => void;
}

const CHOICES: { value: AiRuntimeChoice; label: string; body: string }[] = [
  {
    value: "claude-code",
    label: "Claude Code CLI (recommended)",
    body: "Local CLI agent.",
  },
  {
    value: "codex",
    label: "Codex CLI",
    body: "Local CLI agent.",
  },
  {
    value: "anthropic",
    label: "Anthropic API",
    body: "Direct API key in the OS keychain.",
  },
  {
    value: "local-llm",
    label: "Local OpenAI-compatible runtime",
    body: "Local /v1 endpoint.",
  },
  {
    value: "none",
    label: "None (static-pass only)",
    body: "Static pass only.",
  },
];

export function AiRuntimeStep({ form, update }: Props) {
  return (
    <div className="setup-step__body">
      <h3>Pick an AI runtime</h3>
      <p>Claude Code is the default. You can switch later in Settings.</p>
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
          <p className="setup-hint">Stored in the OS keychain.</p>
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
            <p className="setup-hint">Optional. Stored in the OS keychain.</p>
          </div>
        </>
      )}

      {form.aiRuntime === "claude-code" && (
        <div className="setup-field">
          <p>
            Nyctos will look for <code>claude</code> on <code>$PATH</code>.
          </p>
        </div>
      )}

      {form.aiRuntime === "codex" && (
        <div className="setup-field">
          <p>
            Nyctos will look for <code>codex</code> on <code>$PATH</code>.
          </p>
        </div>
      )}
    </div>
  );
}

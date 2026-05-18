import { AiRuntimeChoice } from "@/api/client";
import { SetupFormState } from "./index";

interface Props {
  form: SetupFormState;
  update: (patch: Partial<SetupFormState>) => void;
}

const CHOICES: { value: AiRuntimeChoice; label: string; body: string }[] = [
  {
    value: "none",
    label: "None (static-pass only)",
    body: "Skip every AI step. The daemon still runs nyx static analysis end-to-end.",
  },
  {
    value: "anthropic",
    label: "Anthropic API",
    body: "Hosted Claude models. Requires an API key; stored in the OS keychain, never in TOML.",
  },
  {
    value: "local-llm",
    label: "Local OpenAI-compatible runtime",
    body: "Point at an LM Studio / Ollama / vLLM endpoint already running on this machine.",
  },
  {
    value: "claude-code",
    label: "Claude Code CLI",
    body: "Drive an installed claude CLI on $PATH. The daemon verifies the binary on save.",
  },
];

export function AiRuntimeStep({ form, update }: Props) {
  return (
    <div className="setup-step__body">
      <h3>Pick an AI runtime</h3>
      <p>
        The agent runs without an AI runtime; selecting one enables triage and
        candidate generation in later phases. You can change this at any time.
      </p>
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
          <p className="setup-hint">
            Stored in your operating-system keychain on save; never written to
            <code> nyctos.toml</code> or the JSON log.
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
              Only set this if your local runtime expects an
              <code> Authorization: Bearer ...</code> header. Stored in the OS keychain.
            </p>
          </div>
        </>
      )}

      {form.aiRuntime === "claude-code" && (
        <div className="setup-field">
          <p>
            The daemon will look for a <code>claude</code> binary on <code>$PATH</code> when
            you reach the next step. No additional configuration is needed here.
          </p>
        </div>
      )}
    </div>
  );
}

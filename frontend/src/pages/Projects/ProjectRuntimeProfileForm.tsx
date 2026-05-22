import { type ChangeEvent, useEffect, useRef, useState } from "react";
import type {
  LaunchEnvRef,
  LaunchHealthCheck,
  LaunchStep,
  ProjectLaunchProfile,
  ProjectLaunchProfileInput,
  ProjectRuntimeCommand,
  ProjectRuntimeEnvVar,
  ProjectRuntimeProfile,
} from "@/api/client";
import { testLaunchTarget } from "@/api/client";
import { Button } from "@/components/Button";

export type LaunchMode = "already-running" | "custom-commands" | "docker-compose";
export type ReadinessKind = "target-url" | "custom-url" | "command" | "skip";
type ReachabilityStatus = "idle" | "checking" | "reachable" | "unreachable";

interface ReachabilityState {
  status: ReachabilityStatus;
  message: string;
}

export interface RuntimeCommandDraft {
  command: string;
  repo_name: string;
  working_directory: string;
  timeout_seconds: string;
}

export interface RuntimeEnvDraft {
  name: string;
  value: string;
  secret: boolean;
}

export interface RuntimeProfileDraft {
  mode: LaunchMode;
  target_base_url: string;
  readiness_kind: ReadinessKind;
  health_check_url: string;
  health_check_command: RuntimeCommandDraft;
  allowed_hosts: string;
  env_file: string;
  timeout_seconds: string;
  build_commands: RuntimeCommandDraft[];
  start_commands: RuntimeCommandDraft[];
  env_vars: RuntimeEnvDraft[];
}

const LAUNCH_MODES: Array<{ value: LaunchMode; label: string }> = [
  { value: "already-running", label: "Already running" },
  { value: "custom-commands", label: "Start project" },
  { value: "docker-compose", label: "Docker" },
];

const READINESS_KINDS: Array<{ value: ReadinessKind; label: string }> = [
  { value: "target-url", label: "URL responds" },
  { value: "custom-url", label: "Health URL" },
  { value: "command", label: "Command" },
  { value: "skip", label: "Skip" },
];

const blankCommand = (): RuntimeCommandDraft => ({
  command: "",
  repo_name: "",
  working_directory: "",
  timeout_seconds: "",
});

const blankEnv = (): RuntimeEnvDraft => ({ name: "", value: "", secret: false });

export function emptyRuntimeProfileDraft(targetBaseUrl = ""): RuntimeProfileDraft {
  return {
    mode: "already-running",
    target_base_url: targetBaseUrl,
    readiness_kind: "target-url",
    health_check_url: "",
    health_check_command: blankCommand(),
    allowed_hosts: "",
    env_file: "",
    timeout_seconds: "",
    build_commands: [],
    start_commands: [],
    env_vars: [],
  };
}

export function runtimeProfileToDraft(
  profile: ProjectRuntimeProfile | null | undefined,
  fallbackTargetBaseUrl = "",
): RuntimeProfileDraft {
  if (!profile) return emptyRuntimeProfileDraft(fallbackTargetBaseUrl);
  const target = profile.target_base_url ?? fallbackTargetBaseUrl;
  const hasCommands =
    (profile.build_commands ?? []).length > 0 || (profile.start_commands ?? []).length > 0;
  return {
    mode: hasCommands ? "custom-commands" : "already-running",
    target_base_url: target,
    readiness_kind: runtimeReadinessKind(profile, target),
    health_check_url: profile.health_check_url ?? "",
    health_check_command: commandToDraft(profile.health_check_command ?? null),
    allowed_hosts: (profile.allowed_hosts ?? []).join("\n"),
    env_file: profile.env_file ?? "",
    timeout_seconds: profile.timeout_seconds?.toString() ?? "",
    build_commands: commandDrafts(profile.build_commands ?? []),
    start_commands: commandDrafts(profile.start_commands ?? []),
    env_vars: envDrafts(profile.env_vars ?? []),
  };
}

export function runtimeProfileFromDraft(
  draft: RuntimeProfileDraft,
): ProjectRuntimeProfile | undefined {
  const build_commands = draft.build_commands.map(commandFromDraft).filter(isDefined);
  const start_commands = draft.start_commands.map(commandFromDraft).filter(isDefined);
  const health_check_command =
    draft.readiness_kind === "command" ? commandFromDraft(draft.health_check_command) : undefined;
  const allowed_hosts = splitList(draft.allowed_hosts);
  const env_vars = draft.env_vars.map(envFromDraft).filter(isDefined);
  const target_base_url = trimOrUndefined(draft.target_base_url);
  const health_check_url = runtimeHealthUrlFromDraft(draft, target_base_url);
  const env_file = trimOrUndefined(draft.env_file);
  const timeout_seconds = positiveIntOrUndefined(draft.timeout_seconds);

  const hasContent =
    build_commands.length > 0 ||
    start_commands.length > 0 ||
    Boolean(health_check_command) ||
    Boolean(target_base_url) ||
    Boolean(health_check_url) ||
    allowed_hosts.length > 0 ||
    env_vars.length > 0 ||
    Boolean(env_file) ||
    timeout_seconds !== undefined;

  if (!hasContent) return undefined;

  const profile: ProjectRuntimeProfile = {
    build_commands,
    start_commands,
    allowed_hosts,
    env_vars,
  };
  if (target_base_url) profile.target_base_url = target_base_url;
  if (health_check_url) profile.health_check_url = health_check_url;
  if (health_check_command) profile.health_check_command = health_check_command;
  if (env_file) profile.env_file = env_file;
  if (timeout_seconds !== undefined) profile.timeout_seconds = timeout_seconds;
  return profile;
}

export function runtimeProfileDraftError(draft: RuntimeProfileDraft): string | null {
  if (!isBlankOrHttpUrl(draft.target_base_url)) {
    return "App URL must start with http:// or https://";
  }
  if (draft.readiness_kind === "custom-url" && !isBlankOrHttpUrl(draft.health_check_url)) {
    return "Readiness URL must start with http:// or https://";
  }
  const timeoutFields = [
    draft.timeout_seconds,
    draft.health_check_command.timeout_seconds,
    ...draft.build_commands.map((cmd) => cmd.timeout_seconds),
    ...draft.start_commands.map((cmd) => cmd.timeout_seconds),
  ];
  if (timeoutFields.some(isInvalidPositiveInteger)) {
    return "Timeouts must be whole seconds greater than zero";
  }
  return null;
}

export const launchProfileDraftError = runtimeProfileDraftError;

export function launchProfileToDraft(
  profile: ProjectLaunchProfile | null | undefined,
  fallbackTargetBaseUrl = "",
): RuntimeProfileDraft {
  if (!profile) return emptyRuntimeProfileDraft(fallbackTargetBaseUrl);
  const target = profile.target_urls[0] ?? fallbackTargetBaseUrl;
  const httpCheck = profile.health_checks.find((check) => check.kind === "http" && check.url);
  const commandCheck = profile.health_checks.find((check) => check.kind === "command");
  const envFile = profile.env_refs.find((ref) => ref.kind === "env-file")?.value ?? "";
  const envVars = profile.env_refs
    .filter((ref) => ref.kind === "env-var")
    .map((ref) => ({ name: ref.value, value: "", secret: ref.secret }));
  return {
    mode: launchMode(profile.mode),
    target_base_url: target,
    readiness_kind: launchReadinessKind(target, httpCheck, commandCheck),
    health_check_url: httpCheck?.url ?? "",
    health_check_command: launchStepToDraft(commandCheck?.command ?? null),
    allowed_hosts: "",
    env_file: envFile,
    timeout_seconds:
      httpCheck?.timeout_seconds?.toString() ??
      commandCheck?.timeout_seconds?.toString() ??
      commandCheck?.command?.timeout_seconds?.toString() ??
      "",
    build_commands: launchStepDrafts(profile.build_steps),
    start_commands: launchStepDrafts(profile.start_steps),
    env_vars: envVars,
  };
}

export function launchProfileFromDraft(
  draft: RuntimeProfileDraft,
): ProjectLaunchProfileInput | undefined {
  const mode = draft.mode;
  const includeCommands = mode === "custom-commands";
  const build_steps = includeCommands
    ? draft.build_commands.map(launchStepFromDraft).filter(isDefined)
    : [];
  const start_steps = includeCommands
    ? draft.start_commands.map(launchStepFromDraft).filter(isDefined)
    : [];
  const target = trimOrUndefined(draft.target_base_url);
  const health_checks = launchHealthChecksFromDraft(draft, target);
  const env_refs: LaunchEnvRef[] = [];
  const envFile = trimOrUndefined(draft.env_file);
  if (envFile) env_refs.push({ kind: "env-file", value: envFile, secret: true });
  for (const env of draft.env_vars) {
    const name = trimOrUndefined(env.name);
    if (name) env_refs.push({ kind: "env-var", value: name, secret: env.secret });
  }
  const hasContent =
    build_steps.length > 0 ||
    start_steps.length > 0 ||
    health_checks.length > 0 ||
    Boolean(target) ||
    env_refs.length > 0;
  if (!hasContent) return undefined;
  return {
    name: "App",
    mode,
    build_steps,
    start_steps,
    stop_steps: [],
    health_checks,
    target_urls: target ? [target] : [],
    env_refs,
    working_dirs: [],
  };
}

interface Props {
  value: RuntimeProfileDraft;
  onChange: (next: RuntimeProfileDraft) => void;
}

export function ProjectRuntimeProfileForm({ value, onChange }: Props) {
  const setField = (field: keyof RuntimeProfileDraft) => (e: ChangeEvent<HTMLInputElement>) => {
    onChange({ ...value, [field]: e.target.value });
  };
  const reachability = useTargetReachability(value.target_base_url);
  const hasLaunchCommands =
    value.build_commands.some(hasCommandContent) || value.start_commands.some(hasCommandContent);
  const hasEnvironment =
    Boolean(trimOrUndefined(value.env_file)) ||
    value.env_vars.some((row) => Boolean(trimOrUndefined(row.name)));

  return (
    <div className="runtime-profile-form">
      <section className="runtime-profile-card runtime-profile-card--primary">
        <div className="runtime-profile-card__header">
          <h3>App</h3>
        </div>
        <div className="runtime-profile-grid">
          <div className="setup-field">
            <span className="runtime-profile-label">Launch mode</span>
            <SegmentedControl
              ariaLabel="Launch mode"
              options={LAUNCH_MODES}
              value={value.mode}
              onChange={(mode) => onChange({ ...value, mode })}
            />
          </div>
          <div className="setup-field">
            <label htmlFor="runtime-target-url">App URL</label>
            <input
              id="runtime-target-url"
              type="text"
              autoComplete="off"
              placeholder="http://localhost:3000"
              value={value.target_base_url}
              onChange={setField("target_base_url")}
            />
            <ReachabilityLine state={reachability} />
          </div>
        </div>

        <div className="runtime-profile-ready">
          <span className="runtime-profile-label">Ready when</span>
          <SegmentedControl
            ariaLabel="Ready when"
            options={READINESS_KINDS}
            value={value.readiness_kind}
            onChange={(readiness_kind) => onChange({ ...value, readiness_kind })}
          />
        </div>
        {value.readiness_kind === "custom-url" && (
          <div className="runtime-profile-grid runtime-profile-grid--inline">
            <div className="setup-field">
              <label htmlFor="runtime-health-url">Readiness URL</label>
              <input
                id="runtime-health-url"
                type="text"
                autoComplete="off"
                placeholder="http://localhost:3000/health"
                value={value.health_check_url}
                onChange={setField("health_check_url")}
              />
            </div>
            <TimeoutField
              id="runtime-timeout"
              label="Timeout"
              value={value.timeout_seconds}
              onChange={(timeout_seconds) => onChange({ ...value, timeout_seconds })}
            />
          </div>
        )}
        {value.readiness_kind === "command" && (
          <CommandFields
            prefix="runtime-health-command"
            index={0}
            row={value.health_check_command}
            commandLabel="Readiness command"
            onChange={(row) => onChange({ ...value, health_check_command: row })}
          />
        )}
      </section>

      {value.mode === "custom-commands" && (
        <details className="runtime-profile-details" open={hasLaunchCommands}>
          <summary>Launch commands</summary>
          <CommandRows
            title="Setup"
            prefix="runtime-setup"
            rows={value.build_commands}
            addLabel="Add setup command"
            onChange={(rows) => onChange({ ...value, build_commands: rows })}
          />
          <CommandRows
            title="Start"
            prefix="runtime-start"
            rows={value.start_commands}
            addLabel="Add start command"
            onChange={(rows) => onChange({ ...value, start_commands: rows })}
          />
        </details>
      )}

      <details className="runtime-profile-details" open={hasEnvironment}>
        <summary>Environment</summary>
        <div className="setup-field">
          <label htmlFor="runtime-env-file">Env file</label>
          <input
            id="runtime-env-file"
            type="text"
            autoComplete="off"
            placeholder=".env.test"
            value={value.env_file}
            onChange={setField("env_file")}
          />
        </div>
        <EnvRows
          rows={value.env_vars}
          onChange={(rows) => onChange({ ...value, env_vars: rows })}
        />
      </details>
    </div>
  );
}

function useTargetReachability(url: string): ReachabilityState {
  const [state, setState] = useState<ReachabilityState>({ status: "idle", message: "" });
  const seq = useRef(0);

  useEffect(() => {
    const trimmed = url.trim();
    const nextSeq = seq.current + 1;
    seq.current = nextSeq;

    if (!trimmed || !isBlankOrHttpUrl(trimmed)) {
      setState({ status: "idle", message: "" });
      return;
    }

    setState({ status: "checking", message: "Checking app URL..." });
    const timer = window.setTimeout(async () => {
      try {
        const result = await testLaunchTarget({ url: trimmed, timeout_seconds: 3 });
        if (seq.current !== nextSeq) return;
        setState({
          status: result.ok ? "reachable" : "unreachable",
          message: result.message,
        });
      } catch (err) {
        if (seq.current !== nextSeq) return;
        setState({
          status: "unreachable",
          message: err instanceof Error ? err.message : String(err),
        });
      }
    }, 600);

    return () => {
      window.clearTimeout(timer);
    };
  }, [url]);

  return state;
}

function ReachabilityLine({ state }: { state: ReachabilityState }) {
  if (state.status === "idle") return null;
  return (
    <p className={`runtime-url-status runtime-url-status--${state.status}`} aria-live="polite">
      {state.status === "checking" && "Checking..."}
      {state.status === "reachable" && "Reachable"}
      {state.status === "unreachable" && "Not reachable"}
      {state.message && <span>{state.message}</span>}
    </p>
  );
}

function SegmentedControl<T extends string>({
  ariaLabel,
  options,
  value,
  onChange,
}: {
  ariaLabel: string;
  options: Array<{ value: T; label: string }>;
  value: T;
  onChange: (next: T) => void;
}) {
  const name = ariaLabel.toLowerCase().replace(/\s+/g, "-");
  return (
    <fieldset className="runtime-segmented" aria-label={ariaLabel}>
      {options.map((option) => (
        <label
          key={option.value}
          className={`runtime-segmented__item${value === option.value ? " active" : ""}`}
        >
          <input
            type="radio"
            name={name}
            value={option.value}
            checked={value === option.value}
            onChange={() => onChange(option.value)}
          />
          {option.label}
        </label>
      ))}
    </fieldset>
  );
}

function CommandRows({
  title,
  prefix,
  rows,
  addLabel,
  onChange,
}: {
  title: string;
  prefix: string;
  rows: RuntimeCommandDraft[];
  addLabel: string;
  onChange: (rows: RuntimeCommandDraft[]) => void;
}) {
  return (
    <section className="runtime-profile-subsection" aria-labelledby={`${prefix}-title`}>
      <div className="runtime-profile-section__header">
        <h4 id={`${prefix}-title`}>{title}</h4>
        <Button size="sm" variant="ghost" onClick={() => onChange([...rows, blankCommand()])}>
          {addLabel}
        </Button>
      </div>
      {rows.length > 0 && (
        <div className="runtime-profile-list">
          {rows.map((row, index) => (
            <div className="runtime-profile-row" key={`${prefix}-${index}`}>
              <CommandFields
                prefix={prefix}
                index={index}
                row={row}
                commandLabel={`${title} command ${index + 1}`}
                onChange={(next) => onChange(replaceAt(rows, index, next))}
              />
              <Button
                size="sm"
                variant="ghost"
                className="runtime-profile-row__remove"
                onClick={() => onChange(rows.filter((_, i) => i !== index))}
              >
                Remove
              </Button>
            </div>
          ))}
        </div>
      )}
    </section>
  );
}

function CommandFields({
  prefix,
  index,
  row,
  commandLabel,
  onChange,
}: {
  prefix: string;
  index: number;
  row: RuntimeCommandDraft;
  commandLabel: string;
  onChange: (row: RuntimeCommandDraft) => void;
}) {
  const set = (field: keyof RuntimeCommandDraft) => (e: ChangeEvent<HTMLInputElement>) =>
    onChange({ ...row, [field]: e.target.value });

  return (
    <div className="runtime-command-fields">
      <div className="setup-field runtime-command-fields__command">
        <label htmlFor={`${prefix}-command-${index}`}>{commandLabel}</label>
        <input
          id={`${prefix}-command-${index}`}
          type="text"
          autoComplete="off"
          placeholder={commandLabel.startsWith("Setup") ? "npm ci" : "npm run dev"}
          value={row.command}
          onChange={set("command")}
        />
      </div>
      <details className="runtime-command-advanced">
        <summary>Advanced</summary>
        <div className="runtime-command-advanced__grid">
          <div className="setup-field">
            <label htmlFor={`${prefix}-repo-${index}`}>Code source</label>
            <input
              id={`${prefix}-repo-${index}`}
              type="text"
              autoComplete="off"
              placeholder="website"
              value={row.repo_name}
              onChange={set("repo_name")}
            />
          </div>
          <div className="setup-field">
            <label htmlFor={`${prefix}-working-directory-${index}`}>Working dir</label>
            <input
              id={`${prefix}-working-directory-${index}`}
              type="text"
              autoComplete="off"
              placeholder="apps/web"
              value={row.working_directory}
              onChange={set("working_directory")}
            />
          </div>
          <TimeoutField
            id={`${prefix}-timeout-${index}`}
            label="Timeout"
            value={row.timeout_seconds}
            onChange={(timeout_seconds) => onChange({ ...row, timeout_seconds })}
          />
        </div>
      </details>
    </div>
  );
}

function TimeoutField({
  id,
  label,
  value,
  onChange,
}: {
  id: string;
  label: string;
  value: string;
  onChange: (next: string) => void;
}) {
  return (
    <div className="setup-field runtime-timeout-field">
      <label htmlFor={id}>{label}</label>
      <input
        id={id}
        type="number"
        min="1"
        inputMode="numeric"
        placeholder="60"
        value={value}
        onChange={(e) => onChange(e.target.value)}
      />
    </div>
  );
}

function EnvRows({
  rows,
  onChange,
}: {
  rows: RuntimeEnvDraft[];
  onChange: (rows: RuntimeEnvDraft[]) => void;
}) {
  return (
    <div className="runtime-profile-list">
      <div className="runtime-profile-section__header">
        <h4>Env variables</h4>
        <Button size="sm" variant="ghost" onClick={() => onChange([...rows, blankEnv()])}>
          Add variable
        </Button>
      </div>
      {rows.map((row, index) => (
        <div className="runtime-env-row" key={`runtime-env-${index}`}>
          <div className="setup-field">
            <label htmlFor={`runtime-env-name-${index}`}>Name</label>
            <input
              id={`runtime-env-name-${index}`}
              type="text"
              autoComplete="off"
              placeholder="NODE_ENV"
              value={row.name}
              onChange={(e) => onChange(replaceAt(rows, index, { ...row, name: e.target.value }))}
            />
          </div>
          <div className="setup-field">
            <label htmlFor={`runtime-env-value-${index}`}>Value</label>
            <input
              id={`runtime-env-value-${index}`}
              type={row.secret ? "password" : "text"}
              autoComplete="off"
              placeholder="test"
              value={row.value}
              onChange={(e) => onChange(replaceAt(rows, index, { ...row, value: e.target.value }))}
            />
          </div>
          <label className="runtime-env-row__secret">
            <input
              type="checkbox"
              checked={row.secret}
              onChange={(e) =>
                onChange(replaceAt(rows, index, { ...row, secret: e.target.checked }))
              }
            />
            Secret
          </label>
          <Button
            size="sm"
            variant="ghost"
            className="runtime-profile-row__remove"
            onClick={() => onChange(rows.filter((_, i) => i !== index))}
          >
            Remove
          </Button>
        </div>
      ))}
    </div>
  );
}

function commandDrafts(commands: ProjectRuntimeCommand[]): RuntimeCommandDraft[] {
  return commands.map(commandToDraft);
}

function envDrafts(vars: ProjectRuntimeEnvVar[]): RuntimeEnvDraft[] {
  return vars.map((v) => ({
    name: v.name,
    value: v.value,
    secret: v.secret,
  }));
}

function commandToDraft(command: ProjectRuntimeCommand | null): RuntimeCommandDraft {
  if (!command) return blankCommand();
  return {
    command: command.command,
    repo_name: command.repo_name ?? "",
    working_directory: command.working_directory ?? "",
    timeout_seconds: command.timeout_seconds?.toString() ?? "",
  };
}

function commandFromDraft(draft: RuntimeCommandDraft): ProjectRuntimeCommand | undefined {
  const command = trimOrUndefined(draft.command);
  if (!command) return undefined;
  const out: ProjectRuntimeCommand = { command };
  const repo_name = trimOrUndefined(draft.repo_name);
  const working_directory = trimOrUndefined(draft.working_directory);
  const timeout_seconds = positiveIntOrUndefined(draft.timeout_seconds);
  if (repo_name) out.repo_name = repo_name;
  if (working_directory) out.working_directory = working_directory;
  if (timeout_seconds !== undefined) out.timeout_seconds = timeout_seconds;
  return out;
}

function launchStepFromDraft(draft: RuntimeCommandDraft): LaunchStep | undefined {
  const command = trimOrUndefined(draft.command);
  if (!command) return undefined;
  const out: LaunchStep = { command };
  const repo_name = trimOrUndefined(draft.repo_name);
  const working_directory = trimOrUndefined(draft.working_directory);
  const timeout_seconds = positiveIntOrUndefined(draft.timeout_seconds);
  if (repo_name) out.repo_name = repo_name;
  if (working_directory) out.working_directory = working_directory;
  if (timeout_seconds !== undefined) out.timeout_seconds = timeout_seconds;
  return out;
}

function launchStepToDraft(step: LaunchStep | null): RuntimeCommandDraft {
  if (!step) return blankCommand();
  return {
    command: step.command,
    repo_name: step.repo_name ?? "",
    working_directory: step.working_directory ?? "",
    timeout_seconds: step.timeout_seconds?.toString() ?? "",
  };
}

function launchStepDrafts(steps: LaunchStep[]): RuntimeCommandDraft[] {
  return steps.map(launchStepToDraft);
}

function envFromDraft(draft: RuntimeEnvDraft): ProjectRuntimeEnvVar | undefined {
  const name = trimOrUndefined(draft.name);
  if (!name) return undefined;
  return {
    name,
    value: draft.value.trim(),
    secret: draft.secret,
  };
}

function launchHealthChecksFromDraft(
  draft: RuntimeProfileDraft,
  target: string | undefined,
): LaunchHealthCheck[] {
  const timeout = positiveIntOrUndefined(draft.timeout_seconds);
  if (draft.readiness_kind === "skip") return [];
  if (draft.readiness_kind === "target-url" && target) {
    return [{ kind: "http", url: target, timeout_seconds: timeout }];
  }
  if (draft.readiness_kind === "custom-url") {
    const url = trimOrUndefined(draft.health_check_url);
    return url ? [{ kind: "http", url, timeout_seconds: timeout }] : [];
  }
  const command = launchStepFromDraft(draft.health_check_command);
  if (!command) return [];
  return [
    {
      kind: "command",
      command,
      timeout_seconds: command.timeout_seconds ?? timeout,
    },
  ];
}

function runtimeHealthUrlFromDraft(
  draft: RuntimeProfileDraft,
  target: string | undefined,
): string | undefined {
  if (draft.readiness_kind === "target-url") return target;
  if (draft.readiness_kind === "custom-url") return trimOrUndefined(draft.health_check_url);
  return undefined;
}

function runtimeReadinessKind(profile: ProjectRuntimeProfile, target: string): ReadinessKind {
  if (profile.health_check_command) return "command";
  if (!profile.health_check_url) return "target-url";
  return sameTrimmed(profile.health_check_url, target) ? "target-url" : "custom-url";
}

function launchReadinessKind(
  target: string,
  httpCheck: LaunchHealthCheck | undefined,
  commandCheck: LaunchHealthCheck | undefined,
): ReadinessKind {
  if (commandCheck) return "command";
  if (!httpCheck?.url) return "target-url";
  return sameTrimmed(httpCheck.url, target) ? "target-url" : "custom-url";
}

function launchMode(input: string | null | undefined): LaunchMode {
  if (input === "docker-compose") return "docker-compose";
  if (input === "custom-commands") return "custom-commands";
  return "already-running";
}

function splitList(input: string): string[] {
  const seen = new Set<string>();
  const out: string[] = [];
  for (const part of input.split(/[,\n]/)) {
    const trimmed = part.trim();
    if (!trimmed || seen.has(trimmed)) continue;
    seen.add(trimmed);
    out.push(trimmed);
  }
  return out;
}

function trimOrUndefined(input: string | null | undefined): string | undefined {
  const trimmed = input?.trim() ?? "";
  return trimmed.length > 0 ? trimmed : undefined;
}

function positiveIntOrUndefined(input: string): number | undefined {
  const trimmed = input.trim();
  if (!trimmed) return undefined;
  const parsed = Number.parseInt(trimmed, 10);
  return Number.isFinite(parsed) && parsed > 0 ? parsed : undefined;
}

function isBlankOrHttpUrl(input: string): boolean {
  const trimmed = input.trim();
  return trimmed.length === 0 || /^https?:\/\//.test(trimmed);
}

function isInvalidPositiveInteger(input: string): boolean {
  const trimmed = input.trim();
  if (!trimmed) return false;
  return !/^[1-9]\d*$/.test(trimmed);
}

function isDefined<T>(value: T | undefined): value is T {
  return value !== undefined;
}

function hasCommandContent(row: RuntimeCommandDraft): boolean {
  return Boolean(
    trimOrUndefined(row.command) ||
      trimOrUndefined(row.repo_name) ||
      trimOrUndefined(row.working_directory) ||
      trimOrUndefined(row.timeout_seconds),
  );
}

function sameTrimmed(a: string | null | undefined, b: string | null | undefined): boolean {
  return (a ?? "").trim() === (b ?? "").trim();
}

function replaceAt<T>(items: T[], index: number, next: T): T[] {
  return items.map((item, i) => (i === index ? next : item));
}

import { type ChangeEvent } from "react";
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
import { Button } from "@/components/Button";

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
  target_base_url: string;
  health_check_url: string;
  health_check_command: RuntimeCommandDraft;
  allowed_hosts: string;
  env_file: string;
  timeout_seconds: string;
  build_commands: RuntimeCommandDraft[];
  start_commands: RuntimeCommandDraft[];
  env_vars: RuntimeEnvDraft[];
}

const blankCommand = (): RuntimeCommandDraft => ({
  command: "",
  repo_name: "",
  working_directory: "",
  timeout_seconds: "",
});

const blankEnv = (): RuntimeEnvDraft => ({ name: "", value: "", secret: false });

export function emptyRuntimeProfileDraft(targetBaseUrl = ""): RuntimeProfileDraft {
  return {
    target_base_url: targetBaseUrl,
    health_check_url: "",
    health_check_command: blankCommand(),
    allowed_hosts: "",
    env_file: "",
    timeout_seconds: "",
    build_commands: [blankCommand()],
    start_commands: [blankCommand()],
    env_vars: [blankEnv()],
  };
}

export function runtimeProfileToDraft(
  profile: ProjectRuntimeProfile | null | undefined,
  fallbackTargetBaseUrl = "",
): RuntimeProfileDraft {
  if (!profile) return emptyRuntimeProfileDraft(fallbackTargetBaseUrl);
  return {
    target_base_url: profile.target_base_url ?? fallbackTargetBaseUrl,
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
  const health_check_command = commandFromDraft(draft.health_check_command);
  const allowed_hosts = splitList(draft.allowed_hosts);
  const env_vars = draft.env_vars.map(envFromDraft).filter(isDefined);
  const target_base_url = trimOrUndefined(draft.target_base_url);
  const health_check_url = trimOrUndefined(draft.health_check_url);
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
    return "Runtime target base URL must start with http:// or https://";
  }
  if (!isBlankOrHttpUrl(draft.health_check_url)) {
    return "Health check URL must start with http:// or https://";
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
  const httpCheck = profile.health_checks.find((check) => check.kind === "http" && check.url);
  const commandCheck = profile.health_checks.find((check) => check.kind === "command");
  const envFile = profile.env_refs.find((ref) => ref.kind === "env-file")?.value ?? "";
  const envVars = profile.env_refs
    .filter((ref) => ref.kind === "env-var")
    .map((ref) => ({ name: ref.value, value: "", secret: ref.secret }));
  return {
    target_base_url: profile.target_urls[0] ?? fallbackTargetBaseUrl,
    health_check_url: httpCheck?.url ?? "",
    health_check_command: launchStepToDraft(commandCheck?.command ?? null),
    allowed_hosts: "",
    env_file: envFile,
    timeout_seconds: "",
    build_commands: launchStepDrafts(profile.build_steps),
    start_commands: launchStepDrafts(profile.start_steps),
    env_vars: envVars.length > 0 ? envVars : [blankEnv()],
  };
}

export function launchProfileFromDraft(
  draft: RuntimeProfileDraft,
): ProjectLaunchProfileInput | undefined {
  const build_steps = draft.build_commands.map(launchStepFromDraft).filter(isDefined);
  const start_steps = draft.start_commands.map(launchStepFromDraft).filter(isDefined);
  const health_checks: LaunchHealthCheck[] = [];
  const healthUrl = trimOrUndefined(draft.health_check_url);
  if (healthUrl) {
    health_checks.push({
      kind: "http",
      url: healthUrl,
      timeout_seconds: positiveIntOrUndefined(draft.timeout_seconds),
    });
  }
  const commandCheck = launchStepFromDraft(draft.health_check_command);
  if (commandCheck) {
    health_checks.push({
      kind: "command",
      command: commandCheck,
      timeout_seconds:
        commandCheck.timeout_seconds ?? positiveIntOrUndefined(draft.timeout_seconds),
    });
  }
  const target = trimOrUndefined(draft.target_base_url);
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
    name: "local dev",
    mode: "custom-commands",
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

  return (
    <div className="runtime-profile-form">
      <section className="runtime-profile-section" aria-labelledby="runtime-target-title">
        <h3 id="runtime-target-title">Target and health</h3>
        <div className="runtime-profile-grid">
          <div className="setup-field">
            <label htmlFor="runtime-target-url">Runtime target base URL</label>
            <input
              id="runtime-target-url"
              type="text"
              autoComplete="off"
              placeholder="http://localhost:3000"
              value={value.target_base_url}
              onChange={setField("target_base_url")}
            />
          </div>
          <div className="setup-field">
            <label htmlFor="runtime-health-url">Health check URL</label>
            <input
              id="runtime-health-url"
              type="text"
              autoComplete="off"
              placeholder="http://localhost:3000/health"
              value={value.health_check_url}
              onChange={setField("health_check_url")}
            />
          </div>
        </div>
        <div className="runtime-profile-grid runtime-profile-grid--narrow">
          <div className="setup-field">
            <label htmlFor="runtime-timeout">Default timeout seconds</label>
            <input
              id="runtime-timeout"
              type="number"
              min="1"
              inputMode="numeric"
              placeholder="300"
              value={value.timeout_seconds}
              onChange={setField("timeout_seconds")}
            />
          </div>
          <div className="setup-field">
            <label htmlFor="runtime-allowed-hosts">Allowed hosts</label>
            <textarea
              id="runtime-allowed-hosts"
              rows={3}
              placeholder={"localhost\n127.0.0.1"}
              value={value.allowed_hosts}
              onChange={(e) => onChange({ ...value, allowed_hosts: e.target.value })}
            />
          </div>
        </div>
      </section>

      <CommandRows
        title="Build commands"
        prefix="runtime-build"
        rows={value.build_commands}
        onChange={(rows) => onChange({ ...value, build_commands: rows })}
      />

      <CommandRows
        title="Start commands"
        prefix="runtime-start"
        rows={value.start_commands}
        onChange={(rows) => onChange({ ...value, start_commands: rows })}
      />

      <section className="runtime-profile-section" aria-labelledby="runtime-health-command-title">
        <h3 id="runtime-health-command-title">Health check command</h3>
        <CommandFields
          prefix="runtime-health-command"
          index={0}
          row={value.health_check_command}
          commandLabel="Health check command"
          onChange={(row) => onChange({ ...value, health_check_command: row })}
        />
      </section>

      <section className="runtime-profile-section" aria-labelledby="runtime-env-title">
        <h3 id="runtime-env-title">Test environment</h3>
        <div className="setup-field">
          <label htmlFor="runtime-env-file">Env file path</label>
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
      </section>
    </div>
  );
}

function CommandRows({
  title,
  prefix,
  rows,
  onChange,
}: {
  title: string;
  prefix: string;
  rows: RuntimeCommandDraft[];
  onChange: (rows: RuntimeCommandDraft[]) => void;
}) {
  const safeRows = rows.length > 0 ? rows : [blankCommand()];
  return (
    <section className="runtime-profile-section" aria-labelledby={`${prefix}-title`}>
      <div className="runtime-profile-section__header">
        <h3 id={`${prefix}-title`}>{title}</h3>
        <Button size="sm" variant="ghost" onClick={() => onChange([...safeRows, blankCommand()])}>
          Add command
        </Button>
      </div>
      <div className="runtime-profile-list">
        {safeRows.map((row, index) => (
          <div className="runtime-profile-row" key={`${prefix}-${index}`}>
            <CommandFields
              prefix={prefix}
              index={index}
              row={row}
              commandLabel={`${title.slice(0, -1)} ${index + 1}`}
              onChange={(next) => onChange(replaceAt(safeRows, index, next))}
            />
            {safeRows.length > 1 && (
              <Button
                size="sm"
                variant="ghost"
                className="runtime-profile-row__remove"
                onClick={() => onChange(safeRows.filter((_, i) => i !== index))}
              >
                Remove
              </Button>
            )}
          </div>
        ))}
      </div>
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
          placeholder="npm run dev"
          value={row.command}
          onChange={set("command")}
        />
      </div>
      <div className="setup-field">
        <label htmlFor={`${prefix}-repo-${index}`}>Repo</label>
        <input
          id={`${prefix}-repo-${index}`}
          type="text"
          autoComplete="off"
          placeholder="frontend"
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
      <div className="setup-field">
        <label htmlFor={`${prefix}-timeout-${index}`}>Timeout</label>
        <input
          id={`${prefix}-timeout-${index}`}
          type="number"
          min="1"
          inputMode="numeric"
          placeholder="120"
          value={row.timeout_seconds}
          onChange={set("timeout_seconds")}
        />
      </div>
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
  const safeRows = rows.length > 0 ? rows : [blankEnv()];
  return (
    <div className="runtime-profile-list">
      <div className="runtime-profile-section__header">
        <h4>Env variables</h4>
        <Button size="sm" variant="ghost" onClick={() => onChange([...safeRows, blankEnv()])}>
          Add variable
        </Button>
      </div>
      {safeRows.map((row, index) => (
        <div className="runtime-env-row" key={`runtime-env-${index}`}>
          <div className="setup-field">
            <label htmlFor={`runtime-env-name-${index}`}>Name</label>
            <input
              id={`runtime-env-name-${index}`}
              type="text"
              autoComplete="off"
              placeholder="NODE_ENV"
              value={row.name}
              onChange={(e) =>
                onChange(replaceAt(safeRows, index, { ...row, name: e.target.value }))
              }
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
              onChange={(e) =>
                onChange(replaceAt(safeRows, index, { ...row, value: e.target.value }))
              }
            />
          </div>
          <label className="runtime-env-row__secret">
            <input
              type="checkbox"
              checked={row.secret}
              onChange={(e) =>
                onChange(replaceAt(safeRows, index, { ...row, secret: e.target.checked }))
              }
            />
            Secret
          </label>
          {safeRows.length > 1 && (
            <Button
              size="sm"
              variant="ghost"
              className="runtime-profile-row__remove"
              onClick={() => onChange(safeRows.filter((_, i) => i !== index))}
            >
              Remove
            </Button>
          )}
        </div>
      ))}
    </div>
  );
}

function commandDrafts(commands: ProjectRuntimeCommand[]): RuntimeCommandDraft[] {
  return commands.length > 0 ? commands.map(commandToDraft) : [blankCommand()];
}

function envDrafts(vars: ProjectRuntimeEnvVar[]): RuntimeEnvDraft[] {
  return vars.length > 0
    ? vars.map((v) => ({
        name: v.name,
        value: v.value,
        secret: v.secret,
      }))
    : [blankEnv()];
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
  return steps.length > 0 ? steps.map(launchStepToDraft) : [blankCommand()];
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

function replaceAt<T>(items: T[], index: number, next: T): T[] {
  return items.map((item, i) => (i === index ? next : item));
}

function isDefined<T>(value: T | undefined): value is T {
  return value !== undefined;
}

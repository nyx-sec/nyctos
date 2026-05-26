import { type ChangeEvent, type SyntheticEvent, useEffect, useRef, useState } from "react";
import type {
  LaunchEnvRef,
  LaunchHealthCheck,
  LaunchStep,
  ProjectAuthOwnedObject,
  ProjectAuthProfile,
  ProjectLaunchProfile,
  ProjectLaunchProfileInput,
  ProjectRuntimeCommand,
  ProjectRuntimeEnvVar,
  ProjectRuntimeProfile,
} from "@/api/client";
import { testLaunchTarget } from "@/api/client";
import { useAuthSetupJobs } from "@/components/AuthSetupJobs";
import { Button } from "@/components/Button";
import { Spinner } from "@/components/Spinner";
import { useToast } from "@/components/Toast";

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
  stdin: string;
}

export interface RuntimeEnvDraft {
  name: string;
  value: string;
  secret: boolean;
}

export type AuthMode =
  | "anonymous"
  | "header_injection"
  | "browser_login"
  | "manual_sso"
  | "session_import"
  | "otp_email_manual"
  | "otp_email_mailbox"
  | "ai_auto"
  | "oidc_device"
  | "custom_command";

export type OtpSourceKind = "manual" | "mailbox" | "imap";
export type AuthAssertionKind =
  | "url_contains"
  | "dom_text_contains"
  | "cookie_exists"
  | "http_status";

export interface AuthHeaderDraft {
  name: string;
  value_env: string;
}

export interface AuthAssertionDraft {
  kind: AuthAssertionKind;
  value: string;
  status: string;
}

export interface AuthOwnedObjectDraft {
  name: string;
  id: string;
  route: string;
  marker: string;
}

export interface AuthProfileDraft {
  role: string;
  mode: AuthMode;
  label: string;
  session_cache_ttl_seconds: string;
  session_import_path: string;
  login_url: string;
  username: string;
  username_env: string;
  login_email_env: string;
  password_env: string;
  cookie_env: string;
  bearer_token_env: string;
  headers: AuthHeaderDraft[];
  otp_source_kind: OtpSourceKind;
  otp_mailbox_url: string;
  otp_email_env: string;
  otp_subject_contains: string;
  otp_body_regex: string;
  post_login_assertion: string;
  post_login_assertions: AuthAssertionDraft[];
  custom_command: string;
  owned_objects: AuthOwnedObjectDraft[];
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
  seed_commands: RuntimeCommandDraft[];
  reset_commands: RuntimeCommandDraft[];
  login_commands: RuntimeCommandDraft[];
  stop_commands: RuntimeCommandDraft[];
  env_vars: RuntimeEnvDraft[];
  auth_profiles: AuthProfileDraft[];
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

const AUTH_MODE_OPTIONS: Array<{ value: AuthMode; label: string }> = [
  { value: "header_injection", label: "Headers" },
  { value: "browser_login", label: "Browser login" },
  { value: "manual_sso", label: "Manual SSO" },
  { value: "session_import", label: "Import session" },
  { value: "otp_email_manual", label: "Manual OTP" },
  { value: "otp_email_mailbox", label: "Mailbox OTP" },
  { value: "ai_auto", label: "AI auto" },
  { value: "oidc_device", label: "OIDC device" },
  { value: "custom_command", label: "Custom command" },
];

const ASSERTION_OPTIONS: Array<{ value: AuthAssertionKind; label: string }> = [
  { value: "cookie_exists", label: "Cookie exists" },
  { value: "http_status", label: "HTTP status" },
  { value: "url_contains", label: "URL contains" },
  { value: "dom_text_contains", label: "DOM text" },
];

const blankCommand = (): RuntimeCommandDraft => ({
  command: "",
  repo_name: "",
  working_directory: "",
  timeout_seconds: "",
  stdin: "",
});

const blankEnv = (): RuntimeEnvDraft => ({ name: "", value: "", secret: false });

const blankHeader = (): AuthHeaderDraft => ({ name: "", value_env: "" });

const blankAssertion = (): AuthAssertionDraft => ({
  kind: "cookie_exists",
  value: "",
  status: "",
});

const blankOwnedObject = (): AuthOwnedObjectDraft => ({
  name: "",
  id: "",
  route: "",
  marker: "",
});

const blankAuthProfile = (): AuthProfileDraft => ({
  role: "",
  mode: "header_injection",
  label: "",
  session_cache_ttl_seconds: "",
  session_import_path: "",
  login_url: "",
  username: "",
  username_env: "",
  login_email_env: "",
  password_env: "",
  cookie_env: "",
  bearer_token_env: "",
  headers: [],
  otp_source_kind: "manual",
  otp_mailbox_url: "",
  otp_email_env: "",
  otp_subject_contains: "",
  otp_body_regex: "",
  post_login_assertion: "",
  post_login_assertions: [],
  custom_command: "",
  owned_objects: [],
});

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
    seed_commands: [],
    reset_commands: [],
    login_commands: [],
    stop_commands: [],
    env_vars: [],
    auth_profiles: [],
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
    seed_commands: [],
    reset_commands: [],
    login_commands: [],
    stop_commands: [],
    env_vars: envDrafts(profile.env_vars ?? []),
    auth_profiles: authDrafts(profile.auth_profiles ?? []),
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
  const auth_profiles = draft.auth_profiles.map(authFromDraft).filter(isDefined);
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
    auth_profiles.length > 0 ||
    Boolean(env_file) ||
    timeout_seconds !== undefined;

  if (!hasContent) return undefined;

  const profile: ProjectRuntimeProfile = {
    build_commands,
    start_commands,
    allowed_hosts,
    env_vars,
    auth_profiles,
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
  const roles = draft.auth_profiles.map((p) => p.role.trim()).filter(Boolean);
  if (new Set(roles).size !== roles.length) {
    return "Auth profile roles must be unique";
  }
  if (draft.auth_profiles.some((p) => p.role.trim().toLowerCase() === "anonymous")) {
    return "Anonymous is built in; use a named role for auth profiles";
  }
  if (draft.auth_profiles.some((p) => isInvalidPositiveInteger(p.session_cache_ttl_seconds))) {
    return "Session TTL must be whole seconds greater than zero";
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
    seed_commands: launchStepDrafts(profile.seed_steps),
    reset_commands: launchStepDrafts(profile.reset_steps),
    login_commands: launchStepDrafts(profile.login_steps),
    stop_commands: launchStepDrafts(profile.stop_steps),
    env_vars: envVars,
    auth_profiles: [],
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
  const seed_steps = draft.seed_commands.map(launchStepFromDraft).filter(isDefined);
  const reset_steps = draft.reset_commands.map(launchStepFromDraft).filter(isDefined);
  const login_steps = draft.login_commands.map(launchStepFromDraft).filter(isDefined);
  const stop_steps = draft.stop_commands.map(launchStepFromDraft).filter(isDefined);
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
    seed_steps.length > 0 ||
    reset_steps.length > 0 ||
    login_steps.length > 0 ||
    stop_steps.length > 0 ||
    health_checks.length > 0 ||
    Boolean(target) ||
    env_refs.length > 0;
  if (!hasContent) return undefined;
  return {
    name: "App",
    mode,
    build_steps,
    start_steps,
    seed_steps,
    reset_steps,
    login_steps,
    stop_steps,
    health_checks,
    target_urls: target ? [target] : [],
    env_refs,
    working_dirs: [],
  };
}

interface Props {
  value: RuntimeProfileDraft;
  onChange: (next: RuntimeProfileDraft) => void;
  projectId?: string;
}

export function ProjectRuntimeProfileForm({ value, onChange, projectId }: Props) {
  const setField = (field: keyof RuntimeProfileDraft) => (e: ChangeEvent<HTMLInputElement>) => {
    onChange({ ...value, [field]: e.target.value });
  };
  const reachability = useTargetReachability(value.target_base_url);
  const hasLaunchCommands =
    value.build_commands.some(hasCommandContent) || value.start_commands.some(hasCommandContent);
  const hasLifecycleHooks =
    value.seed_commands.some(hasCommandContent) ||
    value.reset_commands.some(hasCommandContent) ||
    value.login_commands.some(hasCommandContent) ||
    value.stop_commands.some(hasCommandContent);
  const hasEnvironment =
    Boolean(trimOrUndefined(value.env_file)) ||
    value.env_vars.some((row) => Boolean(trimOrUndefined(row.name)));
  const hasAuthProfiles = value.auth_profiles.some((row) => Boolean(trimOrUndefined(row.role)));
  const [openSections, setOpenSections] = useState(() => ({
    launch: hasLaunchCommands,
    lifecycle: hasLifecycleHooks,
    environment: hasEnvironment,
    auth: hasAuthProfiles,
  }));

  useEffect(() => {
    setOpenSections({
      launch: hasLaunchCommands,
      lifecycle: hasLifecycleHooks,
      environment: hasEnvironment,
      auth: hasAuthProfiles,
    });
  }, [projectId]);

  const setSectionOpen =
    (section: keyof typeof openSections) => (event: SyntheticEvent<HTMLDetailsElement>) => {
      const open = event.currentTarget.open;
      setOpenSections((current) =>
        current[section] === open ? current : { ...current, [section]: open },
      );
    };

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
        <details
          className="runtime-profile-details"
          open={openSections.launch}
          onToggle={setSectionOpen("launch")}
        >
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

      <details
        className="runtime-profile-details"
        open={openSections.lifecycle}
        onToggle={setSectionOpen("lifecycle")}
      >
        <summary>Lifecycle hooks</summary>
        <CommandRows
          title="Seed"
          prefix="runtime-seed"
          rows={value.seed_commands}
          addLabel="Add seed command"
          onChange={(rows) => onChange({ ...value, seed_commands: rows })}
        />
        <CommandRows
          title="Login"
          prefix="runtime-login"
          rows={value.login_commands}
          addLabel="Add login command"
          onChange={(rows) => onChange({ ...value, login_commands: rows })}
        />
        <CommandRows
          title="Reset"
          prefix="runtime-reset"
          rows={value.reset_commands}
          addLabel="Add reset command"
          onChange={(rows) => onChange({ ...value, reset_commands: rows })}
        />
        <CommandRows
          title="Stop"
          prefix="runtime-stop"
          rows={value.stop_commands}
          addLabel="Add stop command"
          onChange={(rows) => onChange({ ...value, stop_commands: rows })}
        />
      </details>

      <details
        className="runtime-profile-details"
        open={openSections.environment}
        onToggle={setSectionOpen("environment")}
      >
        <summary>Environment</summary>
        <div className="runtime-profile-env">
          <div className="setup-field">
            <label htmlFor="runtime-env-file">Env file path</label>
            <input
              id="runtime-env-file"
              type="text"
              autoComplete="off"
              placeholder=".env.dev"
              value={value.env_file}
              onChange={setField("env_file")}
            />
          </div>
          <EnvRows
            rows={value.env_vars}
            onChange={(rows) => onChange({ ...value, env_vars: rows })}
          />
        </div>
      </details>

      <details
        className="runtime-profile-details"
        open={openSections.auth}
        onToggle={setSectionOpen("auth")}
      >
        <summary>Auth profiles</summary>
        <AuthProfileRows
          rows={value.auth_profiles}
          projectId={projectId}
          targetBaseUrl={value.target_base_url}
          onAuthSetupApplied={(profile) => {
            const applied = runtimeProfileToDraft(profile, value.target_base_url);
            onChange({
              ...value,
              env_vars: applied.env_vars,
              auth_profiles: applied.auth_profiles,
            });
          }}
          onChange={(rows) => onChange({ ...value, auth_profiles: rows })}
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
  const set =
    (field: keyof RuntimeCommandDraft) =>
    (e: ChangeEvent<HTMLInputElement | HTMLTextAreaElement>) =>
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
          <div className="setup-field runtime-command-advanced__stdin">
            <label htmlFor={`${prefix}-stdin-${index}`}>Stdin</label>
            <textarea
              id={`${prefix}-stdin-${index}`}
              rows={2}
              spellCheck={false}
              placeholder={"y\\n"}
              value={row.stdin}
              onChange={set("stdin")}
            />
          </div>
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
        <h4>Forwarded env vars</h4>
        <Button size="sm" variant="ghost" onClick={() => onChange([...rows, blankEnv()])}>
          Add variable
        </Button>
      </div>
      {rows.map((row, index) => (
        <div className="runtime-env-row" key={`runtime-env-${index}`}>
          <div className="setup-field">
            <label htmlFor={`runtime-env-name-${index}`}>Variable name</label>
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
              placeholder={row.secret ? "Secret value" : "value"}
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

function AuthProfileRows({
  rows,
  projectId,
  targetBaseUrl,
  onAuthSetupApplied,
  onChange,
}: {
  rows: AuthProfileDraft[];
  projectId?: string;
  targetBaseUrl: string;
  onAuthSetupApplied: (profile: ProjectRuntimeProfile | null | undefined) => void;
  onChange: (rows: AuthProfileDraft[]) => void;
}) {
  const update = (index: number, patch: Partial<AuthProfileDraft>) =>
    onChange(replaceAt(rows, index, { ...rows[index], ...patch }));
  const { jobForProject, startAuthSetup } = useAuthSetupJobs();
  const { showToast } = useToast();
  const authSetupJob = jobForProject(projectId);
  const authSetupRunning = authSetupJob?.status === "queued" || authSetupJob?.status === "running";
  const appliedJobId = useRef<string | null>(null);

  useEffect(() => {
    if (
      authSetupJob?.status !== "succeeded" ||
      !authSetupJob.result ||
      appliedJobId.current === authSetupJob.id
    ) {
      return;
    }
    appliedJobId.current = authSetupJob.id;
    onAuthSetupApplied(authSetupJob.result.project.runtime_profile);
  }, [authSetupJob, onAuthSetupApplied]);

  async function runAuthSetup() {
    if (!projectId) {
      showToast("Save the project before running auth setup.", { tone: "warning" });
      return;
    }
    try {
      const seeded_objects = rows
        .flatMap((row) => row.owned_objects)
        .map(ownedObjectFromDraft)
        .filter(isDefined);
      await startAuthSetup(projectId, {
        target_base_url: trimOrUndefined(targetBaseUrl),
        seeded_objects,
      });
    } catch (err) {
      showToast(`Could not start auth setup: ${err instanceof Error ? err.message : String(err)}`, {
        tone: "danger",
      });
    }
  }

  return (
    <div className="runtime-profile-list">
      <div className="runtime-profile-section__header">
        <div>
          <h4>Roles</h4>
          <p className="runtime-profile-note">Secrets use env refs only.</p>
        </div>
        <div className="runtime-profile-actions">
          <Button
            size="sm"
            variant="ghost"
            onClick={runAuthSetup}
            disabled={authSetupRunning || !projectId}
          >
            {authSetupRunning ? <Spinner /> : "Explore repo"}
          </Button>
          <Button size="sm" variant="ghost" onClick={() => onChange([...rows, blankAuthProfile()])}>
            Add role
          </Button>
        </div>
      </div>
      {authSetupJob ? (
        <p className="runtime-profile-note" role="status">
          {authSetupJob.status === "failed" && authSetupJob.error
            ? `${authSetupJob.error.title}: ${authSetupJob.error.detail}`
            : authSetupJob.message}
        </p>
      ) : null}
      {rows.map((row, index) => (
        <div className="runtime-auth-row" key={`runtime-auth-${index}`}>
          <div className="setup-field">
            <label htmlFor={`runtime-auth-role-${index}`}>Role</label>
            <input
              id={`runtime-auth-role-${index}`}
              type="text"
              autoComplete="off"
              placeholder="user_a"
              value={row.role}
              onChange={(e) => update(index, { role: e.target.value })}
            />
          </div>
          <div className="setup-field">
            <label htmlFor={`runtime-auth-mode-${index}`}>Mode</label>
            <select
              id={`runtime-auth-mode-${index}`}
              value={row.mode}
              onChange={(e) => update(index, { mode: e.target.value as AuthMode })}
            >
              {AUTH_MODE_OPTIONS.map((option) => (
                <option key={option.value} value={option.value}>
                  {option.label}
                </option>
              ))}
            </select>
          </div>
          <TimeoutField
            id={`runtime-auth-ttl-${index}`}
            label="Session TTL"
            value={row.session_cache_ttl_seconds}
            onChange={(session_cache_ttl_seconds) => update(index, { session_cache_ttl_seconds })}
          />

          {row.mode === "session_import" && (
            <div className="setup-field">
              <label htmlFor={`runtime-auth-import-${index}`}>Session path</label>
              <input
                id={`runtime-auth-import-${index}`}
                type="text"
                autoComplete="off"
                placeholder="sessions/user_a.json"
                value={row.session_import_path}
                onChange={(e) => update(index, { session_import_path: e.target.value })}
              />
            </div>
          )}

          {authModeUsesLogin(row.mode) && (
            <div className="setup-field">
              <label htmlFor={`runtime-auth-login-${index}`}>Login URL</label>
              <input
                id={`runtime-auth-login-${index}`}
                type="text"
                autoComplete="off"
                placeholder="/login"
                value={row.login_url}
                onChange={(e) => update(index, { login_url: e.target.value })}
              />
            </div>
          )}

          {authModeUsesLogin(row.mode) && row.mode !== "manual_sso" && (
            <>
              <div className="setup-field">
                <label htmlFor={`runtime-auth-username-env-${index}`}>Username env</label>
                <input
                  id={`runtime-auth-username-env-${index}`}
                  type="text"
                  autoComplete="off"
                  placeholder="NYX_AGENT_USER_A_EMAIL"
                  value={row.username_env}
                  onChange={(e) => update(index, { username_env: e.target.value })}
                />
              </div>
              <div className="setup-field">
                <label htmlFor={`runtime-auth-password-env-${index}`}>Password env</label>
                <input
                  id={`runtime-auth-password-env-${index}`}
                  type="text"
                  autoComplete="off"
                  placeholder="NYX_AGENT_USER_A_PASSWORD"
                  value={row.password_env}
                  onChange={(e) => update(index, { password_env: e.target.value })}
                />
              </div>
            </>
          )}

          {row.mode === "header_injection" && (
            <>
              <div className="setup-field">
                <label htmlFor={`runtime-auth-cookie-env-${index}`}>Cookie env</label>
                <input
                  id={`runtime-auth-cookie-env-${index}`}
                  type="text"
                  autoComplete="off"
                  placeholder="NYX_AGENT_USER_A_COOKIE"
                  value={row.cookie_env}
                  onChange={(e) => update(index, { cookie_env: e.target.value })}
                />
              </div>
              <div className="setup-field">
                <label htmlFor={`runtime-auth-bearer-env-${index}`}>Bearer env</label>
                <input
                  id={`runtime-auth-bearer-env-${index}`}
                  type="text"
                  autoComplete="off"
                  placeholder="NYX_AGENT_USER_A_TOKEN"
                  value={row.bearer_token_env}
                  onChange={(e) => update(index, { bearer_token_env: e.target.value })}
                />
              </div>
            </>
          )}

          {row.mode === "otp_email_mailbox" && (
            <>
              <div className="setup-field">
                <label htmlFor={`runtime-auth-otp-mailbox-${index}`}>Mailbox URL</label>
                <input
                  id={`runtime-auth-otp-mailbox-${index}`}
                  type="text"
                  autoComplete="off"
                  placeholder="http://127.0.0.1:8025"
                  value={row.otp_mailbox_url}
                  onChange={(e) => update(index, { otp_mailbox_url: e.target.value })}
                />
              </div>
              <div className="setup-field">
                <label htmlFor={`runtime-auth-otp-email-${index}`}>Email env</label>
                <input
                  id={`runtime-auth-otp-email-${index}`}
                  type="text"
                  autoComplete="off"
                  placeholder="NYX_AGENT_USER_A_EMAIL"
                  value={row.otp_email_env}
                  onChange={(e) => update(index, { otp_email_env: e.target.value })}
                />
              </div>
              <div className="setup-field">
                <label htmlFor={`runtime-auth-otp-subject-${index}`}>Subject contains</label>
                <input
                  id={`runtime-auth-otp-subject-${index}`}
                  type="text"
                  autoComplete="off"
                  placeholder="login code"
                  value={row.otp_subject_contains}
                  onChange={(e) => update(index, { otp_subject_contains: e.target.value })}
                />
              </div>
            </>
          )}

          {row.mode === "custom_command" && (
            <div className="setup-field runtime-auth-row__wide">
              <label htmlFor={`runtime-auth-custom-command-${index}`}>Command</label>
              <input
                id={`runtime-auth-custom-command-${index}`}
                type="text"
                autoComplete="off"
                placeholder="scripts/nyx-agent-auth-session"
                value={row.custom_command}
                onChange={(e) => update(index, { custom_command: e.target.value })}
              />
            </div>
          )}

          <HeaderRows
            rows={row.headers}
            prefix={`runtime-auth-header-${index}`}
            onChange={(headers) => update(index, { headers })}
          />
          <AssertionRows
            rows={row.post_login_assertions}
            prefix={`runtime-auth-assertion-${index}`}
            onChange={(post_login_assertions) => update(index, { post_login_assertions })}
          />
          <OwnedObjectRows
            rows={row.owned_objects}
            prefix={`runtime-auth-owned-object-${index}`}
            onChange={(owned_objects) => update(index, { owned_objects })}
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
  );
}

function HeaderRows({
  rows,
  prefix,
  onChange,
}: {
  rows: AuthHeaderDraft[];
  prefix: string;
  onChange: (rows: AuthHeaderDraft[]) => void;
}) {
  return (
    <details className="runtime-auth-advanced">
      <summary>Headers</summary>
      <div className="runtime-auth-nested-list">
        <Button size="sm" variant="ghost" onClick={() => onChange([...rows, blankHeader()])}>
          Add header
        </Button>
        {rows.map((row, index) => (
          <div className="runtime-auth-nested-row" key={`${prefix}-${index}`}>
            <div className="setup-field">
              <label htmlFor={`${prefix}-name-${index}`}>Name</label>
              <input
                id={`${prefix}-name-${index}`}
                type="text"
                autoComplete="off"
                placeholder="X-Test-Role"
                value={row.name}
                onChange={(e) => onChange(replaceAt(rows, index, { ...row, name: e.target.value }))}
              />
            </div>
            <div className="setup-field">
              <label htmlFor={`${prefix}-env-${index}`}>Value env</label>
              <input
                id={`${prefix}-env-${index}`}
                type="text"
                autoComplete="off"
                placeholder="NYX_AGENT_USER_A_ROLE"
                value={row.value_env}
                onChange={(e) =>
                  onChange(replaceAt(rows, index, { ...row, value_env: e.target.value }))
                }
              />
            </div>
            <Button
              size="sm"
              variant="ghost"
              onClick={() => onChange(rows.filter((_, i) => i !== index))}
            >
              Remove
            </Button>
          </div>
        ))}
      </div>
    </details>
  );
}

function AssertionRows({
  rows,
  prefix,
  onChange,
}: {
  rows: AuthAssertionDraft[];
  prefix: string;
  onChange: (rows: AuthAssertionDraft[]) => void;
}) {
  return (
    <details className="runtime-auth-advanced">
      <summary>Assertions</summary>
      <div className="runtime-auth-nested-list">
        <Button size="sm" variant="ghost" onClick={() => onChange([...rows, blankAssertion()])}>
          Add assertion
        </Button>
        {rows.map((row, index) => (
          <div className="runtime-auth-nested-row" key={`${prefix}-${index}`}>
            <div className="setup-field">
              <label htmlFor={`${prefix}-kind-${index}`}>Kind</label>
              <select
                id={`${prefix}-kind-${index}`}
                value={row.kind}
                onChange={(e) =>
                  onChange(
                    replaceAt(rows, index, { ...row, kind: e.target.value as AuthAssertionKind }),
                  )
                }
              >
                {ASSERTION_OPTIONS.map((option) => (
                  <option key={option.value} value={option.value}>
                    {option.label}
                  </option>
                ))}
              </select>
            </div>
            {row.kind === "http_status" ? (
              <TimeoutField
                id={`${prefix}-status-${index}`}
                label="Status"
                value={row.status}
                onChange={(status) => onChange(replaceAt(rows, index, { ...row, status }))}
              />
            ) : (
              <div className="setup-field">
                <label htmlFor={`${prefix}-value-${index}`}>Value</label>
                <input
                  id={`${prefix}-value-${index}`}
                  type="text"
                  autoComplete="off"
                  placeholder={row.kind === "cookie_exists" ? "sid" : "Dashboard"}
                  value={row.value}
                  onChange={(e) =>
                    onChange(replaceAt(rows, index, { ...row, value: e.target.value }))
                  }
                />
              </div>
            )}
            <Button
              size="sm"
              variant="ghost"
              onClick={() => onChange(rows.filter((_, i) => i !== index))}
            >
              Remove
            </Button>
          </div>
        ))}
      </div>
    </details>
  );
}

function OwnedObjectRows({
  rows,
  prefix,
  onChange,
}: {
  rows: AuthOwnedObjectDraft[];
  prefix: string;
  onChange: (rows: AuthOwnedObjectDraft[]) => void;
}) {
  return (
    <details className="runtime-auth-advanced">
      <summary>Owned objects</summary>
      <div className="runtime-auth-nested-list">
        <Button size="sm" variant="ghost" onClick={() => onChange([...rows, blankOwnedObject()])}>
          Add object
        </Button>
        {rows.map((row, index) => (
          <div className="runtime-auth-owned-row" key={`${prefix}-${index}`}>
            <div className="setup-field">
              <label htmlFor={`${prefix}-name-${index}`}>Name</label>
              <input
                id={`${prefix}-name-${index}`}
                type="text"
                autoComplete="off"
                placeholder="project"
                value={row.name}
                onChange={(e) => onChange(replaceAt(rows, index, { ...row, name: e.target.value }))}
              />
            </div>
            <div className="setup-field">
              <label htmlFor={`${prefix}-id-${index}`}>Object ID</label>
              <input
                id={`${prefix}-id-${index}`}
                type="text"
                autoComplete="off"
                placeholder="proj-user-a-1"
                value={row.id}
                onChange={(e) => onChange(replaceAt(rows, index, { ...row, id: e.target.value }))}
              />
            </div>
            <div className="setup-field">
              <label htmlFor={`${prefix}-route-${index}`}>Route</label>
              <input
                id={`${prefix}-route-${index}`}
                type="text"
                autoComplete="off"
                placeholder="/api/projects/{id}"
                value={row.route}
                onChange={(e) =>
                  onChange(replaceAt(rows, index, { ...row, route: e.target.value }))
                }
              />
            </div>
            <div className="setup-field">
              <label htmlFor={`${prefix}-marker-${index}`}>Marker</label>
              <input
                id={`${prefix}-marker-${index}`}
                type="text"
                autoComplete="off"
                placeholder="nyx-agent-user-a-project"
                value={row.marker}
                onChange={(e) =>
                  onChange(replaceAt(rows, index, { ...row, marker: e.target.value }))
                }
              />
            </div>
            <Button
              size="sm"
              variant="ghost"
              onClick={() => onChange(rows.filter((_, i) => i !== index))}
            >
              Remove
            </Button>
          </div>
        ))}
      </div>
    </details>
  );
}

function authModeUsesLogin(mode: AuthMode): boolean {
  return (
    mode === "browser_login" ||
    mode === "manual_sso" ||
    mode === "otp_email_manual" ||
    mode === "otp_email_mailbox" ||
    mode === "ai_auto" ||
    mode === "oidc_device"
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

function authDrafts(profiles: ProjectAuthProfile[]): AuthProfileDraft[] {
  return profiles.map((profile) => ({
    role: profile.role,
    mode: (profile.mode ?? "header_injection") as AuthMode,
    label: profile.label ?? "",
    session_cache_ttl_seconds: profile.session_cache_ttl_seconds?.toString() ?? "",
    session_import_path: profile.session_import_path ?? "",
    login_url: profile.login_url ?? "",
    username: profile.username ?? "",
    username_env: profile.username_env ?? "",
    login_email_env: profile.login_email_env ?? "",
    password_env: profile.password_env ?? "",
    cookie_env: profile.cookie_env ?? "",
    bearer_token_env: profile.bearer_token_env ?? "",
    headers: (profile.headers ?? []).map((header) => ({
      name: header.name,
      value_env: header.value_env ?? "",
    })),
    otp_source_kind: (profile.otp_source?.kind ?? "manual") as OtpSourceKind,
    otp_mailbox_url: profile.otp_source?.mailbox_url ?? "",
    otp_email_env: profile.otp_source?.email_env ?? "",
    otp_subject_contains: profile.otp_source?.subject_contains ?? "",
    otp_body_regex: profile.otp_source?.body_regex ?? "",
    post_login_assertion: profile.post_login_assertion ?? "",
    post_login_assertions: (profile.post_login_assertions ?? []).map((assertion) => ({
      kind: assertion.kind as AuthAssertionKind,
      value: assertion.value ?? "",
      status: assertion.status?.toString() ?? "",
    })),
    custom_command: profile.custom_command ?? "",
    owned_objects: (profile.owned_objects ?? []).map((object) => ({
      name: object.name,
      id: object.id,
      route: object.route ?? "",
      marker: object.marker ?? "",
    })),
  }));
}

function commandToDraft(command: ProjectRuntimeCommand | null): RuntimeCommandDraft {
  if (!command) return blankCommand();
  return {
    command: command.command,
    repo_name: command.repo_name ?? "",
    working_directory: command.working_directory ?? "",
    timeout_seconds: command.timeout_seconds?.toString() ?? "",
    stdin: "",
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
  const stdin = draft.stdin ? decodeEscapedNewlines(draft.stdin) : undefined;
  if (repo_name) out.repo_name = repo_name;
  if (working_directory) out.working_directory = working_directory;
  if (timeout_seconds !== undefined) out.timeout_seconds = timeout_seconds;
  if (stdin !== undefined) out.stdin = stdin;
  return out;
}

function launchStepToDraft(step: LaunchStep | null): RuntimeCommandDraft {
  if (!step) return blankCommand();
  return {
    command: step.command,
    repo_name: step.repo_name ?? "",
    working_directory: step.working_directory ?? "",
    timeout_seconds: step.timeout_seconds?.toString() ?? "",
    stdin: step.stdin ? encodeEscapedNewlines(step.stdin) : "",
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

function authFromDraft(draft: AuthProfileDraft): ProjectAuthProfile | undefined {
  const role = trimOrUndefined(draft.role);
  if (!role) return undefined;
  const out: ProjectAuthProfile = {
    role,
    mode: draft.mode,
    headers: [],
    post_login_assertions: [],
    owned_objects: [],
  };
  const label = trimOrUndefined(draft.label);
  const session_cache_ttl_seconds = positiveIntOrUndefined(draft.session_cache_ttl_seconds);
  const session_import_path = trimOrUndefined(draft.session_import_path);
  const login_url = trimOrUndefined(draft.login_url);
  const username = trimOrUndefined(draft.username);
  const username_env = trimOrUndefined(draft.username_env);
  const login_email_env = trimOrUndefined(draft.login_email_env);
  const password_env = trimOrUndefined(draft.password_env);
  const cookie_env = trimOrUndefined(draft.cookie_env);
  const bearer_token_env = trimOrUndefined(draft.bearer_token_env);
  const post_login_assertion = trimOrUndefined(draft.post_login_assertion);
  const custom_command = trimOrUndefined(draft.custom_command);
  if (label) out.label = label;
  if (session_cache_ttl_seconds !== undefined) {
    out.session_cache_ttl_seconds = session_cache_ttl_seconds;
  }
  if (session_import_path) out.session_import_path = session_import_path;
  if (login_url) out.login_url = login_url;
  if (username) out.username = username;
  if (username_env) out.username_env = username_env;
  if (login_email_env) out.login_email_env = login_email_env;
  if (password_env) out.password_env = password_env;
  if (cookie_env) out.cookie_env = cookie_env;
  if (bearer_token_env) out.bearer_token_env = bearer_token_env;
  out.headers = draft.headers
    .map((header) => {
      const name = trimOrUndefined(header.name);
      const value_env = trimOrUndefined(header.value_env);
      return name && value_env ? { name, value_env } : undefined;
    })
    .filter(isDefined);
  const mailbox_url = trimOrUndefined(draft.otp_mailbox_url);
  const otp_email_env = trimOrUndefined(draft.otp_email_env);
  const subject_contains = trimOrUndefined(draft.otp_subject_contains);
  const body_regex = trimOrUndefined(draft.otp_body_regex);
  if (
    draft.mode === "otp_email_manual" ||
    draft.mode === "otp_email_mailbox" ||
    mailbox_url ||
    otp_email_env ||
    subject_contains ||
    body_regex
  ) {
    out.otp_source = { kind: draft.otp_source_kind };
    if (mailbox_url) out.otp_source.mailbox_url = mailbox_url;
    if (otp_email_env) out.otp_source.email_env = otp_email_env;
    if (subject_contains) out.otp_source.subject_contains = subject_contains;
    if (body_regex) out.otp_source.body_regex = body_regex;
  }
  out.post_login_assertions = draft.post_login_assertions
    .map((assertion) => {
      const value = trimOrUndefined(assertion.value);
      const status = positiveIntOrUndefined(assertion.status);
      if (assertion.kind === "http_status") {
        return status !== undefined ? { kind: assertion.kind, status } : undefined;
      }
      return value ? { kind: assertion.kind, value } : undefined;
    })
    .filter(isDefined);
  if (post_login_assertion) out.post_login_assertion = post_login_assertion;
  if (custom_command) out.custom_command = custom_command;
  out.owned_objects = draft.owned_objects.map(ownedObjectFromDraft).filter(isDefined);
  return out;
}

function ownedObjectFromDraft(draft: AuthOwnedObjectDraft): ProjectAuthOwnedObject | undefined {
  const name = trimOrUndefined(draft.name);
  const id = trimOrUndefined(draft.id);
  if (!name || !id) return undefined;
  const out: ProjectAuthOwnedObject = { name, id };
  const route = trimOrUndefined(draft.route);
  const marker = trimOrUndefined(draft.marker);
  if (route) out.route = route;
  if (marker) out.marker = marker;
  return out;
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
      trimOrUndefined(row.timeout_seconds) ||
      trimOrUndefined(row.stdin),
  );
}

function decodeEscapedNewlines(input: string): string | undefined {
  const trimmed = input.trim();
  if (!trimmed) return undefined;
  return input.replaceAll("\\n", "\n");
}

function encodeEscapedNewlines(input: string): string {
  return input.replaceAll("\n", "\\n");
}

function sameTrimmed(a: string | null | undefined, b: string | null | undefined): boolean {
  return (a ?? "").trim() === (b ?? "").trim();
}

function replaceAt<T>(items: T[], index: number, next: T): T[] {
  return items.map((item, i) => (i === index ? next : item));
}

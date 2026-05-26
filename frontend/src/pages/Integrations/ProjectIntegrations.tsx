import { type Dispatch, type SetStateAction, useMemo, useState } from "react";
import { Link, useParams } from "react-router-dom";
import type {
  CreateProjectIntegrationRequest,
  ProjectIntegrationEvent,
  ProjectIntegrationKind,
  ProjectIntegrationRecord,
} from "@/api/client";
import {
  useCreateProjectIntegration,
  useDeleteProjectIntegration,
  usePatchProjectIntegration,
  useProject,
  useProjectIntegrations,
  useTestProjectIntegration,
} from "@/api/client";
import { Button } from "@/components/Button";
import { Card } from "@/components/Card";
import { EmptyState } from "@/components/EmptyState";
import { PageHeader, PageShell } from "@/components/Page";
import { Spinner } from "@/components/Spinner";
import { useToast } from "@/components/Toast";

type FormKind = ProjectIntegrationKind;

const EVENT_CHOICES: { value: ProjectIntegrationEvent; label: string }[] = [
  { value: "run_finished", label: "Run finished" },
  { value: "finding_verified", label: "Finding verified" },
];

const KIND_CHOICES: { value: FormKind; label: string }[] = [
  { value: "webhook", label: "Webhook" },
  { value: "slack", label: "Slack" },
  { value: "smtp", label: "Email" },
];

const SEVERITIES = ["", "Low", "Medium", "High", "Critical"];

export function ProjectIntegrations() {
  const { projectId } = useParams<{ projectId: string }>();
  const project = useProject(projectId);
  const integrations = useProjectIntegrations(projectId);
  const create = useCreateProjectIntegration(projectId ?? "");
  const patch = usePatchProjectIntegration(projectId ?? "");
  const remove = useDeleteProjectIntegration(projectId ?? "");
  const test = useTestProjectIntegration(projectId ?? "");
  const { showToast } = useToast();
  const [form, setForm] = useState(defaultForm());

  const rows = useMemo(() => integrations.data ?? [], [integrations.data]);

  if (!projectId) {
    return (
      <Card title="Integrations">
        <p>Missing project id.</p>
      </Card>
    );
  }

  if (project.isPending) {
    return (
      <Card>
        <div style={{ padding: 40, textAlign: "center" }}>
          <Spinner size="lg" />
        </div>
      </Card>
    );
  }

  if (project.error || !project.data) {
    return (
      <Card title="Project not found">
        <p>
          <Link to="/projects">Back to projects</Link>
        </p>
      </Card>
    );
  }

  async function createIntegration() {
    try {
      const body = buildRequest(form);
      const row = await create.mutateAsync(body);
      showToast(`Created ${row.name}.`, { tone: "success" });
      setForm(defaultForm());
    } catch (err) {
      showToast(`Could not create integration: ${String(err)}`, { tone: "danger" });
    }
  }

  async function toggleEnabled(row: ProjectIntegrationRecord) {
    try {
      await patch.mutateAsync({ id: row.id, patch: { enabled: !row.enabled } });
    } catch (err) {
      showToast(`Could not update ${row.name}: ${String(err)}`, { tone: "danger" });
    }
  }

  async function sendTest(row: ProjectIntegrationRecord) {
    try {
      await test.mutateAsync(row.id);
      showToast(`Sent test delivery to ${row.name}.`, { tone: "success" });
    } catch (err) {
      showToast(`Test delivery failed for ${row.name}: ${String(err)}`, { tone: "danger" });
    }
  }

  async function deleteIntegration(row: ProjectIntegrationRecord) {
    if (!window.confirm(`Delete "${row.name}"?`)) return;
    try {
      await remove.mutateAsync(row.id);
      showToast(`Deleted ${row.name}.`, { tone: "success" });
    } catch (err) {
      showToast(`Could not delete ${row.name}: ${String(err)}`, { tone: "danger" });
    }
  }

  return (
    <PageShell className="integrations-page">
      <PageHeader title="Integrations" meta={`${project.data.name} · ${rows.length} configured`} />

      <div className="integrations-grid">
        <Card title="Add integration" className="integration-card integration-card--form">
          <div className="integration-form">
            <label>
              <span>Name</span>
              <input
                value={form.name}
                onChange={(event) => setForm((cur) => ({ ...cur, name: event.target.value }))}
                placeholder="Security alerts"
              />
            </label>

            <fieldset className="integration-form__segmented">
              <legend>Integration type</legend>
              {KIND_CHOICES.map((choice) => (
                <button
                  key={choice.value}
                  type="button"
                  className={form.kind === choice.value ? "active" : ""}
                  onClick={() => setForm((cur) => ({ ...cur, kind: choice.value }))}
                >
                  {choice.label}
                </button>
              ))}
            </fieldset>

            <fieldset className="integration-form__events">
              <legend>Events</legend>
              {EVENT_CHOICES.map((choice) => (
                <label key={choice.value}>
                  <input
                    type="checkbox"
                    checked={form.events.includes(choice.value)}
                    onChange={(event) =>
                      setForm((cur) => ({
                        ...cur,
                        events: event.currentTarget.checked
                          ? [...cur.events, choice.value]
                          : cur.events.filter((value) => value !== choice.value),
                      }))
                    }
                  />
                  <span>{choice.label}</span>
                </label>
              ))}
            </fieldset>

            <label>
              <span>Minimum severity</span>
              <select
                value={form.minSeverity}
                onChange={(event) =>
                  setForm((cur) => ({ ...cur, minSeverity: event.target.value }))
                }
              >
                {SEVERITIES.map((severity) => (
                  <option key={severity || "all"} value={severity}>
                    {severity || "All severities"}
                  </option>
                ))}
              </select>
            </label>

            {form.kind === "webhook" && <WebhookFields form={form} setForm={setForm} />}
            {form.kind === "slack" && <SlackFields form={form} setForm={setForm} />}
            {form.kind === "smtp" && <SmtpFields form={form} setForm={setForm} />}

            <label className="integration-form__check">
              <input
                type="checkbox"
                checked={form.enabled}
                onChange={(event) => setForm((cur) => ({ ...cur, enabled: event.target.checked }))}
              />
              <span>Enabled</span>
            </label>

            <div className="integration-form__actions">
              <Button variant="primary" disabled={create.isPending} onClick={createIntegration}>
                {create.isPending ? "Adding..." : "Add integration"}
              </Button>
            </div>
          </div>
        </Card>

        <Card title="Configured" className="integration-card">
          {integrations.isPending && (
            <div className="repo-list__pending">
              <Spinner /> Loading integrations...
            </div>
          )}
          {integrations.error && (
            <p className="repo-list__error" role="alert">
              Failed to load integrations: {String(integrations.error)}
            </p>
          )}
          {!integrations.isPending && rows.length === 0 && (
            <EmptyState title="No integrations yet" />
          )}
          {rows.length > 0 && (
            <div className="integration-list">
              {rows.map((row) => (
                <article key={row.id} className="integration-row">
                  <div>
                    <div className="integration-row__title">
                      <strong>{row.name}</strong>
                      <span>
                        {kindLabel(row.kind)} · {row.enabled ? "Enabled" : "Off"}
                      </span>
                    </div>
                    <p>{row.target}</p>
                    <small>
                      {row.events.map(eventLabel).join(", ")}
                      {row.min_severity ? ` · ${row.min_severity}+` : ""}
                    </small>
                  </div>
                  <div className="integration-row__status">
                    <span>{deliveryStatus(row)}</span>
                    {row.last_delivery_error && <code>{row.last_delivery_error}</code>}
                  </div>
                  <div className="integration-row__actions">
                    <Button variant="ghost" size="sm" onClick={() => toggleEnabled(row)}>
                      {row.enabled ? "Disable" : "Enable"}
                    </Button>
                    <Button
                      variant="ghost"
                      size="sm"
                      disabled={test.isPending}
                      onClick={() => sendTest(row)}
                    >
                      Test
                    </Button>
                    <Button
                      variant="danger"
                      size="sm"
                      disabled={remove.isPending}
                      onClick={() => deleteIntegration(row)}
                    >
                      Delete
                    </Button>
                  </div>
                </article>
              ))}
            </div>
          )}
        </Card>
      </div>
    </PageShell>
  );
}

interface IntegrationForm {
  name: string;
  kind: FormKind;
  enabled: boolean;
  events: ProjectIntegrationEvent[];
  minSeverity: string;
  webhookUrl: string;
  signingSecret: string;
  slackWebhookUrl: string;
  smtpHost: string;
  smtpPort: string;
  smtpSecurity: "start_tls" | "none";
  smtpUsername: string;
  smtpPassword: string;
  smtpFrom: string;
  smtpRecipients: string;
}

function defaultForm(): IntegrationForm {
  return {
    name: "",
    kind: "webhook",
    enabled: true,
    events: ["run_finished", "finding_verified"],
    minSeverity: "",
    webhookUrl: "",
    signingSecret: "",
    slackWebhookUrl: "",
    smtpHost: "",
    smtpPort: "587",
    smtpSecurity: "start_tls",
    smtpUsername: "",
    smtpPassword: "",
    smtpFrom: "",
    smtpRecipients: "",
  };
}

function buildRequest(form: IntegrationForm): CreateProjectIntegrationRequest {
  const base = {
    name: form.name.trim(),
    enabled: form.enabled,
    events: form.events,
    min_severity: form.minSeverity || undefined,
  };
  if (form.kind === "webhook") {
    return {
      ...base,
      config: {
        kind: "webhook",
        url: form.webhookUrl.trim(),
        signing_secret: form.signingSecret.trim() || undefined,
      },
    };
  }
  if (form.kind === "slack") {
    return {
      ...base,
      config: { kind: "slack", webhook_url: form.slackWebhookUrl.trim() },
    };
  }
  return {
    ...base,
    config: {
      kind: "smtp",
      host: form.smtpHost.trim(),
      port: Number(form.smtpPort),
      security: form.smtpSecurity,
      username: form.smtpUsername.trim() || undefined,
      password: form.smtpPassword || undefined,
      from: form.smtpFrom.trim(),
      recipients: form.smtpRecipients
        .split(/[\n,]/)
        .map((value) => value.trim())
        .filter(Boolean),
    },
  };
}

function WebhookFields({
  form,
  setForm,
}: {
  form: IntegrationForm;
  setForm: Dispatch<SetStateAction<IntegrationForm>>;
}) {
  return (
    <>
      <label>
        <span>Webhook URL</span>
        <input
          value={form.webhookUrl}
          onChange={(event) => setForm((cur) => ({ ...cur, webhookUrl: event.target.value }))}
          placeholder="https://example.com/nyx-agent"
        />
      </label>
      <label>
        <span>Signing secret</span>
        <input
          type="password"
          value={form.signingSecret}
          onChange={(event) => setForm((cur) => ({ ...cur, signingSecret: event.target.value }))}
          placeholder="Optional"
        />
      </label>
    </>
  );
}

function SlackFields({
  form,
  setForm,
}: {
  form: IntegrationForm;
  setForm: Dispatch<SetStateAction<IntegrationForm>>;
}) {
  return (
    <label>
      <span>Slack webhook URL</span>
      <input
        type="password"
        value={form.slackWebhookUrl}
        onChange={(event) => setForm((cur) => ({ ...cur, slackWebhookUrl: event.target.value }))}
        placeholder="https://hooks.slack.com/services/..."
      />
    </label>
  );
}

function SmtpFields({
  form,
  setForm,
}: {
  form: IntegrationForm;
  setForm: Dispatch<SetStateAction<IntegrationForm>>;
}) {
  return (
    <>
      <div className="integration-form__grid">
        <label>
          <span>SMTP host</span>
          <input
            value={form.smtpHost}
            onChange={(event) => setForm((cur) => ({ ...cur, smtpHost: event.target.value }))}
            placeholder="smtp.example.com"
          />
        </label>
        <label>
          <span>Port</span>
          <input
            value={form.smtpPort}
            onChange={(event) => setForm((cur) => ({ ...cur, smtpPort: event.target.value }))}
            inputMode="numeric"
          />
        </label>
      </div>
      <label>
        <span>Security</span>
        <select
          value={form.smtpSecurity}
          onChange={(event) =>
            setForm((cur) => ({
              ...cur,
              smtpSecurity: event.target.value as IntegrationForm["smtpSecurity"],
            }))
          }
        >
          <option value="start_tls">STARTTLS</option>
          <option value="none">None</option>
        </select>
      </label>
      <div className="integration-form__grid">
        <label>
          <span>Username</span>
          <input
            value={form.smtpUsername}
            onChange={(event) => setForm((cur) => ({ ...cur, smtpUsername: event.target.value }))}
            autoComplete="username"
          />
        </label>
        <label>
          <span>Password</span>
          <input
            type="password"
            value={form.smtpPassword}
            onChange={(event) => setForm((cur) => ({ ...cur, smtpPassword: event.target.value }))}
            autoComplete="current-password"
          />
        </label>
      </div>
      <label>
        <span>From</span>
        <input
          value={form.smtpFrom}
          onChange={(event) => setForm((cur) => ({ ...cur, smtpFrom: event.target.value }))}
          placeholder="Nyx Agent <alerts@example.com>"
        />
      </label>
      <label>
        <span>Recipients</span>
        <textarea
          value={form.smtpRecipients}
          onChange={(event) => setForm((cur) => ({ ...cur, smtpRecipients: event.target.value }))}
          placeholder="security@example.com, appsec@example.com"
          rows={3}
        />
      </label>
    </>
  );
}

function kindLabel(kind: ProjectIntegrationKind): string {
  if (kind === "smtp") return "Email";
  if (kind === "slack") return "Slack";
  return "Webhook";
}

function eventLabel(event: ProjectIntegrationEvent): string {
  return EVENT_CHOICES.find((choice) => choice.value === event)?.label ?? event;
}

function deliveryStatus(row: ProjectIntegrationRecord): string {
  if (!row.last_delivery_at) return "No deliveries yet";
  const when = new Date(row.last_delivery_at).toLocaleString();
  return `${row.last_delivery_status ?? "unknown"} · ${when}`;
}

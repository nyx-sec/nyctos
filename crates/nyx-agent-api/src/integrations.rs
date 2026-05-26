//! Outbound project integration delivery.

use hmac::{Hmac, KeyInit, Mac};
use lettre::message::Mailbox;
use lettre::transport::smtp::authentication::Credentials;
use lettre::{AsyncSmtpTransport, AsyncTransport, Message as EmailMessage, Tokio1Executor};
use serde::Serialize;
use sha2::Sha256;
use tokio::sync::broadcast::error::RecvError;

use nyx_agent_core::store::{
    FindingRecord, ProjectIntegrationRecord, ProjectIntegrationStoredRecord,
};
use nyx_agent_core::{now_epoch_ms, Store};
use nyx_agent_types::event::{AgentEvent, RunEvent, SandboxEvent};
use nyx_agent_types::integration::{
    ProjectIntegrationConfigInput, ProjectIntegrationEvent, ProjectIntegrationKind, SmtpSecurity,
};

type HmacSha256 = Hmac<Sha256>;

#[derive(Debug, Clone)]
pub struct PreparedIntegrationConfig {
    pub kind: ProjectIntegrationKind,
    pub config_json: String,
    pub target: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct IntegrationDeliveryPayload {
    pub event: String,
    pub project_id: String,
    pub project_name: String,
    pub run_id: Option<String>,
    pub finding_id: Option<String>,
    pub title: String,
    pub summary: String,
    pub severity: Option<String>,
    pub status: Option<String>,
    pub url: Option<String>,
    pub vulnerabilities: Vec<IntegrationVulnerabilitySummary>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub counts: Option<IntegrationRunCounts>,
    pub sent_at_ms: i64,
}

#[derive(Debug, Clone, Serialize)]
pub struct IntegrationVulnerabilitySummary {
    pub id: String,
    pub title: String,
    pub severity: String,
    pub status: String,
    pub vuln_class: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct IntegrationRunCounts {
    pub succeeded: u32,
    pub inconclusive: u32,
    pub failed: u32,
    pub verified_vulnerabilities: usize,
}

pub fn prepare_config(
    config: &ProjectIntegrationConfigInput,
) -> Result<PreparedIntegrationConfig, String> {
    let kind = integration_kind(config);
    validate_config(config)?;
    let target = target_summary(config);
    let config_json = serde_json::to_string(config)
        .map_err(|err| format!("serialise integration config: {err}"))?;
    Ok(PreparedIntegrationConfig { kind, config_json, target })
}

pub fn integration_kind(config: &ProjectIntegrationConfigInput) -> ProjectIntegrationKind {
    match config {
        ProjectIntegrationConfigInput::Webhook { .. } => ProjectIntegrationKind::Webhook,
        ProjectIntegrationConfigInput::Slack { .. } => ProjectIntegrationKind::Slack,
        ProjectIntegrationConfigInput::Smtp { .. } => ProjectIntegrationKind::Smtp,
    }
}

pub fn validate_config(config: &ProjectIntegrationConfigInput) -> Result<(), String> {
    match config {
        ProjectIntegrationConfigInput::Webhook { url, .. } => validate_http_url(url, "webhook URL"),
        ProjectIntegrationConfigInput::Slack { webhook_url } => {
            validate_http_url(webhook_url, "Slack webhook URL")?;
            if !webhook_url.starts_with("https://") {
                return Err("Slack webhook URL must use https".to_string());
            }
            Ok(())
        }
        ProjectIntegrationConfigInput::Smtp {
            host,
            port,
            username,
            password,
            from,
            recipients,
            ..
        } => {
            if host.trim().is_empty() {
                return Err("SMTP host is required".to_string());
            }
            if *port == 0 {
                return Err("SMTP port must be greater than 0".to_string());
            }
            if username.as_deref().unwrap_or("").trim().is_empty() && password.is_some() {
                return Err("SMTP password requires a username".to_string());
            }
            parse_mailbox(from, "from address")?;
            if recipients.is_empty() {
                return Err("at least one recipient is required".to_string());
            }
            for recipient in recipients {
                parse_mailbox(recipient, "recipient")?;
            }
            Ok(())
        }
    }
}

pub fn validate_min_severity(value: Option<&str>) -> Result<(), String> {
    if let Some(value) = value {
        if severity_rank(value).is_none() {
            return Err("minimum severity must be Low, Medium, High, or Critical".to_string());
        }
    }
    Ok(())
}

pub fn target_summary(config: &ProjectIntegrationConfigInput) -> String {
    match config {
        ProjectIntegrationConfigInput::Webhook { url, .. } => url_host_summary(url),
        ProjectIntegrationConfigInput::Slack { webhook_url } => url_host_summary(webhook_url),
        ProjectIntegrationConfigInput::Smtp { host, port, recipients, .. } => {
            format!("{host}:{port} -> {}", recipients.join(", "))
        }
    }
}

pub fn spawn_integration_delivery_task(
    store: Store,
    events: nyx_agent_types::event::EventSink,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let dispatcher = IntegrationDispatcher::new();
        let mut rx = events.subscribe();
        loop {
            let ev = match rx.recv().await {
                Ok(ev) => ev,
                Err(RecvError::Lagged(skipped)) => {
                    tracing::warn!(skipped, "integration delivery task lagged");
                    continue;
                }
                Err(RecvError::Closed) => break,
            };
            if let Err(err) = dispatcher.handle_event(&store, ev).await {
                tracing::warn!(error = %err, "integration delivery failed");
            }
        }
    })
}

#[derive(Clone)]
pub struct IntegrationDispatcher {
    http: reqwest::Client,
}

impl IntegrationDispatcher {
    pub fn new() -> Self {
        Self { http: reqwest::Client::new() }
    }

    pub async fn send_test(
        &self,
        store: &Store,
        integration: &ProjectIntegrationStoredRecord,
    ) -> Result<(), String> {
        let project = store
            .projects()
            .get(&integration.public.project_id)
            .await
            .map_err(|err| err.to_string())?
            .ok_or_else(|| format!("project `{}` not found", integration.public.project_id))?;
        let payload = IntegrationDeliveryPayload {
            event: "test".to_string(),
            project_id: project.id,
            project_name: project.name,
            run_id: None,
            finding_id: None,
            title: "Nyx Agent test notification".to_string(),
            summary: "This is a test delivery from the project integrations page.".to_string(),
            severity: None,
            status: Some("Test".to_string()),
            url: None,
            vulnerabilities: Vec::new(),
            counts: None,
            sent_at_ms: now_epoch_ms(),
        };
        self.deliver(integration, &payload).await.map_err(|err| err.to_string())
    }

    async fn handle_event(&self, store: &Store, ev: AgentEvent) -> Result<(), String> {
        match ev {
            AgentEvent::Run {
                data:
                    RunEvent::RunFinished {
                        run_id, project_id, succeeded, inconclusive, failed, ..
                    },
            } => {
                let project = store
                    .projects()
                    .get(&project_id)
                    .await
                    .map_err(|err| err.to_string())?
                    .ok_or_else(|| format!("project `{project_id}` not found"))?;
                let vulnerabilities = store
                    .verified_vulnerabilities()
                    .list_by_run(&run_id)
                    .await
                    .map_err(|err| err.to_string())?;
                let top = vulnerabilities
                    .iter()
                    .take(5)
                    .map(|v| IntegrationVulnerabilitySummary {
                        id: v.id.clone(),
                        title: v.title.clone(),
                        severity: v.severity.clone(),
                        status: v.status.clone(),
                        vuln_class: v.vuln_class.clone(),
                    })
                    .collect::<Vec<_>>();
                let severity = vulnerabilities
                    .iter()
                    .map(|v| v.severity.as_str())
                    .max_by_key(|severity| severity_rank(severity).unwrap_or(0));
                let title = if vulnerabilities.is_empty() {
                    format!("Nyx Agent run {run_id} finished")
                } else {
                    format!(
                        "Nyx Agent run {run_id} found {} verified issue(s)",
                        vulnerabilities.len()
                    )
                };
                let payload = IntegrationDeliveryPayload {
                    event: ProjectIntegrationEvent::RunFinished.as_str().to_string(),
                    project_id: project.id,
                    project_name: project.name,
                    run_id: Some(run_id),
                    finding_id: None,
                    title,
                    summary: format!(
                        "Run finished with {succeeded} succeeded, {inconclusive} inconclusive, {failed} failed repo(s)."
                    ),
                    severity: severity.map(str::to_string),
                    status: Some(if failed > 0 { "Failed" } else { "Finished" }.to_string()),
                    url: None,
                    vulnerabilities: top,
                    counts: Some(IntegrationRunCounts {
                        succeeded,
                        inconclusive,
                        failed,
                        verified_vulnerabilities: vulnerabilities.len(),
                    }),
                    sent_at_ms: now_epoch_ms(),
                };
                self.deliver_project_event(
                    store,
                    &project_id,
                    ProjectIntegrationEvent::RunFinished,
                    payload,
                )
                .await
            }
            AgentEvent::Sandbox {
                data: SandboxEvent::VerifierFinished { run_id, finding_id, verdict, .. },
            } if verdict == "Confirmed" => {
                let Some(run) = store.runs().get(&run_id).await.map_err(|err| err.to_string())?
                else {
                    return Ok(());
                };
                let project_id = run.project_id.unwrap_or_else(|| "default-project".to_string());
                let project = store
                    .projects()
                    .get(&project_id)
                    .await
                    .map_err(|err| err.to_string())?
                    .ok_or_else(|| format!("project `{project_id}` not found"))?;
                let Some(finding) =
                    store.findings().get(&finding_id).await.map_err(|err| err.to_string())?
                else {
                    return Ok(());
                };
                let payload = finding_payload(&project.id, &project.name, &finding);
                self.deliver_project_event(
                    store,
                    &project.id,
                    ProjectIntegrationEvent::FindingVerified,
                    payload,
                )
                .await
            }
            _ => Ok(()),
        }
    }

    async fn deliver_project_event(
        &self,
        store: &Store,
        project_id: &str,
        event: ProjectIntegrationEvent,
        payload: IntegrationDeliveryPayload,
    ) -> Result<(), String> {
        let rows = store
            .integrations()
            .list_enabled_by_project(project_id)
            .await
            .map_err(|err| err.to_string())?;
        for row in rows {
            if !row.public.events.contains(&event) || !passes_severity(&row.public, &payload) {
                continue;
            }
            let delivered_at = now_epoch_ms();
            match self.deliver(&row, &payload).await {
                Ok(()) => {
                    if let Err(err) = store
                        .integrations()
                        .record_delivery(&row.public.id, delivered_at, "ok", None)
                        .await
                    {
                        tracing::warn!(integration_id = %row.public.id, error = %err, "failed to record integration delivery status");
                    }
                }
                Err(err) => {
                    let err_s = err.to_string();
                    if let Err(store_err) = store
                        .integrations()
                        .record_delivery(&row.public.id, delivered_at, "error", Some(&err_s))
                        .await
                    {
                        tracing::warn!(integration_id = %row.public.id, error = %store_err, "failed to record integration delivery error");
                    }
                    tracing::warn!(integration_id = %row.public.id, error = %err_s, "integration delivery failed");
                }
            }
        }
        Ok(())
    }

    async fn deliver(
        &self,
        row: &ProjectIntegrationStoredRecord,
        payload: &IntegrationDeliveryPayload,
    ) -> anyhow::Result<()> {
        let cfg: ProjectIntegrationConfigInput = serde_json::from_str(&row.config_json)?;
        match cfg {
            ProjectIntegrationConfigInput::Webhook { url, signing_secret } => {
                let body = serde_json::to_vec(payload)?;
                let mut req = self
                    .http
                    .post(url)
                    .header("content-type", "application/json")
                    .body(body.clone());
                if let Some(secret) = signing_secret.filter(|s| !s.is_empty()) {
                    let mut mac = HmacSha256::new_from_slice(secret.as_bytes())?;
                    mac.update(&body);
                    let sig = format!("sha256={}", hex::encode(mac.finalize().into_bytes()));
                    req = req.header("X-Nyx-Agent-Signature-256", sig);
                }
                let res = req.send().await?;
                if !res.status().is_success() {
                    anyhow::bail!("webhook returned {}", res.status());
                }
                Ok(())
            }
            ProjectIntegrationConfigInput::Slack { webhook_url } => {
                let body = serde_json::json!({ "text": slack_text(payload) });
                let res = self.http.post(webhook_url).json(&body).send().await?;
                if !res.status().is_success() {
                    anyhow::bail!("Slack webhook returned {}", res.status());
                }
                Ok(())
            }
            ProjectIntegrationConfigInput::Smtp {
                host,
                port,
                security,
                username,
                password,
                from,
                recipients,
            } => {
                let mut builder = match security {
                    SmtpSecurity::StartTls => {
                        AsyncSmtpTransport::<Tokio1Executor>::starttls_relay(&host)?
                    }
                    SmtpSecurity::None => {
                        AsyncSmtpTransport::<Tokio1Executor>::builder_dangerous(&host)
                    }
                }
                .port(port);
                if let Some(username) = username.filter(|s| !s.trim().is_empty()) {
                    builder = builder
                        .credentials(Credentials::new(username, password.unwrap_or_default()));
                }
                let mut email = EmailMessage::builder()
                    .from(parse_mailbox(&from, "from address").map_err(|err| anyhow::anyhow!(err))?)
                    .subject(payload.title.clone());
                for recipient in recipients {
                    email = email.to(parse_mailbox(&recipient, "recipient")
                        .map_err(|err| anyhow::anyhow!(err))?);
                }
                let email = email.body(email_text(payload))?;
                builder.build().send(email).await?;
                Ok(())
            }
        }
    }
}

impl Default for IntegrationDispatcher {
    fn default() -> Self {
        Self::new()
    }
}

fn finding_payload(
    project_id: &str,
    project_name: &str,
    finding: &FindingRecord,
) -> IntegrationDeliveryPayload {
    let title = format!("Confirmed {} in {}", finding.cap, finding.path);
    IntegrationDeliveryPayload {
        event: ProjectIntegrationEvent::FindingVerified.as_str().to_string(),
        project_id: project_id.to_string(),
        project_name: project_name.to_string(),
        run_id: Some(finding.run_id.clone()),
        finding_id: Some(finding.id.clone()),
        title: title.clone(),
        summary: format!(
            "{}:{} matched {} ({})",
            finding.path,
            finding.line.map(|n| n.to_string()).unwrap_or_else(|| "?".to_string()),
            finding.rule,
            finding.severity
        ),
        severity: Some(finding.severity.clone()),
        status: Some("Confirmed".to_string()),
        url: None,
        vulnerabilities: vec![IntegrationVulnerabilitySummary {
            id: finding.id.clone(),
            title,
            severity: finding.severity.clone(),
            status: "Confirmed".to_string(),
            vuln_class: finding.cap.clone(),
        }],
        counts: None,
        sent_at_ms: now_epoch_ms(),
    }
}

fn passes_severity(
    integration: &ProjectIntegrationRecord,
    payload: &IntegrationDeliveryPayload,
) -> bool {
    let Some(min) = integration.min_severity.as_deref() else {
        return true;
    };
    let Some(severity) = payload.severity.as_deref() else {
        return false;
    };
    severity_rank(severity).unwrap_or(0) >= severity_rank(min).unwrap_or(0)
}

fn severity_rank(severity: &str) -> Option<u8> {
    match severity.to_ascii_lowercase().as_str() {
        "low" => Some(1),
        "medium" => Some(2),
        "high" => Some(3),
        "critical" => Some(4),
        _ => None,
    }
}

fn slack_text(payload: &IntegrationDeliveryPayload) -> String {
    let mut text =
        format!("*{}*\nProject: {}\n{}", payload.title, payload.project_name, payload.summary);
    if let Some(severity) = &payload.severity {
        text.push_str(&format!("\nSeverity: {severity}"));
    }
    for vuln in &payload.vulnerabilities {
        text.push_str(&format!("\n- [{}] {} ({})", vuln.severity, vuln.title, vuln.status));
    }
    text
}

fn email_text(payload: &IntegrationDeliveryPayload) -> String {
    let mut text = format!(
        "{}\n\nProject: {}\nEvent: {}\n{}\n",
        payload.title, payload.project_name, payload.event, payload.summary
    );
    if let Some(severity) = &payload.severity {
        text.push_str(&format!("Severity: {severity}\n"));
    }
    if let Some(run_id) = &payload.run_id {
        text.push_str(&format!("Run: {run_id}\n"));
    }
    if let Some(finding_id) = &payload.finding_id {
        text.push_str(&format!("Finding: {finding_id}\n"));
    }
    if !payload.vulnerabilities.is_empty() {
        text.push_str("\nFindings:\n");
        for vuln in &payload.vulnerabilities {
            text.push_str(&format!(
                "- [{}] {} ({}, {})\n",
                vuln.severity, vuln.title, vuln.vuln_class, vuln.status
            ));
        }
    }
    text
}

fn validate_http_url(raw: &str, label: &str) -> Result<(), String> {
    let url = reqwest::Url::parse(raw).map_err(|err| format!("invalid {label}: {err}"))?;
    if !matches!(url.scheme(), "http" | "https") {
        return Err(format!("{label} must use http or https"));
    }
    if url.host_str().is_none() {
        return Err(format!("{label} must include a host"));
    }
    Ok(())
}

fn url_host_summary(raw: &str) -> String {
    reqwest::Url::parse(raw)
        .ok()
        .and_then(|url| url.host_str().map(str::to_string))
        .unwrap_or_else(|| "configured URL".to_string())
}

fn parse_mailbox(raw: &str, label: &str) -> Result<Mailbox, String> {
    raw.parse::<Mailbox>().map_err(|err| format!("invalid {label}: {err}"))
}

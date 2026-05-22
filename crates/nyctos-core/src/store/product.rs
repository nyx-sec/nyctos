//! Product-reset persistence stores.

use sqlx::{Row, SqlitePool};

pub use nyctos_types::product::{
    EnvironmentRunRecord, LaunchEnvRef, LaunchHealthCheck, LaunchStep, LaunchWorkingDir,
    NyxSignalRecord, PentestCandidateRecord, ProjectLaunchProfile, ProjectLaunchProfileInput,
    VerificationAttemptRecord, VerifiedVulnerabilityRecord,
};

use crate::store::StoreError;

pub struct LaunchProfileStore<'a> {
    pool: &'a SqlitePool,
}

impl<'a> LaunchProfileStore<'a> {
    pub fn new(pool: &'a SqlitePool) -> Self {
        Self { pool }
    }

    pub async fn get_default(
        &self,
        project_id: &str,
    ) -> Result<Option<ProjectLaunchProfile>, StoreError> {
        let row = sqlx::query(
            r#"
            SELECT id, project_id, name, mode, build_steps_json, start_steps_json,
                   stop_steps_json, health_checks_json, target_urls_json, env_refs_json,
                   working_dirs_json, readiness, created_at, updated_at, is_default
            FROM project_launch_profiles
            WHERE project_id = ? AND is_default = 1
            ORDER BY updated_at DESC
            LIMIT 1
            "#,
        )
        .bind(project_id)
        .fetch_optional(self.pool)
        .await?;
        row.map(row_to_launch_profile).transpose()
    }

    pub async fn list_by_project(
        &self,
        project_id: &str,
    ) -> Result<Vec<ProjectLaunchProfile>, StoreError> {
        let rows = sqlx::query(
            r#"
            SELECT id, project_id, name, mode, build_steps_json, start_steps_json,
                   stop_steps_json, health_checks_json, target_urls_json, env_refs_json,
                   working_dirs_json, readiness, created_at, updated_at, is_default
            FROM project_launch_profiles
            WHERE project_id = ?
            ORDER BY is_default DESC, name
            "#,
        )
        .bind(project_id)
        .fetch_all(self.pool)
        .await?;
        rows.into_iter().map(row_to_launch_profile).collect()
    }

    pub async fn upsert_default(
        &self,
        project_id: &str,
        input: &ProjectLaunchProfileInput,
        now_ms: i64,
    ) -> Result<ProjectLaunchProfile, StoreError> {
        let id = format!("lp-{project_id}-default");
        let name = input.name.as_deref().unwrap_or("local dev");
        let mode = input.mode.as_deref().unwrap_or("custom-commands");
        let readiness = launch_profile_readiness(input);
        let build = serde_json::to_string(&input.build_steps)?;
        let start = serde_json::to_string(&input.start_steps)?;
        let stop = serde_json::to_string(&input.stop_steps)?;
        let health = serde_json::to_string(&input.health_checks)?;
        let targets = serde_json::to_string(&input.target_urls)?;
        let env_refs = serde_json::to_string(&input.env_refs)?;
        let working_dirs = serde_json::to_string(&input.working_dirs)?;

        sqlx::query(
            r#"
            INSERT INTO project_launch_profiles (
                id, project_id, name, mode, build_steps_json, start_steps_json,
                stop_steps_json, health_checks_json, target_urls_json, env_refs_json,
                working_dirs_json, readiness, created_at, updated_at, is_default
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1)
            ON CONFLICT(id) DO UPDATE SET
                name = excluded.name,
                mode = excluded.mode,
                build_steps_json = excluded.build_steps_json,
                start_steps_json = excluded.start_steps_json,
                stop_steps_json = excluded.stop_steps_json,
                health_checks_json = excluded.health_checks_json,
                target_urls_json = excluded.target_urls_json,
                env_refs_json = excluded.env_refs_json,
                working_dirs_json = excluded.working_dirs_json,
                readiness = excluded.readiness,
                updated_at = excluded.updated_at,
                is_default = 1
            "#,
        )
        .bind(&id)
        .bind(project_id)
        .bind(name)
        .bind(mode)
        .bind(&build)
        .bind(&start)
        .bind(&stop)
        .bind(&health)
        .bind(&targets)
        .bind(&env_refs)
        .bind(&working_dirs)
        .bind(readiness)
        .bind(now_ms)
        .bind(now_ms)
        .execute(self.pool)
        .await?;

        self.get_default(project_id).await?.ok_or(StoreError::Sqlx(sqlx::Error::RowNotFound))
    }
}

pub struct EnvironmentRunStore<'a> {
    pool: &'a SqlitePool,
}

impl<'a> EnvironmentRunStore<'a> {
    pub fn new(pool: &'a SqlitePool) -> Self {
        Self { pool }
    }

    pub async fn insert(&self, rec: &EnvironmentRunRecord) -> Result<(), StoreError> {
        sqlx::query(
            r#"
            INSERT INTO environment_runs (
                id, run_id, project_id, profile_id, status, started_at, ready_at, stopped_at,
                target_urls_json, health_blob, logs_dir, teardown_blob
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            "#,
        )
        .bind(&rec.id)
        .bind(&rec.run_id)
        .bind(&rec.project_id)
        .bind(&rec.profile_id)
        .bind(&rec.status)
        .bind(rec.started_at)
        .bind(rec.ready_at)
        .bind(rec.stopped_at)
        .bind(serde_json::to_string(&rec.target_urls)?)
        .bind(json_opt_to_string(&rec.health)?)
        .bind(&rec.logs_dir)
        .bind(json_opt_to_string(&rec.teardown)?)
        .execute(self.pool)
        .await?;
        Ok(())
    }

    pub async fn get(&self, id: &str) -> Result<Option<EnvironmentRunRecord>, StoreError> {
        let row = sqlx::query(
            r#"
            SELECT id, run_id, project_id, profile_id, status, started_at, ready_at,
                   stopped_at, target_urls_json, health_blob, logs_dir, teardown_blob
            FROM environment_runs
            WHERE id = ?
            "#,
        )
        .bind(id)
        .fetch_optional(self.pool)
        .await?;
        row.map(row_to_environment_run).transpose()
    }

    pub async fn list_by_run(&self, run_id: &str) -> Result<Vec<EnvironmentRunRecord>, StoreError> {
        let rows = sqlx::query(
            r#"
            SELECT id, run_id, project_id, profile_id, status, started_at, ready_at,
                   stopped_at, target_urls_json, health_blob, logs_dir, teardown_blob
            FROM environment_runs
            WHERE run_id = ?
            ORDER BY started_at DESC
            "#,
        )
        .bind(run_id)
        .fetch_all(self.pool)
        .await?;
        rows.into_iter().map(row_to_environment_run).collect()
    }

    pub async fn update_lifecycle(
        &self,
        id: &str,
        status: &str,
        ready_at: Option<i64>,
        stopped_at: Option<i64>,
        health: Option<&serde_json::Value>,
        teardown: Option<&serde_json::Value>,
    ) -> Result<(), StoreError> {
        sqlx::query(
            r#"
            UPDATE environment_runs SET
                status = ?,
                ready_at = COALESCE(?, ready_at),
                stopped_at = COALESCE(?, stopped_at),
                health_blob = COALESCE(?, health_blob),
                teardown_blob = COALESCE(?, teardown_blob)
            WHERE id = ?
            "#,
        )
        .bind(status)
        .bind(ready_at)
        .bind(stopped_at)
        .bind(health.map(serde_json::to_string).transpose()?)
        .bind(teardown.map(serde_json::to_string).transpose()?)
        .bind(id)
        .execute(self.pool)
        .await?;
        Ok(())
    }
}

pub struct NyxSignalStore<'a> {
    pool: &'a SqlitePool,
}

impl<'a> NyxSignalStore<'a> {
    pub fn new(pool: &'a SqlitePool) -> Self {
        Self { pool }
    }

    pub async fn insert(&self, rec: &NyxSignalRecord) -> Result<(), StoreError> {
        sqlx::query(
            r#"
            INSERT INTO nyx_signals (
                id, run_id, project_id, repo_id, repo, path, line, cap, rule, severity,
                message, evidence_blob, signal_kind, meaningful, suppressed_reason,
                agent_candidate_id, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(id) DO UPDATE SET
                agent_candidate_id = excluded.agent_candidate_id
            "#,
        )
        .bind(&rec.id)
        .bind(&rec.run_id)
        .bind(&rec.project_id)
        .bind(&rec.repo_id)
        .bind(&rec.repo)
        .bind(&rec.path)
        .bind(rec.line)
        .bind(&rec.cap)
        .bind(&rec.rule)
        .bind(&rec.severity)
        .bind(&rec.message)
        .bind(json_opt_to_string(&rec.evidence)?)
        .bind(&rec.signal_kind)
        .bind(if rec.meaningful { 1_i64 } else { 0_i64 })
        .bind(&rec.suppressed_reason)
        .bind(&rec.agent_candidate_id)
        .bind(rec.created_at)
        .execute(self.pool)
        .await?;
        Ok(())
    }

    pub async fn set_candidate(&self, id: &str, candidate_id: &str) -> Result<(), StoreError> {
        sqlx::query("UPDATE nyx_signals SET agent_candidate_id = ? WHERE id = ?")
            .bind(candidate_id)
            .bind(id)
            .execute(self.pool)
            .await?;
        Ok(())
    }

    pub async fn list_by_run(
        &self,
        run_id: &str,
        meaningful_only: bool,
    ) -> Result<Vec<NyxSignalRecord>, StoreError> {
        let sql = if meaningful_only {
            r#"
            SELECT id, run_id, project_id, repo_id, repo, path, line, cap, rule, severity,
                   message, evidence_blob, signal_kind, meaningful, suppressed_reason,
                   agent_candidate_id, created_at
            FROM nyx_signals
            WHERE run_id = ? AND meaningful = 1
            ORDER BY created_at DESC
            "#
        } else {
            r#"
            SELECT id, run_id, project_id, repo_id, repo, path, line, cap, rule, severity,
                   message, evidence_blob, signal_kind, meaningful, suppressed_reason,
                   agent_candidate_id, created_at
            FROM nyx_signals
            WHERE run_id = ?
            ORDER BY created_at DESC
            "#
        };
        let rows = sqlx::query(sql).bind(run_id).fetch_all(self.pool).await?;
        rows.into_iter().map(row_to_nyx_signal).collect()
    }
}

pub struct PentestCandidateStore<'a> {
    pool: &'a SqlitePool,
}

impl<'a> PentestCandidateStore<'a> {
    pub fn new(pool: &'a SqlitePool) -> Self {
        Self { pool }
    }

    pub async fn insert(&self, rec: &PentestCandidateRecord) -> Result<(), StoreError> {
        sqlx::query(
            r#"
            INSERT INTO pentest_candidates (
                id, run_id, project_id, source, source_ids_json, title, vuln_class,
                severity_guess, affected_components_json, hypothesis, test_plan, status,
                rejection_reason, confidence, trace_id, created_at, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(id) DO UPDATE SET
                status = excluded.status,
                rejection_reason = excluded.rejection_reason,
                updated_at = excluded.updated_at
            "#,
        )
        .bind(&rec.id)
        .bind(&rec.run_id)
        .bind(&rec.project_id)
        .bind(&rec.source)
        .bind(serde_json::to_string(&rec.source_ids)?)
        .bind(&rec.title)
        .bind(&rec.vuln_class)
        .bind(&rec.severity_guess)
        .bind(serde_json::to_string(&rec.affected_components)?)
        .bind(&rec.hypothesis)
        .bind(&rec.test_plan)
        .bind(&rec.status)
        .bind(&rec.rejection_reason)
        .bind(rec.confidence)
        .bind(&rec.trace_id)
        .bind(rec.created_at)
        .bind(rec.updated_at)
        .execute(self.pool)
        .await?;
        Ok(())
    }

    pub async fn set_status(
        &self,
        id: &str,
        status: &str,
        rejection_reason: Option<&str>,
        updated_at: i64,
    ) -> Result<(), StoreError> {
        sqlx::query(
            "UPDATE pentest_candidates SET status = ?, rejection_reason = ?, updated_at = ? WHERE id = ?",
        )
        .bind(status)
        .bind(rejection_reason)
        .bind(updated_at)
        .bind(id)
        .execute(self.pool)
        .await?;
        Ok(())
    }

    pub async fn list_by_run(
        &self,
        run_id: &str,
    ) -> Result<Vec<PentestCandidateRecord>, StoreError> {
        let rows = sqlx::query(
            r#"
            SELECT id, run_id, project_id, source, source_ids_json, title, vuln_class,
                   severity_guess, affected_components_json, hypothesis, test_plan, status,
                   rejection_reason, confidence, trace_id, created_at, updated_at
            FROM pentest_candidates
            WHERE run_id = ?
            ORDER BY created_at DESC
            "#,
        )
        .bind(run_id)
        .fetch_all(self.pool)
        .await?;
        rows.into_iter().map(row_to_candidate).collect()
    }
}

pub struct VerificationAttemptStore<'a> {
    pool: &'a SqlitePool,
}

impl<'a> VerificationAttemptStore<'a> {
    pub fn new(pool: &'a SqlitePool) -> Self {
        Self { pool }
    }

    pub async fn insert(&self, rec: &VerificationAttemptRecord) -> Result<(), StoreError> {
        sqlx::query(
            r#"
            INSERT INTO verification_attempts (
                id, run_id, project_id, environment_run_id, candidate_id, chain_id, method,
                status, started_at, finished_at, duration_ms, request_blob, response_blob,
                oracle_blob, artifact_paths_json, error, replay_stable
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            "#,
        )
        .bind(&rec.id)
        .bind(&rec.run_id)
        .bind(&rec.project_id)
        .bind(&rec.environment_run_id)
        .bind(&rec.candidate_id)
        .bind(&rec.chain_id)
        .bind(&rec.method)
        .bind(&rec.status)
        .bind(rec.started_at)
        .bind(rec.finished_at)
        .bind(rec.duration_ms)
        .bind(json_opt_to_string(&rec.request)?)
        .bind(json_opt_to_string(&rec.response)?)
        .bind(json_opt_to_string(&rec.oracle)?)
        .bind(serde_json::to_string(&rec.artifact_paths)?)
        .bind(&rec.error)
        .bind(rec.replay_stable.map(|v| if v { 1_i64 } else { 0_i64 }))
        .execute(self.pool)
        .await?;
        Ok(())
    }

    pub async fn list_by_run(
        &self,
        run_id: &str,
    ) -> Result<Vec<VerificationAttemptRecord>, StoreError> {
        let rows = sqlx::query(
            r#"
            SELECT id, run_id, project_id, environment_run_id, candidate_id, chain_id,
                   method, status, started_at, finished_at, duration_ms, request_blob,
                   response_blob, oracle_blob, artifact_paths_json, error, replay_stable
            FROM verification_attempts
            WHERE run_id = ?
            ORDER BY started_at DESC
            "#,
        )
        .bind(run_id)
        .fetch_all(self.pool)
        .await?;
        rows.into_iter().map(row_to_attempt).collect()
    }
}

pub struct VerifiedVulnerabilityStore<'a> {
    pool: &'a SqlitePool,
}

impl<'a> VerifiedVulnerabilityStore<'a> {
    pub fn new(pool: &'a SqlitePool) -> Self {
        Self { pool }
    }

    pub async fn upsert(&self, rec: &VerifiedVulnerabilityRecord) -> Result<(), StoreError> {
        sqlx::query(
            r#"
            INSERT INTO verified_vulnerabilities (
                id, run_id, project_id, title, severity, confidence, vuln_class,
                affected_components_json, business_impact, evidence_summary, repro_steps,
                remediation, source_candidate_ids_json, source_signal_ids_json,
                verification_attempt_ids_json, chain_id, status, first_seen, last_seen
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(id) DO UPDATE SET
                last_seen = excluded.last_seen,
                status = excluded.status,
                verification_attempt_ids_json = excluded.verification_attempt_ids_json
            "#,
        )
        .bind(&rec.id)
        .bind(&rec.run_id)
        .bind(&rec.project_id)
        .bind(&rec.title)
        .bind(&rec.severity)
        .bind(rec.confidence)
        .bind(&rec.vuln_class)
        .bind(serde_json::to_string(&rec.affected_components)?)
        .bind(&rec.business_impact)
        .bind(&rec.evidence_summary)
        .bind(&rec.repro_steps)
        .bind(&rec.remediation)
        .bind(serde_json::to_string(&rec.source_candidate_ids)?)
        .bind(serde_json::to_string(&rec.source_signal_ids)?)
        .bind(serde_json::to_string(&rec.verification_attempt_ids)?)
        .bind(&rec.chain_id)
        .bind(&rec.status)
        .bind(rec.first_seen)
        .bind(rec.last_seen)
        .execute(self.pool)
        .await?;
        Ok(())
    }

    pub async fn list_by_run(
        &self,
        run_id: &str,
    ) -> Result<Vec<VerifiedVulnerabilityRecord>, StoreError> {
        let rows = sqlx::query(
            r#"
            SELECT id, run_id, project_id, title, severity, confidence, vuln_class,
                   affected_components_json, business_impact, evidence_summary, repro_steps,
                   remediation, source_candidate_ids_json, source_signal_ids_json,
                   verification_attempt_ids_json, chain_id, status, first_seen, last_seen
            FROM verified_vulnerabilities
            WHERE run_id = ? AND status != 'FalsePositive'
            ORDER BY
                CASE severity
                    WHEN 'Critical' THEN 0
                    WHEN 'High' THEN 1
                    WHEN 'Medium' THEN 2
                    WHEN 'Low' THEN 3
                    ELSE 4
                END,
                last_seen DESC
            "#,
        )
        .bind(run_id)
        .fetch_all(self.pool)
        .await?;
        rows.into_iter().map(row_to_vulnerability).collect()
    }

    pub async fn list_by_project(
        &self,
        project_id: &str,
    ) -> Result<Vec<VerifiedVulnerabilityRecord>, StoreError> {
        let rows = sqlx::query(
            r#"
            SELECT id, run_id, project_id, title, severity, confidence, vuln_class,
                   affected_components_json, business_impact, evidence_summary, repro_steps,
                   remediation, source_candidate_ids_json, source_signal_ids_json,
                   verification_attempt_ids_json, chain_id, status, first_seen, last_seen
            FROM verified_vulnerabilities
            WHERE project_id = ? AND status != 'FalsePositive'
            ORDER BY last_seen DESC
            "#,
        )
        .bind(project_id)
        .fetch_all(self.pool)
        .await?;
        rows.into_iter().map(row_to_vulnerability).collect()
    }

    pub async fn list_all(&self) -> Result<Vec<VerifiedVulnerabilityRecord>, StoreError> {
        let rows = sqlx::query(
            r#"
            SELECT id, run_id, project_id, title, severity, confidence, vuln_class,
                   affected_components_json, business_impact, evidence_summary, repro_steps,
                   remediation, source_candidate_ids_json, source_signal_ids_json,
                   verification_attempt_ids_json, chain_id, status, first_seen, last_seen
            FROM verified_vulnerabilities
            WHERE status != 'FalsePositive'
            ORDER BY last_seen DESC
            "#,
        )
        .fetch_all(self.pool)
        .await?;
        rows.into_iter().map(row_to_vulnerability).collect()
    }
}

fn launch_profile_readiness(input: &ProjectLaunchProfileInput) -> &'static str {
    if input.target_urls.is_empty() {
        "NeedsTarget"
    } else {
        "Ready"
    }
}

fn row_to_launch_profile(row: sqlx::sqlite::SqliteRow) -> Result<ProjectLaunchProfile, StoreError> {
    Ok(ProjectLaunchProfile {
        id: row.try_get("id")?,
        project_id: row.try_get("project_id")?,
        name: row.try_get("name")?,
        mode: row.try_get("mode")?,
        build_steps: parse_json(row.try_get::<String, _>("build_steps_json")?)?,
        start_steps: parse_json(row.try_get::<String, _>("start_steps_json")?)?,
        stop_steps: parse_json(row.try_get::<String, _>("stop_steps_json")?)?,
        health_checks: parse_json(row.try_get::<String, _>("health_checks_json")?)?,
        target_urls: parse_json(row.try_get::<String, _>("target_urls_json")?)?,
        env_refs: parse_json(row.try_get::<String, _>("env_refs_json")?)?,
        working_dirs: parse_json(row.try_get::<String, _>("working_dirs_json")?)?,
        readiness: row.try_get("readiness")?,
        created_at: row.try_get::<i64, _>("created_at")?,
        updated_at: row.try_get::<i64, _>("updated_at")?,
        is_default: row.try_get::<i64, _>("is_default")? != 0,
    })
}

fn row_to_environment_run(
    row: sqlx::sqlite::SqliteRow,
) -> Result<EnvironmentRunRecord, StoreError> {
    Ok(EnvironmentRunRecord {
        id: row.try_get("id")?,
        run_id: row.try_get("run_id")?,
        project_id: row.try_get("project_id")?,
        profile_id: row.try_get("profile_id")?,
        status: row.try_get("status")?,
        started_at: row.try_get("started_at")?,
        ready_at: row.try_get("ready_at")?,
        stopped_at: row.try_get("stopped_at")?,
        target_urls: parse_json(row.try_get::<String, _>("target_urls_json")?)?,
        health: parse_json_opt(row.try_get("health_blob")?)?,
        logs_dir: row.try_get("logs_dir")?,
        teardown: parse_json_opt(row.try_get("teardown_blob")?)?,
    })
}

fn row_to_nyx_signal(row: sqlx::sqlite::SqliteRow) -> Result<NyxSignalRecord, StoreError> {
    Ok(NyxSignalRecord {
        id: row.try_get("id")?,
        run_id: row.try_get("run_id")?,
        project_id: row.try_get("project_id")?,
        repo_id: row.try_get("repo_id")?,
        repo: row.try_get("repo")?,
        path: row.try_get("path")?,
        line: row.try_get("line")?,
        cap: row.try_get("cap")?,
        rule: row.try_get("rule")?,
        severity: row.try_get("severity")?,
        message: row.try_get("message")?,
        evidence: parse_json_opt(row.try_get("evidence_blob")?)?,
        signal_kind: row.try_get("signal_kind")?,
        meaningful: row.try_get::<i64, _>("meaningful")? != 0,
        suppressed_reason: row.try_get("suppressed_reason")?,
        agent_candidate_id: row.try_get("agent_candidate_id")?,
        created_at: row.try_get::<i64, _>("created_at")?,
    })
}

fn row_to_candidate(row: sqlx::sqlite::SqliteRow) -> Result<PentestCandidateRecord, StoreError> {
    Ok(PentestCandidateRecord {
        id: row.try_get("id")?,
        run_id: row.try_get("run_id")?,
        project_id: row.try_get("project_id")?,
        source: row.try_get("source")?,
        source_ids: parse_json(row.try_get::<String, _>("source_ids_json")?)?,
        title: row.try_get("title")?,
        vuln_class: row.try_get("vuln_class")?,
        severity_guess: row.try_get("severity_guess")?,
        affected_components: parse_json(row.try_get::<String, _>("affected_components_json")?)?,
        hypothesis: row.try_get("hypothesis")?,
        test_plan: row.try_get("test_plan")?,
        status: row.try_get("status")?,
        rejection_reason: row.try_get("rejection_reason")?,
        confidence: row.try_get("confidence")?,
        trace_id: row.try_get("trace_id")?,
        created_at: row.try_get::<i64, _>("created_at")?,
        updated_at: row.try_get::<i64, _>("updated_at")?,
    })
}

fn row_to_attempt(row: sqlx::sqlite::SqliteRow) -> Result<VerificationAttemptRecord, StoreError> {
    Ok(VerificationAttemptRecord {
        id: row.try_get("id")?,
        run_id: row.try_get("run_id")?,
        project_id: row.try_get("project_id")?,
        environment_run_id: row.try_get("environment_run_id")?,
        candidate_id: row.try_get("candidate_id")?,
        chain_id: row.try_get("chain_id")?,
        method: row.try_get("method")?,
        status: row.try_get("status")?,
        started_at: row.try_get::<i64, _>("started_at")?,
        finished_at: row.try_get("finished_at")?,
        duration_ms: row.try_get("duration_ms")?,
        request: parse_json_opt(row.try_get("request_blob")?)?,
        response: parse_json_opt(row.try_get("response_blob")?)?,
        oracle: parse_json_opt(row.try_get("oracle_blob")?)?,
        artifact_paths: parse_json(row.try_get::<String, _>("artifact_paths_json")?)?,
        error: row.try_get("error")?,
        replay_stable: row.try_get::<Option<i64>, _>("replay_stable")?.map(|v| v != 0),
    })
}

fn row_to_vulnerability(
    row: sqlx::sqlite::SqliteRow,
) -> Result<VerifiedVulnerabilityRecord, StoreError> {
    Ok(VerifiedVulnerabilityRecord {
        id: row.try_get("id")?,
        run_id: row.try_get("run_id")?,
        project_id: row.try_get("project_id")?,
        title: row.try_get("title")?,
        severity: row.try_get("severity")?,
        confidence: row.try_get("confidence")?,
        vuln_class: row.try_get("vuln_class")?,
        affected_components: parse_json(row.try_get::<String, _>("affected_components_json")?)?,
        business_impact: row.try_get("business_impact")?,
        evidence_summary: row.try_get("evidence_summary")?,
        repro_steps: row.try_get("repro_steps")?,
        remediation: row.try_get("remediation")?,
        source_candidate_ids: parse_json(row.try_get::<String, _>("source_candidate_ids_json")?)?,
        source_signal_ids: parse_json(row.try_get::<String, _>("source_signal_ids_json")?)?,
        verification_attempt_ids: parse_json(
            row.try_get::<String, _>("verification_attempt_ids_json")?,
        )?,
        chain_id: row.try_get("chain_id")?,
        status: row.try_get("status")?,
        first_seen: row.try_get::<i64, _>("first_seen")?,
        last_seen: row.try_get::<i64, _>("last_seen")?,
    })
}

fn parse_json<T: serde::de::DeserializeOwned>(raw: String) -> Result<T, StoreError> {
    Ok(serde_json::from_str(&raw)?)
}

fn parse_json_opt<T: serde::de::DeserializeOwned>(
    raw: Option<String>,
) -> Result<Option<T>, StoreError> {
    raw.map(|s| serde_json::from_str(&s)).transpose().map_err(StoreError::from)
}

fn json_opt_to_string(value: &Option<serde_json::Value>) -> Result<Option<String>, StoreError> {
    value.as_ref().map(serde_json::to_string).transpose().map_err(StoreError::from)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::testutil::{fresh_store, sample_repo_for_project, sample_run};

    #[tokio::test]
    async fn launch_profile_roundtrips_default() {
        let (_tmp, s) = fresh_store().await;
        s.projects().create("p-1", "acme", None, None, None, 1_000).await.unwrap();
        let input = ProjectLaunchProfileInput {
            name: Some("local dev".to_string()),
            mode: Some("custom-commands".to_string()),
            start_steps: vec![LaunchStep {
                command: "npm run dev".to_string(),
                repo_id: None,
                repo_name: Some("web".to_string()),
                working_directory: Some("frontend".to_string()),
                timeout_seconds: Some(120),
            }],
            health_checks: vec![LaunchHealthCheck {
                kind: "http".to_string(),
                url: Some("http://localhost:3000/health".to_string()),
                host: None,
                port: None,
                command: None,
                timeout_seconds: Some(10),
            }],
            target_urls: vec!["http://localhost:3000".to_string()],
            ..empty_input()
        };
        let row = s.launch_profiles().upsert_default("p-1", &input, 2_000).await.unwrap();
        assert_eq!(row.readiness, "Ready");
        assert_eq!(row.start_steps[0].command, "npm run dev");
        assert!(row.is_default);
    }

    #[tokio::test]
    async fn launch_profile_target_url_is_enough_to_be_ready() {
        let (_tmp, s) = fresh_store().await;
        s.projects().create("p-1", "acme", None, None, None, 1_000).await.unwrap();
        let row = s
            .launch_profiles()
            .upsert_default(
                "p-1",
                &ProjectLaunchProfileInput {
                    mode: Some("already-running".to_string()),
                    target_urls: vec!["http://localhost:3000".to_string()],
                    ..empty_input()
                },
                2_000,
            )
            .await
            .unwrap();
        assert_eq!(row.readiness, "Ready");
        assert!(row.start_steps.is_empty());
        assert!(row.health_checks.is_empty());
    }

    #[tokio::test]
    async fn signal_candidate_attempt_vulnerability_roundtrip() {
        let (_tmp, s) = fresh_store().await;
        s.projects().create("p-1", "acme", None, None, None, 1_000).await.unwrap();
        let profile = s
            .launch_profiles()
            .upsert_default(
                "p-1",
                &ProjectLaunchProfileInput {
                    start_steps: vec![LaunchStep {
                        command: "true".to_string(),
                        repo_id: None,
                        repo_name: None,
                        working_directory: None,
                        timeout_seconds: None,
                    }],
                    target_urls: vec!["http://localhost:3000".to_string()],
                    ..empty_input()
                },
                2_000,
            )
            .await
            .unwrap();
        let mut run = sample_run("run-1");
        run.project_id = Some("p-1".to_string());
        run.kind = "Pentest".to_string();
        s.runs().insert(&run).await.unwrap();
        let env = EnvironmentRunRecord {
            id: "env-1".to_string(),
            run_id: "run-1".to_string(),
            project_id: "p-1".to_string(),
            profile_id: profile.id,
            status: "Ready".to_string(),
            started_at: Some(3_000),
            ready_at: Some(3_100),
            stopped_at: None,
            target_urls: vec!["http://localhost:3000".to_string()],
            health: Some(serde_json::json!({"ok": true})),
            logs_dir: None,
            teardown: None,
        };
        s.environment_runs().insert(&env).await.unwrap();
        let signal = NyxSignalRecord {
            id: "sig-1".to_string(),
            run_id: "run-1".to_string(),
            project_id: "p-1".to_string(),
            repo_id: "repo-1".to_string(),
            repo: "web".to_string(),
            path: "src/main.rs".to_string(),
            line: Some(10),
            cap: "xss".to_string(),
            rule: "reflected".to_string(),
            severity: "High".to_string(),
            message: Some("possible reflected XSS".to_string()),
            evidence: Some(serde_json::json!({"sink":"html"})),
            signal_kind: "security".to_string(),
            meaningful: true,
            suppressed_reason: None,
            agent_candidate_id: None,
            created_at: 3_200,
        };
        let repo = sample_repo_for_project("web", "p-1");
        let repo_id = repo.id.clone();
        s.repos().upsert(&repo).await.unwrap();
        let signal = NyxSignalRecord { repo_id: repo_id.clone(), ..signal };
        s.nyx_signals().insert(&signal).await.unwrap();
        assert_eq!(s.nyx_signals().list_by_run("run-1", true).await.unwrap().len(), 1);

        let candidate = PentestCandidateRecord {
            id: "pc-1".to_string(),
            run_id: "run-1".to_string(),
            project_id: "p-1".to_string(),
            source: "NyxSignal".to_string(),
            source_ids: vec!["sig-1".to_string()],
            title: "Reflected XSS candidate".to_string(),
            vuln_class: "xss".to_string(),
            severity_guess: "High".to_string(),
            affected_components: vec![serde_json::json!({"repo_id": repo_id})],
            hypothesis: "Nyx found an HTML sink".to_string(),
            test_plan: "{\"method\":\"http\"}".to_string(),
            status: "NeedsLiveTest".to_string(),
            rejection_reason: None,
            confidence: 0.7,
            trace_id: None,
            created_at: 3_300,
            updated_at: 3_300,
        };
        s.pentest_candidates().insert(&candidate).await.unwrap();
        s.nyx_signals().set_candidate("sig-1", "pc-1").await.unwrap();
        assert_eq!(s.pentest_candidates().list_by_run("run-1").await.unwrap()[0].id, "pc-1");

        let attempt = VerificationAttemptRecord {
            id: "va-1".to_string(),
            run_id: "run-1".to_string(),
            project_id: "p-1".to_string(),
            environment_run_id: "env-1".to_string(),
            candidate_id: Some("pc-1".to_string()),
            chain_id: None,
            method: "http".to_string(),
            status: "Confirmed".to_string(),
            started_at: 3_400,
            finished_at: Some(3_450),
            duration_ms: Some(50),
            request: Some(serde_json::json!({"url":"http://localhost:3000"})),
            response: Some(serde_json::json!({"status":200})),
            oracle: Some(serde_json::json!({"matched":true})),
            artifact_paths: vec![],
            error: None,
            replay_stable: Some(true),
        };
        s.verification_attempts().insert(&attempt).await.unwrap();
        assert_eq!(s.verification_attempts().list_by_run("run-1").await.unwrap()[0].id, "va-1");

        let vuln = VerifiedVulnerabilityRecord {
            id: "vuln-1".to_string(),
            run_id: "run-1".to_string(),
            project_id: "p-1".to_string(),
            title: "Reflected XSS".to_string(),
            severity: "High".to_string(),
            confidence: 0.95,
            vuln_class: "xss".to_string(),
            affected_components: vec![serde_json::json!({"repo":"web"})],
            business_impact: "Session theft in local dev build".to_string(),
            evidence_summary: "HTTP oracle confirmed the payload reflected".to_string(),
            repro_steps: "Open the confirmed URL".to_string(),
            remediation: "Escape reflected HTML".to_string(),
            source_candidate_ids: vec!["pc-1".to_string()],
            source_signal_ids: vec!["sig-1".to_string()],
            verification_attempt_ids: vec!["va-1".to_string()],
            chain_id: None,
            status: "Open".to_string(),
            first_seen: 3_450,
            last_seen: 3_450,
        };
        s.verified_vulnerabilities().upsert(&vuln).await.unwrap();
        assert_eq!(
            s.verified_vulnerabilities().list_by_run("run-1").await.unwrap()[0].id,
            "vuln-1"
        );
    }

    fn empty_input() -> ProjectLaunchProfileInput {
        ProjectLaunchProfileInput {
            name: None,
            mode: None,
            build_steps: Vec::new(),
            start_steps: Vec::new(),
            stop_steps: Vec::new(),
            health_checks: Vec::new(),
            target_urls: Vec::new(),
            env_refs: Vec::new(),
            working_dirs: Vec::new(),
        }
    }
}

//! Attack graph store.
//!
//! The graph is a derived index over first-class Nyctos artifacts. Writers
//! keep inserting into their owning tables, then mirror the relationship
//! into `attack_graph_nodes` / `attack_graph_edges` so later UI and report
//! surfaces can answer provenance and blast-radius questions without
//! reverse-engineering every table's JSON columns.

use std::collections::{HashMap, HashSet};

use sqlx::{Row, SqlitePool};

use nyctos_types::attack_graph::{
    AttackGraphEdgeRecord, AttackGraphEvidenceTrail, AttackGraphNodeRecord, EDGE_CHAINED_WITH,
    EDGE_DERIVED_CANDIDATE, EDGE_TARGETS, EDGE_TOUCHES_OBJECT, EDGE_USES_ROLE, EDGE_VERIFIED_AS,
    NODE_CANDIDATE, NODE_CHAIN, NODE_ENDPOINT, NODE_FORM, NODE_OBJECT, NODE_PARAMETER, NODE_ROLE,
    NODE_ROUTE, NODE_SIGNAL, NODE_VERIFICATION_ATTEMPT, NODE_VERIFIED_VULNERABILITY,
};
use nyctos_types::chain::ChainRecord;
use nyctos_types::product::{
    ApiClientCallModel, FormModel, FrontendRouteModel, NyxSignalRecord, PentestCandidateRecord,
    RouteModelEndpoint, RouteModelRecord, VerificationAttemptRecord, VerifiedVulnerabilityRecord,
};

use super::candidate::CandidateFindingRecord;
use super::project::DEFAULT_PROJECT_ID;
use crate::store::StoreError;
use crate::time::now_epoch_ms;

const GRAPH_HASH_BYTES: usize = 12;
const SOURCE_LINE_WINDOW: i64 = 80;
const TOUCH_QUERY_MAX_DEPTH: usize = 8;
const EVIDENCE_QUERY_MAX_DEPTH: usize = 8;

pub fn attack_graph_node_id(run_id: &str, kind: &str, stable_key: &str) -> String {
    format!("agn-{}", short_hash(&[run_id, kind, stable_key]))
}

pub fn attack_graph_edge_id(
    run_id: &str,
    kind: &str,
    from_node_id: &str,
    to_node_id: &str,
    evidence_ref: Option<&str>,
) -> String {
    format!(
        "age-{}",
        short_hash(&[run_id, kind, from_node_id, to_node_id, evidence_ref.unwrap_or("")])
    )
}

fn short_hash(parts: &[&str]) -> String {
    let mut h = blake3::Hasher::new();
    for part in parts {
        h.update(part.as_bytes());
        h.update(b"\0");
    }
    let digest = h.finalize();
    let mut out = String::with_capacity(GRAPH_HASH_BYTES * 2);
    for b in &digest.as_bytes()[..GRAPH_HASH_BYTES] {
        out.push_str(&format!("{b:02x}"));
    }
    out
}

pub struct AttackGraphStore<'a> {
    pool: &'a SqlitePool,
}

impl<'a> AttackGraphStore<'a> {
    pub fn new(pool: &'a SqlitePool) -> Self {
        Self { pool }
    }

    pub async fn upsert_node(&self, rec: &AttackGraphNodeRecord) -> Result<(), StoreError> {
        sqlx::query(
            r#"
            INSERT INTO attack_graph_nodes (
                id, run_id, project_id, kind, stable_key, label, ref_id,
                properties_json, created_at, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(id) DO UPDATE SET
                project_id = excluded.project_id,
                stable_key = excluded.stable_key,
                label = excluded.label,
                ref_id = excluded.ref_id,
                properties_json = excluded.properties_json,
                updated_at = excluded.updated_at
            "#,
        )
        .bind(&rec.id)
        .bind(&rec.run_id)
        .bind(&rec.project_id)
        .bind(&rec.kind)
        .bind(&rec.stable_key)
        .bind(&rec.label)
        .bind(&rec.ref_id)
        .bind(serde_json::to_string(&rec.properties)?)
        .bind(rec.created_at)
        .bind(rec.updated_at)
        .execute(self.pool)
        .await?;
        Ok(())
    }

    pub async fn upsert_edge(&self, rec: &AttackGraphEdgeRecord) -> Result<(), StoreError> {
        sqlx::query(
            r#"
            INSERT INTO attack_graph_edges (
                id, run_id, project_id, kind, from_node_id, to_node_id,
                evidence_ref, properties_json, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(id) DO UPDATE SET
                project_id = excluded.project_id,
                evidence_ref = excluded.evidence_ref,
                properties_json = excluded.properties_json
            "#,
        )
        .bind(&rec.id)
        .bind(&rec.run_id)
        .bind(&rec.project_id)
        .bind(&rec.kind)
        .bind(&rec.from_node_id)
        .bind(&rec.to_node_id)
        .bind(&rec.evidence_ref)
        .bind(serde_json::to_string(&rec.properties)?)
        .bind(rec.created_at)
        .execute(self.pool)
        .await?;
        Ok(())
    }

    pub async fn upsert_node_by_key(
        &self,
        run_id: &str,
        project_id: &str,
        kind: &str,
        stable_key: &str,
        label: &str,
        ref_id: Option<&str>,
        properties: serde_json::Value,
        now_ms: i64,
    ) -> Result<AttackGraphNodeRecord, StoreError> {
        let rec = AttackGraphNodeRecord {
            id: attack_graph_node_id(run_id, kind, stable_key),
            run_id: run_id.to_string(),
            project_id: project_id.to_string(),
            kind: kind.to_string(),
            stable_key: stable_key.to_string(),
            label: label.to_string(),
            ref_id: ref_id.map(str::to_string),
            properties,
            created_at: now_ms,
            updated_at: now_ms,
        };
        self.upsert_node(&rec).await?;
        Ok(rec)
    }

    pub async fn upsert_edge_by_key(
        &self,
        run_id: &str,
        project_id: &str,
        kind: &str,
        from_node_id: &str,
        to_node_id: &str,
        evidence_ref: Option<&str>,
        properties: serde_json::Value,
        now_ms: i64,
    ) -> Result<AttackGraphEdgeRecord, StoreError> {
        if from_node_id == to_node_id {
            return Ok(AttackGraphEdgeRecord {
                id: attack_graph_edge_id(run_id, kind, from_node_id, to_node_id, evidence_ref),
                run_id: run_id.to_string(),
                project_id: project_id.to_string(),
                kind: kind.to_string(),
                from_node_id: from_node_id.to_string(),
                to_node_id: to_node_id.to_string(),
                evidence_ref: evidence_ref.map(str::to_string),
                properties,
                created_at: now_ms,
            });
        }
        let rec = AttackGraphEdgeRecord {
            id: attack_graph_edge_id(run_id, kind, from_node_id, to_node_id, evidence_ref),
            run_id: run_id.to_string(),
            project_id: project_id.to_string(),
            kind: kind.to_string(),
            from_node_id: from_node_id.to_string(),
            to_node_id: to_node_id.to_string(),
            evidence_ref: evidence_ref.map(str::to_string),
            properties,
            created_at: now_ms,
        };
        self.upsert_edge(&rec).await?;
        Ok(rec)
    }

    pub async fn get_node(&self, id: &str) -> Result<Option<AttackGraphNodeRecord>, StoreError> {
        let row = sqlx::query(
            r#"
            SELECT id, run_id, project_id, kind, stable_key, label, ref_id,
                   properties_json, created_at, updated_at
            FROM attack_graph_nodes
            WHERE id = ?
            "#,
        )
        .bind(id)
        .fetch_optional(self.pool)
        .await?;
        row.map(row_to_node).transpose()
    }

    pub async fn get_node_by_stable_key(
        &self,
        run_id: &str,
        kind: &str,
        stable_key: &str,
    ) -> Result<Option<AttackGraphNodeRecord>, StoreError> {
        let row = sqlx::query(
            r#"
            SELECT id, run_id, project_id, kind, stable_key, label, ref_id,
                   properties_json, created_at, updated_at
            FROM attack_graph_nodes
            WHERE run_id = ? AND kind = ? AND stable_key = ?
            "#,
        )
        .bind(run_id)
        .bind(kind)
        .bind(stable_key)
        .fetch_optional(self.pool)
        .await?;
        row.map(row_to_node).transpose()
    }

    pub async fn get_node_by_ref(
        &self,
        run_id: &str,
        kind: &str,
        ref_id: &str,
    ) -> Result<Option<AttackGraphNodeRecord>, StoreError> {
        let row = sqlx::query(
            r#"
            SELECT id, run_id, project_id, kind, stable_key, label, ref_id,
                   properties_json, created_at, updated_at
            FROM attack_graph_nodes
            WHERE run_id = ? AND kind = ? AND ref_id = ?
            ORDER BY updated_at DESC
            LIMIT 1
            "#,
        )
        .bind(run_id)
        .bind(kind)
        .bind(ref_id)
        .fetch_optional(self.pool)
        .await?;
        row.map(row_to_node).transpose()
    }

    pub async fn list_nodes_by_run(
        &self,
        run_id: &str,
    ) -> Result<Vec<AttackGraphNodeRecord>, StoreError> {
        let rows = sqlx::query(
            r#"
            SELECT id, run_id, project_id, kind, stable_key, label, ref_id,
                   properties_json, created_at, updated_at
            FROM attack_graph_nodes
            WHERE run_id = ?
            ORDER BY kind, label, id
            "#,
        )
        .bind(run_id)
        .fetch_all(self.pool)
        .await?;
        rows.into_iter().map(row_to_node).collect()
    }

    pub async fn list_edges_by_run(
        &self,
        run_id: &str,
    ) -> Result<Vec<AttackGraphEdgeRecord>, StoreError> {
        let rows = sqlx::query(
            r#"
            SELECT id, run_id, project_id, kind, from_node_id, to_node_id,
                   evidence_ref, properties_json, created_at
            FROM attack_graph_edges
            WHERE run_id = ?
            ORDER BY kind, from_node_id, to_node_id, id
            "#,
        )
        .bind(run_id)
        .fetch_all(self.pool)
        .await?;
        rows.into_iter().map(row_to_edge).collect()
    }

    pub async fn evidence_for_vulnerability(
        &self,
        vulnerability_id: &str,
    ) -> Result<Option<AttackGraphEvidenceTrail>, StoreError> {
        let focus =
            self.node_by_kind_ref_any_run(NODE_VERIFIED_VULNERABILITY, vulnerability_id).await?;
        let Some(focus) = focus else {
            return Ok(None);
        };

        let mut nodes: HashMap<String, AttackGraphNodeRecord> =
            HashMap::from([(focus.id.clone(), focus.clone())]);
        let mut edges: HashMap<String, AttackGraphEdgeRecord> = HashMap::new();
        let mut expanded: HashSet<String> = HashSet::new();
        let mut frontier = vec![focus.id.clone()];

        for _ in 0..EVIDENCE_QUERY_MAX_DEPTH {
            let mut next = Vec::new();
            for node_id in frontier {
                if !expanded.insert(node_id.clone()) {
                    continue;
                }
                for edge in self.list_edges_to(&node_id).await? {
                    if let Some(from) = self.get_node(&edge.from_node_id).await? {
                        if !nodes.contains_key(&from.id) {
                            next.push(from.id.clone());
                        }
                        nodes.insert(from.id.clone(), from);
                    }
                    edges.insert(edge.id.clone(), edge);
                }
            }
            if next.is_empty() {
                break;
            }
            frontier = next;
        }

        let context_ids: Vec<String> = nodes.keys().cloned().collect();
        for node_id in context_ids {
            for edge in self.list_context_edges_from(&node_id).await? {
                if let Some(to) = self.get_node(&edge.to_node_id).await? {
                    nodes.insert(to.id.clone(), to);
                }
                edges.insert(edge.id.clone(), edge);
            }
        }

        Ok(Some(AttackGraphEvidenceTrail {
            focus,
            nodes: sorted_nodes(nodes),
            edges: sorted_edges(edges),
        }))
    }

    pub async fn vulnerabilities_touching(
        &self,
        run_id: &str,
        kind: &str,
        stable_key: &str,
    ) -> Result<Vec<AttackGraphNodeRecord>, StoreError> {
        let Some(node) = self.get_node_by_stable_key(run_id, kind, stable_key).await? else {
            return Ok(Vec::new());
        };
        self.vulnerabilities_touching_node(&node.id).await
    }

    pub async fn vulnerabilities_touching_node(
        &self,
        node_id: &str,
    ) -> Result<Vec<AttackGraphNodeRecord>, StoreError> {
        let Some(start) = self.get_node(node_id).await? else {
            return Ok(Vec::new());
        };
        let mut found: HashMap<String, AttackGraphNodeRecord> = HashMap::new();
        if start.kind == NODE_VERIFIED_VULNERABILITY {
            found.insert(start.id.clone(), start.clone());
        }

        let mut visited: HashSet<String> = HashSet::from([start.id.clone()]);
        let mut frontier = vec![start.id];
        for _ in 0..TOUCH_QUERY_MAX_DEPTH {
            let mut next = Vec::new();
            for current in frontier {
                for edge in self.list_incident_edges(&current).await? {
                    let other_id = if edge.from_node_id == current {
                        edge.to_node_id
                    } else {
                        edge.from_node_id
                    };
                    if !visited.insert(other_id.clone()) {
                        continue;
                    }
                    if let Some(node) = self.get_node(&other_id).await? {
                        if node.kind == NODE_VERIFIED_VULNERABILITY {
                            found.insert(node.id.clone(), node.clone());
                        }
                        next.push(node.id);
                    }
                }
            }
            if next.is_empty() {
                break;
            }
            frontier = next;
        }
        let mut out = found.into_values().collect::<Vec<_>>();
        out.sort_by(|a, b| {
            severity_rank(&b.properties)
                .cmp(&severity_rank(&a.properties))
                .then_with(|| b.updated_at.cmp(&a.updated_at))
                .then_with(|| a.label.cmp(&b.label))
        });
        Ok(out)
    }

    pub async fn record_route_model(&self, rec: &RouteModelRecord) -> Result<(), StoreError> {
        let now = rec.created_at;
        for route in &rec.model.backend_routes {
            self.record_backend_route(rec, route, now).await?;
        }
        for route in &rec.model.frontend_routes {
            self.record_frontend_route(rec, route, now).await?;
        }
        for call in &rec.model.api_client_calls {
            self.record_api_client_call(rec, call, now).await?;
        }
        for form in &rec.model.forms {
            self.record_form(rec, form, now).await?;
        }
        Ok(())
    }

    pub async fn record_nyx_signal(&self, rec: &NyxSignalRecord) -> Result<(), StoreError> {
        let now = rec.created_at;
        let node = self
            .upsert_node_by_key(
                &rec.run_id,
                &rec.project_id,
                NODE_SIGNAL,
                &signal_key(&rec.id),
                &signal_label(rec),
                Some(&rec.id),
                serde_json::json!({
                    "repo_id": rec.repo_id,
                    "repo": rec.repo,
                    "path": rec.path,
                    "line": rec.line,
                    "cap": rec.cap,
                    "rule": rec.rule,
                    "severity": rec.severity,
                    "message": rec.message,
                    "signal_kind": rec.signal_kind,
                    "meaningful": rec.meaningful,
                    "suppressed_reason": rec.suppressed_reason,
                    "evidence": rec.evidence,
                }),
                now,
            )
            .await?;
        let file = self
            .upsert_file_object(&rec.run_id, &rec.project_id, Some(&rec.repo), &rec.path, now)
            .await?;
        self.upsert_edge_by_key(
            &rec.run_id,
            &rec.project_id,
            EDGE_TOUCHES_OBJECT,
            &node.id,
            &file.id,
            Some(&rec.id),
            serde_json::json!({"reason": "static_signal_location"}),
            now,
        )
        .await?;
        self.link_source_location_to_targets(
            &rec.run_id,
            &rec.project_id,
            &node.id,
            Some(&rec.repo),
            &rec.path,
            rec.line,
            Some(&rec.id),
            now,
        )
        .await?;
        Ok(())
    }

    pub async fn record_pentest_candidate(
        &self,
        rec: &PentestCandidateRecord,
    ) -> Result<(), StoreError> {
        let now = rec.updated_at.max(rec.created_at);
        let node = self
            .upsert_node_by_key(
                &rec.run_id,
                &rec.project_id,
                NODE_CANDIDATE,
                &candidate_key(&rec.id),
                &rec.title,
                Some(&rec.id),
                serde_json::json!({
                    "source": rec.source,
                    "source_ids": rec.source_ids,
                    "vuln_class": rec.vuln_class,
                    "severity": rec.severity_guess,
                    "status": rec.status,
                    "confidence": rec.confidence,
                    "hypothesis": rec.hypothesis,
                    "affected_components": rec.affected_components,
                    "trace_id": rec.trace_id,
                }),
                now,
            )
            .await?;
        for source_id in &rec.source_ids {
            let source =
                self.ensure_source_node(&rec.run_id, &rec.project_id, source_id, now).await?;
            self.upsert_edge_by_key(
                &rec.run_id,
                &rec.project_id,
                EDGE_DERIVED_CANDIDATE,
                &source.id,
                &node.id,
                Some(source_id),
                serde_json::json!({"source": rec.source}),
                now,
            )
            .await?;
        }
        self.record_component_targets(
            &rec.run_id,
            &rec.project_id,
            &node.id,
            &rec.affected_components,
            Some(&rec.id),
            now,
        )
        .await?;
        Ok(())
    }

    pub async fn record_candidate_finding(
        &self,
        rec: &CandidateFindingRecord,
    ) -> Result<(), StoreError> {
        let project_id = self.project_id_for_run(&rec.run_id).await?;
        let now = now_epoch_ms();
        let node = self
            .upsert_node_by_key(
                &rec.run_id,
                &project_id,
                NODE_CANDIDATE,
                &candidate_key(&rec.id),
                &rec.rationale.clone().unwrap_or_else(|| format!("{} candidate", rec.cap)),
                Some(&rec.id),
                serde_json::json!({
                    "source": "candidate_findings",
                    "repo": rec.repo,
                    "path": rec.path,
                    "line": rec.line,
                    "cap": rec.cap,
                    "rule_hint": rec.rule_hint,
                    "rationale": rec.rationale,
                    "suggested_payload_hint": rec.suggested_payload_hint,
                    "status": rec.status,
                    "prompt_version": rec.prompt_version,
                    "trace_id": rec.trace_id,
                }),
                now,
            )
            .await?;
        let file = self
            .upsert_file_object(&rec.run_id, &project_id, Some(&rec.repo), &rec.path, now)
            .await?;
        self.upsert_edge_by_key(
            &rec.run_id,
            &project_id,
            EDGE_TOUCHES_OBJECT,
            &node.id,
            &file.id,
            Some(&rec.id),
            serde_json::json!({"reason": "candidate_location"}),
            now,
        )
        .await?;
        self.link_source_location_to_targets(
            &rec.run_id,
            &project_id,
            &node.id,
            Some(&rec.repo),
            &rec.path,
            rec.line,
            Some(&rec.id),
            now,
        )
        .await?;
        Ok(())
    }

    pub async fn record_verification_attempt(
        &self,
        rec: &VerificationAttemptRecord,
    ) -> Result<(), StoreError> {
        let now = rec.finished_at.unwrap_or(rec.started_at);
        let node = self
            .upsert_node_by_key(
                &rec.run_id,
                &rec.project_id,
                NODE_VERIFICATION_ATTEMPT,
                &verification_attempt_key(&rec.id),
                &format!("{} {}", rec.method, rec.status),
                Some(&rec.id),
                serde_json::json!({
                    "environment_run_id": rec.environment_run_id,
                    "candidate_id": rec.candidate_id,
                    "chain_id": rec.chain_id,
                    "method": rec.method,
                    "status": rec.status,
                    "started_at": rec.started_at,
                    "finished_at": rec.finished_at,
                    "duration_ms": rec.duration_ms,
                    "request": rec.request,
                    "response": rec.response,
                    "oracle": rec.oracle,
                    "artifact_paths": rec.artifact_paths,
                    "error": rec.error,
                    "replay_stable": rec.replay_stable,
                }),
                now,
            )
            .await?;
        if let Some(candidate_id) = &rec.candidate_id {
            let candidate =
                self.ensure_candidate_node(&rec.run_id, &rec.project_id, candidate_id, now).await?;
            self.upsert_edge_by_key(
                &rec.run_id,
                &rec.project_id,
                EDGE_VERIFIED_AS,
                &candidate.id,
                &node.id,
                Some(&rec.id),
                serde_json::json!({"stage": "verification_attempt"}),
                now,
            )
            .await?;
        }
        if let Some(chain_id) = &rec.chain_id {
            let chain = self.ensure_chain_node(&rec.run_id, &rec.project_id, chain_id, now).await?;
            self.upsert_edge_by_key(
                &rec.run_id,
                &rec.project_id,
                EDGE_VERIFIED_AS,
                &chain.id,
                &node.id,
                Some(&rec.id),
                serde_json::json!({"stage": "chain_verification_attempt"}),
                now,
            )
            .await?;
        }
        let request_components =
            rec.request.as_ref().map(component_values_from_json).unwrap_or_default();
        self.record_component_targets(
            &rec.run_id,
            &rec.project_id,
            &node.id,
            &request_components,
            Some(&rec.id),
            now,
        )
        .await?;
        Ok(())
    }

    pub async fn record_verified_vulnerability(
        &self,
        rec: &VerifiedVulnerabilityRecord,
    ) -> Result<(), StoreError> {
        let now = rec.last_seen;
        let node = self
            .upsert_node_by_key(
                &rec.run_id,
                &rec.project_id,
                NODE_VERIFIED_VULNERABILITY,
                &verified_vulnerability_key(&rec.id),
                &rec.title,
                Some(&rec.id),
                serde_json::json!({
                    "title": rec.title,
                    "severity": rec.severity,
                    "confidence": rec.confidence,
                    "vuln_class": rec.vuln_class,
                    "status": rec.status,
                    "business_impact": rec.business_impact,
                    "evidence_summary": rec.evidence_summary,
                    "affected_components": rec.affected_components,
                    "source_candidate_ids": rec.source_candidate_ids,
                    "source_signal_ids": rec.source_signal_ids,
                    "verification_attempt_ids": rec.verification_attempt_ids,
                    "chain_id": rec.chain_id,
                }),
                now,
            )
            .await?;
        for candidate_id in &rec.source_candidate_ids {
            let candidate =
                self.ensure_candidate_node(&rec.run_id, &rec.project_id, candidate_id, now).await?;
            self.upsert_edge_by_key(
                &rec.run_id,
                &rec.project_id,
                EDGE_VERIFIED_AS,
                &candidate.id,
                &node.id,
                Some(candidate_id),
                serde_json::json!({"source": "source_candidate_ids"}),
                now,
            )
            .await?;
        }
        for signal_id in &rec.source_signal_ids {
            let signal =
                self.ensure_source_node(&rec.run_id, &rec.project_id, signal_id, now).await?;
            self.upsert_edge_by_key(
                &rec.run_id,
                &rec.project_id,
                EDGE_VERIFIED_AS,
                &signal.id,
                &node.id,
                Some(signal_id),
                serde_json::json!({"source": "source_signal_ids"}),
                now,
            )
            .await?;
        }
        for attempt_id in &rec.verification_attempt_ids {
            let attempt = self
                .ensure_verification_attempt_node(&rec.run_id, &rec.project_id, attempt_id, now)
                .await?;
            self.upsert_edge_by_key(
                &rec.run_id,
                &rec.project_id,
                EDGE_VERIFIED_AS,
                &attempt.id,
                &node.id,
                Some(attempt_id),
                serde_json::json!({"source": "verification_attempt_ids"}),
                now,
            )
            .await?;
        }
        if let Some(chain_id) = &rec.chain_id {
            let chain = self.ensure_chain_node(&rec.run_id, &rec.project_id, chain_id, now).await?;
            self.upsert_edge_by_key(
                &rec.run_id,
                &rec.project_id,
                EDGE_CHAINED_WITH,
                &chain.id,
                &node.id,
                Some(chain_id),
                serde_json::json!({"source": "chain_id"}),
                now,
            )
            .await?;
        }
        self.record_component_targets(
            &rec.run_id,
            &rec.project_id,
            &node.id,
            &rec.affected_components,
            Some(&rec.id),
            now,
        )
        .await?;
        Ok(())
    }

    pub async fn record_chain(&self, rec: &ChainRecord) -> Result<(), StoreError> {
        let project_id = self.project_id_for_run(&rec.run_id).await?;
        let now = now_epoch_ms();
        let node = self
            .upsert_node_by_key(
                &rec.run_id,
                &project_id,
                NODE_CHAIN,
                &chain_key(&rec.id),
                &rec.id,
                Some(&rec.id),
                serde_json::json!({
                    "cross_repo": rec.cross_repo,
                    "member_ids": rec.member_ids,
                    "rationale_blob": rec.rationale_blob,
                    "attack_provenance": rec.attack_provenance,
                    "prompt_version": rec.prompt_version,
                    "status": rec.status,
                    "verification_attempt_id": rec.verification_attempt_id,
                    "evidence_blob": rec.evidence_blob,
                    "severity": rec.severity,
                }),
                now,
            )
            .await?;
        let member_ids = parse_member_ids(&rec.member_ids);
        for member_id in member_ids {
            let member =
                self.resolve_member_node(&rec.run_id, &project_id, &member_id, now).await?;
            self.upsert_edge_by_key(
                &rec.run_id,
                &project_id,
                EDGE_CHAINED_WITH,
                &node.id,
                &member.id,
                Some(&member_id),
                serde_json::json!({"source": "chain.member_ids"}),
                now,
            )
            .await?;
        }
        Ok(())
    }

    async fn record_backend_route(
        &self,
        rec: &RouteModelRecord,
        route: &RouteModelEndpoint,
        now: i64,
    ) -> Result<(), StoreError> {
        let repo = route.repo.as_deref();
        let route_node = self
            .upsert_route_node(&rec.run_id, &rec.project_id, &route.path, "backend", now)
            .await?;
        let endpoint_key = endpoint_key(
            "backend",
            repo,
            &route.method,
            &route.path,
            route.handler_file.as_deref(),
            route.line,
        );
        let endpoint = self
            .upsert_node_by_key(
                &rec.run_id,
                &rec.project_id,
                NODE_ENDPOINT,
                &endpoint_key,
                &format!("{} {}", route.method, route.path),
                None,
                serde_json::json!({
                    "source": "backend_route",
                    "repo": route.repo,
                    "method": route.method,
                    "path": route.path,
                    "handler_file": route.handler_file,
                    "line": route.line,
                    "middleware": route.middleware,
                    "auth_checks": route.auth_checks,
                    "role_checks": route.role_checks,
                    "body_fields": route.body_fields,
                    "state_changing": route.state_changing,
                    "confidence": route.confidence,
                    "evidence": route.evidence,
                }),
                now,
            )
            .await?;
        self.upsert_edge_by_key(
            &rec.run_id,
            &rec.project_id,
            EDGE_TARGETS,
            &endpoint.id,
            &route_node.id,
            None,
            serde_json::json!({"source": "route_model.backend"}),
            now,
        )
        .await?;
        self.record_route_details(
            &rec.run_id,
            &rec.project_id,
            &endpoint.id,
            &route_node.id,
            &route.path,
            &route.params,
            &route.body_fields,
            &route.auth_checks,
            &route.role_checks,
            now,
        )
        .await?;
        if let (Some(repo), Some(path)) = (repo, route.handler_file.as_deref()) {
            self.link_existing_signals_to_target(
                &rec.run_id,
                &rec.project_id,
                repo,
                path,
                route.line,
                &endpoint.id,
                "route_model.backend",
                now,
            )
            .await?;
            self.link_existing_signals_to_target(
                &rec.run_id,
                &rec.project_id,
                repo,
                path,
                route.line,
                &route_node.id,
                "route_model.backend",
                now,
            )
            .await?;
        }
        Ok(())
    }

    async fn record_frontend_route(
        &self,
        rec: &RouteModelRecord,
        route: &FrontendRouteModel,
        now: i64,
    ) -> Result<(), StoreError> {
        let route_node = self
            .upsert_route_node(&rec.run_id, &rec.project_id, &route.path, "frontend", now)
            .await?;
        self.record_route_objects(&rec.run_id, &rec.project_id, &route_node.id, &route.path, now)
            .await?;
        if let (Some(repo), Some(path)) = (route.repo.as_deref(), route.file.as_deref()) {
            self.link_existing_signals_to_target(
                &rec.run_id,
                &rec.project_id,
                repo,
                path,
                route.line,
                &route_node.id,
                "route_model.frontend",
                now,
            )
            .await?;
        }
        Ok(())
    }

    async fn record_api_client_call(
        &self,
        rec: &RouteModelRecord,
        call: &ApiClientCallModel,
        now: i64,
    ) -> Result<(), StoreError> {
        let route_node = self
            .upsert_route_node(&rec.run_id, &rec.project_id, &call.path, "api_client", now)
            .await?;
        let endpoint = self
            .upsert_node_by_key(
                &rec.run_id,
                &rec.project_id,
                NODE_ENDPOINT,
                &endpoint_key(
                    "api_client",
                    call.repo.as_deref(),
                    &call.method,
                    &call.path,
                    call.file.as_deref(),
                    call.line,
                ),
                &format!("{} {}", call.method, call.path),
                None,
                serde_json::json!({
                    "source": "api_client_call",
                    "repo": call.repo,
                    "method": call.method,
                    "path": call.path,
                    "file": call.file,
                    "line": call.line,
                    "confidence": call.confidence,
                    "evidence": call.evidence,
                }),
                now,
            )
            .await?;
        self.upsert_edge_by_key(
            &rec.run_id,
            &rec.project_id,
            EDGE_TARGETS,
            &endpoint.id,
            &route_node.id,
            None,
            serde_json::json!({"source": "route_model.api_client"}),
            now,
        )
        .await?;
        self.record_route_objects(&rec.run_id, &rec.project_id, &route_node.id, &call.path, now)
            .await?;
        Ok(())
    }

    async fn record_form(
        &self,
        rec: &RouteModelRecord,
        form: &FormModel,
        now: i64,
    ) -> Result<(), StoreError> {
        let form_node = self
            .upsert_node_by_key(
                &rec.run_id,
                &rec.project_id,
                NODE_FORM,
                &form_key(form),
                &format!("FORM {} {}", form.method, form.action),
                None,
                serde_json::json!({
                    "source": "form_discovery",
                    "repo": form.repo,
                    "method": form.method,
                    "action": form.action,
                    "file": form.file,
                    "line": form.line,
                    "fields": form.fields,
                    "csrf_markers": form.csrf_markers,
                    "state_changing": form.state_changing,
                    "confidence": form.confidence,
                    "evidence": form.evidence,
                }),
                now,
            )
            .await?;
        if let (Some(repo), Some(path)) = (form.repo.as_deref(), form.file.as_deref()) {
            let file = self
                .upsert_file_object(&rec.run_id, &rec.project_id, Some(repo), path, now)
                .await?;
            self.upsert_edge_by_key(
                &rec.run_id,
                &rec.project_id,
                EDGE_TOUCHES_OBJECT,
                &form_node.id,
                &file.id,
                None,
                serde_json::json!({"source": "form_location"}),
                now,
            )
            .await?;
        }
        if form.action.starts_with('/') {
            let route_node = self
                .upsert_route_node(&rec.run_id, &rec.project_id, &form.action, "form", now)
                .await?;
            let endpoint = self
                .upsert_node_by_key(
                    &rec.run_id,
                    &rec.project_id,
                    NODE_ENDPOINT,
                    &endpoint_key(
                        "form",
                        form.repo.as_deref(),
                        &form.method,
                        &form.action,
                        form.file.as_deref(),
                        form.line,
                    ),
                    &format!("{} {}", form.method, form.action),
                    None,
                    serde_json::json!({
                        "source": "form_action",
                        "repo": form.repo,
                        "method": form.method,
                        "path": form.action,
                        "file": form.file,
                        "line": form.line,
                    }),
                    now,
                )
                .await?;
            self.upsert_edge_by_key(
                &rec.run_id,
                &rec.project_id,
                EDGE_TARGETS,
                &form_node.id,
                &endpoint.id,
                None,
                serde_json::json!({"source": "form.action"}),
                now,
            )
            .await?;
            self.upsert_edge_by_key(
                &rec.run_id,
                &rec.project_id,
                EDGE_TARGETS,
                &endpoint.id,
                &route_node.id,
                None,
                serde_json::json!({"source": "form.action"}),
                now,
            )
            .await?;
            self.record_route_details(
                &rec.run_id,
                &rec.project_id,
                &endpoint.id,
                &route_node.id,
                &form.action,
                &[],
                &form.fields,
                &form.csrf_markers,
                &[],
                now,
            )
            .await?;
        }
        Ok(())
    }

    async fn record_route_details(
        &self,
        run_id: &str,
        project_id: &str,
        endpoint_id: &str,
        route_id: &str,
        path: &str,
        params: &[String],
        body_fields: &[String],
        auth_checks: &[String],
        role_checks: &[String],
        now: i64,
    ) -> Result<(), StoreError> {
        self.record_route_objects(run_id, project_id, route_id, path, now).await?;
        self.record_route_objects(run_id, project_id, endpoint_id, path, now).await?;
        for param in params {
            let node =
                self.upsert_parameter_node(run_id, project_id, path, "path", param, now).await?;
            self.upsert_edge_by_key(
                run_id,
                project_id,
                EDGE_TARGETS,
                endpoint_id,
                &node.id,
                None,
                serde_json::json!({"source": "route_param"}),
                now,
            )
            .await?;
        }
        for field in body_fields {
            let node =
                self.upsert_parameter_node(run_id, project_id, path, "body", field, now).await?;
            self.upsert_edge_by_key(
                run_id,
                project_id,
                EDGE_TARGETS,
                endpoint_id,
                &node.id,
                None,
                serde_json::json!({"source": "body_field"}),
                now,
            )
            .await?;
        }
        for role in roles_from_checks(auth_checks, role_checks) {
            let node = self.upsert_role_node(run_id, project_id, &role, now).await?;
            self.upsert_edge_by_key(
                run_id,
                project_id,
                EDGE_USES_ROLE,
                endpoint_id,
                &node.id,
                None,
                serde_json::json!({"source": "route_auth"}),
                now,
            )
            .await?;
        }
        Ok(())
    }

    async fn record_route_objects(
        &self,
        run_id: &str,
        project_id: &str,
        from_node_id: &str,
        path: &str,
        now: i64,
    ) -> Result<(), StoreError> {
        for object in route_objects(path) {
            let node = self.upsert_resource_object(run_id, project_id, &object, now).await?;
            self.upsert_edge_by_key(
                run_id,
                project_id,
                EDGE_TOUCHES_OBJECT,
                from_node_id,
                &node.id,
                None,
                serde_json::json!({"source": "route_path"}),
                now,
            )
            .await?;
        }
        Ok(())
    }

    async fn record_component_targets(
        &self,
        run_id: &str,
        project_id: &str,
        from_node_id: &str,
        components: &[serde_json::Value],
        evidence_ref: Option<&str>,
        now: i64,
    ) -> Result<(), StoreError> {
        for component in components {
            let Some(obj) = component.as_object() else {
                continue;
            };
            if let Some(raw) = obj
                .get("url")
                .or_else(|| obj.get("target"))
                .or_else(|| obj.get("matched_at"))
                .and_then(|v| v.as_str())
            {
                let path = path_from_url_or_path(raw);
                if !path.is_empty() {
                    let method = obj
                        .get("method")
                        .and_then(|v| v.as_str())
                        .unwrap_or("GET")
                        .to_ascii_uppercase();
                    let route =
                        self.upsert_route_node(run_id, project_id, &path, "target", now).await?;
                    let endpoint = self
                        .upsert_node_by_key(
                            run_id,
                            project_id,
                            NODE_ENDPOINT,
                            &endpoint_key("target", None, &method, &path, None, None),
                            &format!("{method} {path}"),
                            None,
                            serde_json::json!({
                                "source": "component_target",
                                "method": method,
                                "path": path,
                                "raw": raw,
                            }),
                            now,
                        )
                        .await?;
                    self.upsert_edge_by_key(
                        run_id,
                        project_id,
                        EDGE_TARGETS,
                        from_node_id,
                        &endpoint.id,
                        evidence_ref,
                        serde_json::json!({"source": "affected_component"}),
                        now,
                    )
                    .await?;
                    self.upsert_edge_by_key(
                        run_id,
                        project_id,
                        EDGE_TARGETS,
                        &endpoint.id,
                        &route.id,
                        evidence_ref,
                        serde_json::json!({"source": "affected_component"}),
                        now,
                    )
                    .await?;
                    self.record_route_objects(run_id, project_id, from_node_id, &path, now).await?;
                }
            }
            if let Some(path) = obj.get("path").and_then(|v| v.as_str()) {
                let repo = obj.get("repo").and_then(|v| v.as_str());
                let line = obj.get("line").and_then(|v| v.as_i64());
                let file = self.upsert_file_object(run_id, project_id, repo, path, now).await?;
                self.upsert_edge_by_key(
                    run_id,
                    project_id,
                    EDGE_TOUCHES_OBJECT,
                    from_node_id,
                    &file.id,
                    evidence_ref,
                    serde_json::json!({"source": "affected_component"}),
                    now,
                )
                .await?;
                self.link_source_location_to_targets(
                    run_id,
                    project_id,
                    from_node_id,
                    repo,
                    path,
                    line,
                    evidence_ref,
                    now,
                )
                .await?;
            }
            if let Some(object) = obj.get("object").and_then(|v| v.as_str()) {
                let node = self.upsert_resource_object(run_id, project_id, object, now).await?;
                self.upsert_edge_by_key(
                    run_id,
                    project_id,
                    EDGE_TOUCHES_OBJECT,
                    from_node_id,
                    &node.id,
                    evidence_ref,
                    serde_json::json!({"source": "affected_component.object"}),
                    now,
                )
                .await?;
            }
            for role in roles_from_component(component) {
                let node = self.upsert_role_node(run_id, project_id, &role, now).await?;
                self.upsert_edge_by_key(
                    run_id,
                    project_id,
                    EDGE_USES_ROLE,
                    from_node_id,
                    &node.id,
                    evidence_ref,
                    serde_json::json!({"source": "affected_component.role"}),
                    now,
                )
                .await?;
            }
        }
        Ok(())
    }

    async fn upsert_route_node(
        &self,
        run_id: &str,
        project_id: &str,
        path: &str,
        source: &str,
        now: i64,
    ) -> Result<AttackGraphNodeRecord, StoreError> {
        self.upsert_node_by_key(
            run_id,
            project_id,
            NODE_ROUTE,
            &route_key(path),
            path,
            None,
            serde_json::json!({"path": path, "source": source}),
            now,
        )
        .await
    }

    async fn upsert_parameter_node(
        &self,
        run_id: &str,
        project_id: &str,
        route_path: &str,
        location: &str,
        name: &str,
        now: i64,
    ) -> Result<AttackGraphNodeRecord, StoreError> {
        self.upsert_node_by_key(
            run_id,
            project_id,
            NODE_PARAMETER,
            &format!("parameter:{}:{location}:{}", route_key(route_path), normalise_key(name)),
            name,
            None,
            serde_json::json!({"route": route_path, "location": location, "name": name}),
            now,
        )
        .await
    }

    async fn upsert_role_node(
        &self,
        run_id: &str,
        project_id: &str,
        role: &str,
        now: i64,
    ) -> Result<AttackGraphNodeRecord, StoreError> {
        self.upsert_node_by_key(
            run_id,
            project_id,
            NODE_ROLE,
            &role_key(role),
            role,
            None,
            serde_json::json!({"role": role}),
            now,
        )
        .await
    }

    async fn upsert_resource_object(
        &self,
        run_id: &str,
        project_id: &str,
        object: &str,
        now: i64,
    ) -> Result<AttackGraphNodeRecord, StoreError> {
        self.upsert_node_by_key(
            run_id,
            project_id,
            NODE_OBJECT,
            &format!("object:resource:{}", normalise_key(object)),
            object,
            None,
            serde_json::json!({"object": object, "object_kind": "resource"}),
            now,
        )
        .await
    }

    async fn upsert_file_object(
        &self,
        run_id: &str,
        project_id: &str,
        repo: Option<&str>,
        path: &str,
        now: i64,
    ) -> Result<AttackGraphNodeRecord, StoreError> {
        let label = repo.map(|r| format!("{r}:{path}")).unwrap_or_else(|| path.to_string());
        self.upsert_node_by_key(
            run_id,
            project_id,
            NODE_OBJECT,
            &format!("object:file:{}:{}", repo.unwrap_or("*"), path),
            &label,
            None,
            serde_json::json!({"object_kind": "file", "repo": repo, "path": path}),
            now,
        )
        .await
    }

    async fn ensure_source_node(
        &self,
        run_id: &str,
        project_id: &str,
        source_id: &str,
        now: i64,
    ) -> Result<AttackGraphNodeRecord, StoreError> {
        if let Some(node) = self.get_node_by_ref(run_id, NODE_SIGNAL, source_id).await? {
            return Ok(node);
        }
        self.upsert_node_by_key(
            run_id,
            project_id,
            NODE_SIGNAL,
            &signal_key(source_id),
            source_id,
            Some(source_id),
            serde_json::json!({"source": "placeholder", "ref_id": source_id}),
            now,
        )
        .await
    }

    async fn ensure_candidate_node(
        &self,
        run_id: &str,
        project_id: &str,
        candidate_id: &str,
        now: i64,
    ) -> Result<AttackGraphNodeRecord, StoreError> {
        if let Some(node) = self.get_node_by_ref(run_id, NODE_CANDIDATE, candidate_id).await? {
            return Ok(node);
        }
        self.upsert_node_by_key(
            run_id,
            project_id,
            NODE_CANDIDATE,
            &candidate_key(candidate_id),
            candidate_id,
            Some(candidate_id),
            serde_json::json!({"source": "placeholder", "ref_id": candidate_id}),
            now,
        )
        .await
    }

    async fn ensure_verification_attempt_node(
        &self,
        run_id: &str,
        project_id: &str,
        attempt_id: &str,
        now: i64,
    ) -> Result<AttackGraphNodeRecord, StoreError> {
        if let Some(node) =
            self.get_node_by_ref(run_id, NODE_VERIFICATION_ATTEMPT, attempt_id).await?
        {
            return Ok(node);
        }
        self.upsert_node_by_key(
            run_id,
            project_id,
            NODE_VERIFICATION_ATTEMPT,
            &verification_attempt_key(attempt_id),
            attempt_id,
            Some(attempt_id),
            serde_json::json!({"source": "placeholder", "ref_id": attempt_id}),
            now,
        )
        .await
    }

    async fn ensure_chain_node(
        &self,
        run_id: &str,
        project_id: &str,
        chain_id: &str,
        now: i64,
    ) -> Result<AttackGraphNodeRecord, StoreError> {
        if let Some(node) = self.get_node_by_ref(run_id, NODE_CHAIN, chain_id).await? {
            return Ok(node);
        }
        self.upsert_node_by_key(
            run_id,
            project_id,
            NODE_CHAIN,
            &chain_key(chain_id),
            chain_id,
            Some(chain_id),
            serde_json::json!({"source": "placeholder", "ref_id": chain_id}),
            now,
        )
        .await
    }

    async fn resolve_member_node(
        &self,
        run_id: &str,
        project_id: &str,
        member_id: &str,
        now: i64,
    ) -> Result<AttackGraphNodeRecord, StoreError> {
        if let Some(node) = self.node_by_ref_any_kind(run_id, member_id).await? {
            return Ok(node);
        }
        if let Some(node) = self.signal_node_by_suffix(run_id, member_id).await? {
            return Ok(node);
        }
        self.upsert_node_by_key(
            run_id,
            project_id,
            NODE_SIGNAL,
            &format!("signal:chain-member:{member_id}"),
            member_id,
            Some(member_id),
            serde_json::json!({"source": "chain_member_placeholder", "ref_id": member_id}),
            now,
        )
        .await
    }

    async fn link_existing_signals_to_target(
        &self,
        run_id: &str,
        project_id: &str,
        repo: &str,
        path: &str,
        line: Option<i64>,
        target_node_id: &str,
        source: &str,
        now: i64,
    ) -> Result<(), StoreError> {
        let rows = if let Some(line) = line {
            sqlx::query(
                r#"
                SELECT id FROM nyx_signals
                WHERE run_id = ? AND project_id = ? AND repo = ? AND path = ?
                  AND (line IS NULL OR ABS(line - ?) <= ?)
                "#,
            )
            .bind(run_id)
            .bind(project_id)
            .bind(repo)
            .bind(path)
            .bind(line)
            .bind(SOURCE_LINE_WINDOW)
            .fetch_all(self.pool)
            .await?
        } else {
            sqlx::query(
                r#"
                SELECT id FROM nyx_signals
                WHERE run_id = ? AND project_id = ? AND repo = ? AND path = ?
                "#,
            )
            .bind(run_id)
            .bind(project_id)
            .bind(repo)
            .bind(path)
            .fetch_all(self.pool)
            .await?
        };
        for row in rows {
            let signal_id: String = row.try_get("id")?;
            let signal = self.ensure_source_node(run_id, project_id, &signal_id, now).await?;
            self.upsert_edge_by_key(
                run_id,
                project_id,
                EDGE_TARGETS,
                &signal.id,
                target_node_id,
                Some(&signal_id),
                serde_json::json!({"source": source}),
                now,
            )
            .await?;
        }
        Ok(())
    }

    async fn link_source_location_to_targets(
        &self,
        run_id: &str,
        project_id: &str,
        from_node_id: &str,
        repo: Option<&str>,
        path: &str,
        line: Option<i64>,
        evidence_ref: Option<&str>,
        now: i64,
    ) -> Result<(), StoreError> {
        let mut query = String::from(
            "SELECT id FROM attack_graph_nodes \
             WHERE run_id = ? AND kind IN ('route','endpoint') \
             AND (json_extract(properties_json, '$.handler_file') = ? \
                  OR json_extract(properties_json, '$.file') = ?)",
        );
        if repo.is_some() {
            query.push_str(" AND (json_extract(properties_json, '$.repo') = ? OR json_extract(properties_json, '$.repo') IS NULL)");
        }
        if line.is_some() {
            query.push_str(
                " AND (json_extract(properties_json, '$.line') IS NULL \
                      OR ABS(CAST(json_extract(properties_json, '$.line') AS INTEGER) - ?) <= ?)",
            );
        }
        let mut q = sqlx::query(&query).bind(run_id).bind(path).bind(path);
        if let Some(repo) = repo {
            q = q.bind(repo);
        }
        if let Some(line) = line {
            q = q.bind(line).bind(SOURCE_LINE_WINDOW);
        }
        let rows = q.fetch_all(self.pool).await?;
        for row in rows {
            let target_id: String = row.try_get("id")?;
            self.upsert_edge_by_key(
                run_id,
                project_id,
                EDGE_TARGETS,
                from_node_id,
                &target_id,
                evidence_ref,
                serde_json::json!({"source": "source_location"}),
                now,
            )
            .await?;
        }
        Ok(())
    }

    async fn project_id_for_run(&self, run_id: &str) -> Result<String, StoreError> {
        let row = sqlx::query("SELECT project_id FROM runs WHERE id = ?")
            .bind(run_id)
            .fetch_optional(self.pool)
            .await?;
        Ok(row
            .and_then(|r| r.try_get::<Option<String>, _>("project_id").ok().flatten())
            .unwrap_or_else(|| DEFAULT_PROJECT_ID.to_string()))
    }

    async fn node_by_kind_ref_any_run(
        &self,
        kind: &str,
        ref_id: &str,
    ) -> Result<Option<AttackGraphNodeRecord>, StoreError> {
        let row = sqlx::query(
            r#"
            SELECT id, run_id, project_id, kind, stable_key, label, ref_id,
                   properties_json, created_at, updated_at
            FROM attack_graph_nodes
            WHERE kind = ? AND ref_id = ?
            ORDER BY updated_at DESC
            LIMIT 1
            "#,
        )
        .bind(kind)
        .bind(ref_id)
        .fetch_optional(self.pool)
        .await?;
        row.map(row_to_node).transpose()
    }

    async fn node_by_ref_any_kind(
        &self,
        run_id: &str,
        ref_id: &str,
    ) -> Result<Option<AttackGraphNodeRecord>, StoreError> {
        let row = sqlx::query(
            r#"
            SELECT id, run_id, project_id, kind, stable_key, label, ref_id,
                   properties_json, created_at, updated_at
            FROM attack_graph_nodes
            WHERE run_id = ? AND ref_id = ?
            ORDER BY updated_at DESC
            LIMIT 1
            "#,
        )
        .bind(run_id)
        .bind(ref_id)
        .fetch_optional(self.pool)
        .await?;
        row.map(row_to_node).transpose()
    }

    async fn signal_node_by_suffix(
        &self,
        run_id: &str,
        member_id: &str,
    ) -> Result<Option<AttackGraphNodeRecord>, StoreError> {
        let suffix = format!("%-{member_id}");
        let row = sqlx::query(
            r#"
            SELECT id, run_id, project_id, kind, stable_key, label, ref_id,
                   properties_json, created_at, updated_at
            FROM attack_graph_nodes
            WHERE run_id = ? AND kind = 'signal' AND ref_id LIKE ?
            ORDER BY updated_at DESC
            LIMIT 1
            "#,
        )
        .bind(run_id)
        .bind(suffix)
        .fetch_optional(self.pool)
        .await?;
        row.map(row_to_node).transpose()
    }

    async fn list_edges_to(&self, node_id: &str) -> Result<Vec<AttackGraphEdgeRecord>, StoreError> {
        let rows = sqlx::query(
            r#"
            SELECT id, run_id, project_id, kind, from_node_id, to_node_id,
                   evidence_ref, properties_json, created_at
            FROM attack_graph_edges
            WHERE to_node_id = ?
            "#,
        )
        .bind(node_id)
        .fetch_all(self.pool)
        .await?;
        rows.into_iter().map(row_to_edge).collect()
    }

    async fn list_context_edges_from(
        &self,
        node_id: &str,
    ) -> Result<Vec<AttackGraphEdgeRecord>, StoreError> {
        let rows = sqlx::query(
            r#"
            SELECT id, run_id, project_id, kind, from_node_id, to_node_id,
                   evidence_ref, properties_json, created_at
            FROM attack_graph_edges
            WHERE from_node_id = ?
              AND kind IN ('targets', 'uses_role', 'touches_object', 'chained_with')
            "#,
        )
        .bind(node_id)
        .fetch_all(self.pool)
        .await?;
        rows.into_iter().map(row_to_edge).collect()
    }

    async fn list_incident_edges(
        &self,
        node_id: &str,
    ) -> Result<Vec<AttackGraphEdgeRecord>, StoreError> {
        let rows = sqlx::query(
            r#"
            SELECT id, run_id, project_id, kind, from_node_id, to_node_id,
                   evidence_ref, properties_json, created_at
            FROM attack_graph_edges
            WHERE from_node_id = ? OR to_node_id = ?
            "#,
        )
        .bind(node_id)
        .bind(node_id)
        .fetch_all(self.pool)
        .await?;
        rows.into_iter().map(row_to_edge).collect()
    }
}

fn row_to_node(row: sqlx::sqlite::SqliteRow) -> Result<AttackGraphNodeRecord, StoreError> {
    Ok(AttackGraphNodeRecord {
        id: row.try_get("id")?,
        run_id: row.try_get("run_id")?,
        project_id: row.try_get("project_id")?,
        kind: row.try_get("kind")?,
        stable_key: row.try_get("stable_key")?,
        label: row.try_get("label")?,
        ref_id: row.try_get("ref_id")?,
        properties: serde_json::from_str(&row.try_get::<String, _>("properties_json")?)?,
        created_at: row.try_get::<i64, _>("created_at")?,
        updated_at: row.try_get::<i64, _>("updated_at")?,
    })
}

fn row_to_edge(row: sqlx::sqlite::SqliteRow) -> Result<AttackGraphEdgeRecord, StoreError> {
    Ok(AttackGraphEdgeRecord {
        id: row.try_get("id")?,
        run_id: row.try_get("run_id")?,
        project_id: row.try_get("project_id")?,
        kind: row.try_get("kind")?,
        from_node_id: row.try_get("from_node_id")?,
        to_node_id: row.try_get("to_node_id")?,
        evidence_ref: row.try_get("evidence_ref")?,
        properties: serde_json::from_str(&row.try_get::<String, _>("properties_json")?)?,
        created_at: row.try_get::<i64, _>("created_at")?,
    })
}

fn sorted_nodes(nodes: HashMap<String, AttackGraphNodeRecord>) -> Vec<AttackGraphNodeRecord> {
    let mut out = nodes.into_values().collect::<Vec<_>>();
    out.sort_by(|a, b| (&a.kind, &a.label, &a.id).cmp(&(&b.kind, &b.label, &b.id)));
    out
}

fn sorted_edges(edges: HashMap<String, AttackGraphEdgeRecord>) -> Vec<AttackGraphEdgeRecord> {
    let mut out = edges.into_values().collect::<Vec<_>>();
    out.sort_by(|a, b| {
        (&a.kind, &a.from_node_id, &a.to_node_id, &a.id).cmp(&(
            &b.kind,
            &b.from_node_id,
            &b.to_node_id,
            &b.id,
        ))
    });
    out
}

fn signal_key(id: &str) -> String {
    format!("signal:{id}")
}

fn candidate_key(id: &str) -> String {
    format!("candidate:{id}")
}

fn verification_attempt_key(id: &str) -> String {
    format!("verification_attempt:{id}")
}

fn verified_vulnerability_key(id: &str) -> String {
    format!("verified_vulnerability:{id}")
}

fn chain_key(id: &str) -> String {
    format!("chain:{id}")
}

fn route_key(path: &str) -> String {
    format!("route:{}", normalise_path(path))
}

fn endpoint_key(
    source: &str,
    repo: Option<&str>,
    method: &str,
    path: &str,
    file: Option<&str>,
    line: Option<i64>,
) -> String {
    let mut key = format!(
        "endpoint:{source}:{}:{}:{}",
        repo.unwrap_or("*"),
        method.to_ascii_uppercase(),
        normalise_path(path)
    );
    if let Some(file) = file {
        key.push(':');
        key.push_str(file);
    }
    if let Some(line) = line {
        key.push(':');
        key.push_str(&line.to_string());
    }
    key
}

fn form_key(form: &FormModel) -> String {
    format!(
        "form:{}:{}:{}:{}:{}",
        form.repo.as_deref().unwrap_or("*"),
        form.method.to_ascii_uppercase(),
        normalise_path(&form.action),
        form.file.as_deref().unwrap_or("*"),
        form.line.map(|line| line.to_string()).unwrap_or_else(|| "*".to_string())
    )
}

fn role_key(role: &str) -> String {
    format!("role:{}", normalise_key(role))
}

fn signal_label(signal: &NyxSignalRecord) -> String {
    signal.message.clone().unwrap_or_else(|| {
        format!(
            "{} {}:{}",
            signal.cap,
            signal.path,
            signal.line.map(|l| l.to_string()).unwrap_or_else(|| "?".to_string())
        )
    })
}

fn normalise_path(path: &str) -> String {
    let path = path.trim();
    if path.is_empty() {
        return "/".to_string();
    }
    let mut out = path.split(['?', '#']).next().unwrap_or(path).replace('\\', "/");
    if !out.starts_with('/') {
        out.insert(0, '/');
    }
    while out.len() > 1 && out.ends_with('/') {
        out.pop();
    }
    out
}

fn normalise_key(value: &str) -> String {
    value
        .trim()
        .to_ascii_lowercase()
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() { c } else { '-' })
        .collect::<String>()
        .split('-')
        .filter(|s| !s.is_empty())
        .collect::<Vec<_>>()
        .join("-")
}

fn route_objects(path: &str) -> Vec<String> {
    let ignored = ["", "api", "v1", "v2", "admin"];
    let mut out = Vec::new();
    for segment in normalise_path(path).split('/') {
        if ignored.contains(&segment) || segment.starts_with(':') || segment.starts_with('{') {
            continue;
        }
        let object = segment
            .trim_matches(|c: char| !c.is_ascii_alphanumeric() && c != '_' && c != '-')
            .trim();
        if object.is_empty() || out.iter().any(|v| v == object) {
            continue;
        }
        out.push(object.to_string());
    }
    out
}

fn roles_from_checks(auth_checks: &[String], role_checks: &[String]) -> Vec<String> {
    let mut out = Vec::new();
    if !auth_checks.is_empty() {
        out.push("authenticated".to_string());
    }
    for role in role_checks {
        let trimmed = role.trim();
        if !trimmed.is_empty() && !out.iter().any(|v| v == trimmed) {
            out.push(trimmed.to_string());
        }
    }
    out
}

fn roles_from_component(component: &serde_json::Value) -> Vec<String> {
    let Some(obj) = component.as_object() else {
        return Vec::new();
    };
    let mut out = Vec::new();
    if let Some(role) = obj.get("role").and_then(|v| v.as_str()) {
        out.push(role.to_string());
    }
    if let Some(roles) = obj.get("roles").and_then(|v| v.as_array()) {
        for role in roles.iter().filter_map(|v| v.as_str()) {
            if !out.iter().any(|r| r == role) {
                out.push(role.to_string());
            }
        }
    }
    out
}

fn path_from_url_or_path(raw: &str) -> String {
    if let Some((_, rest)) = raw.split_once("://") {
        let path = rest.split_once('/').map(|(_, path)| path).unwrap_or("");
        return normalise_path(&format!("/{path}"));
    }
    normalise_path(raw)
}

fn component_values_from_json(value: &serde_json::Value) -> Vec<serde_json::Value> {
    let mut out = Vec::new();
    collect_component_values(value, &mut out, 0);
    out
}

fn collect_component_values(
    value: &serde_json::Value,
    out: &mut Vec<serde_json::Value>,
    depth: u8,
) {
    if depth > 6 {
        return;
    }
    match value {
        serde_json::Value::Object(obj) => {
            if obj.contains_key("url")
                || obj.contains_key("target")
                || obj.contains_key("matched_at")
                || obj.contains_key("path")
                || obj.contains_key("role")
                || obj.contains_key("roles")
                || obj.contains_key("object")
            {
                out.push(value.clone());
            }
            for child in obj.values() {
                collect_component_values(child, out, depth + 1);
            }
        }
        serde_json::Value::Array(values) => {
            for child in values {
                collect_component_values(child, out, depth + 1);
            }
        }
        _ => {}
    }
}

fn parse_member_ids(raw: &str) -> Vec<String> {
    serde_json::from_str::<Vec<String>>(raw).unwrap_or_else(|_| {
        raw.split(',').map(str::trim).filter(|s| !s.is_empty()).map(str::to_string).collect()
    })
}

fn severity_rank(properties: &serde_json::Value) -> u8 {
    let severity = properties.get("severity").and_then(|v| v.as_str()).unwrap_or_default();
    match severity.to_ascii_lowercase().as_str() {
        "critical" => 5,
        "high" => 4,
        "medium" => 3,
        "low" => 2,
        "info" | "informational" => 1,
        _ => 0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::testutil::{fresh_store, sample_repo_for_project, sample_run};

    async fn seed_run_project(s: &crate::store::Store) {
        s.projects().create("p-graph", "graph", None, None, None, 1_000).await.unwrap();
        let repo = sample_repo_for_project("web", "p-graph");
        s.repos().upsert(&repo).await.unwrap();
        let mut run = sample_run("run-graph");
        run.project_id = Some("p-graph".to_string());
        s.runs().insert(&run).await.unwrap();
    }

    #[tokio::test]
    async fn graph_ids_are_stable_and_domain_separated() {
        let a = attack_graph_node_id("run", NODE_ROUTE, "route:/users");
        let b = attack_graph_node_id("run", NODE_ROUTE, "route:/users");
        let c = attack_graph_node_id("run", NODE_ENDPOINT, "route:/users");
        assert_eq!(a, b);
        assert_ne!(a, c);
        assert!(a.starts_with("agn-"));
    }

    #[tokio::test]
    async fn evidence_trail_walks_from_vulnerability_to_sources_and_targets() {
        let (_tmp, s) = fresh_store().await;
        seed_run_project(&s).await;
        let graph = s.attack_graph();
        let now = 2_000;
        let signal = graph
            .upsert_node_by_key(
                "run-graph",
                "p-graph",
                NODE_SIGNAL,
                "signal:sig-1",
                "SQLi signal",
                Some("sig-1"),
                serde_json::json!({"severity": "High"}),
                now,
            )
            .await
            .unwrap();
        let candidate = graph
            .upsert_node_by_key(
                "run-graph",
                "p-graph",
                NODE_CANDIDATE,
                "candidate:pc-1",
                "SQLi candidate",
                Some("pc-1"),
                serde_json::json!({"severity": "High"}),
                now,
            )
            .await
            .unwrap();
        let attempt = graph
            .upsert_node_by_key(
                "run-graph",
                "p-graph",
                NODE_VERIFICATION_ATTEMPT,
                "verification_attempt:va-1",
                "http Confirmed",
                Some("va-1"),
                serde_json::json!({"status": "Confirmed"}),
                now,
            )
            .await
            .unwrap();
        let vuln = graph
            .upsert_node_by_key(
                "run-graph",
                "p-graph",
                NODE_VERIFIED_VULNERABILITY,
                "verified_vulnerability:vuln-1",
                "SQL injection",
                Some("vuln-1"),
                serde_json::json!({"severity": "Critical"}),
                now,
            )
            .await
            .unwrap();
        let route = graph
            .upsert_node_by_key(
                "run-graph",
                "p-graph",
                NODE_ROUTE,
                "route:/api/users",
                "/api/users",
                None,
                serde_json::json!({"path": "/api/users"}),
                now,
            )
            .await
            .unwrap();
        graph
            .upsert_edge_by_key(
                "run-graph",
                "p-graph",
                EDGE_DERIVED_CANDIDATE,
                &signal.id,
                &candidate.id,
                Some("sig-1"),
                serde_json::json!({}),
                now,
            )
            .await
            .unwrap();
        graph
            .upsert_edge_by_key(
                "run-graph",
                "p-graph",
                EDGE_VERIFIED_AS,
                &candidate.id,
                &attempt.id,
                Some("va-1"),
                serde_json::json!({}),
                now,
            )
            .await
            .unwrap();
        graph
            .upsert_edge_by_key(
                "run-graph",
                "p-graph",
                EDGE_VERIFIED_AS,
                &attempt.id,
                &vuln.id,
                Some("va-1"),
                serde_json::json!({}),
                now,
            )
            .await
            .unwrap();
        graph
            .upsert_edge_by_key(
                "run-graph",
                "p-graph",
                EDGE_TARGETS,
                &vuln.id,
                &route.id,
                Some("vuln-1"),
                serde_json::json!({}),
                now,
            )
            .await
            .unwrap();

        let trail = graph.evidence_for_vulnerability("vuln-1").await.unwrap().unwrap();
        let kinds: HashSet<_> = trail.nodes.iter().map(|n| n.kind.as_str()).collect();
        assert!(kinds.contains(NODE_SIGNAL));
        assert!(kinds.contains(NODE_CANDIDATE));
        assert!(kinds.contains(NODE_VERIFICATION_ATTEMPT));
        assert!(kinds.contains(NODE_VERIFIED_VULNERABILITY));
        assert!(kinds.contains(NODE_ROUTE), "target route should be included as context");
        assert!(trail.edges.iter().any(|e| e.kind == EDGE_DERIVED_CANDIDATE));
        assert!(trail.edges.iter().any(|e| e.kind == EDGE_VERIFIED_AS));
    }

    #[tokio::test]
    async fn vulnerabilities_touching_finds_connected_vulns() {
        let (_tmp, s) = fresh_store().await;
        seed_run_project(&s).await;
        let graph = s.attack_graph();
        let now = 2_000;
        let route = graph
            .upsert_node_by_key(
                "run-graph",
                "p-graph",
                NODE_ROUTE,
                "route:/api/admin",
                "/api/admin",
                None,
                serde_json::json!({"path": "/api/admin"}),
                now,
            )
            .await
            .unwrap();
        let vuln = graph
            .upsert_node_by_key(
                "run-graph",
                "p-graph",
                NODE_VERIFIED_VULNERABILITY,
                "verified_vulnerability:vuln-admin",
                "Admin auth bypass",
                Some("vuln-admin"),
                serde_json::json!({"severity": "High"}),
                now,
            )
            .await
            .unwrap();
        graph
            .upsert_edge_by_key(
                "run-graph",
                "p-graph",
                EDGE_TARGETS,
                &vuln.id,
                &route.id,
                Some("vuln-admin"),
                serde_json::json!({}),
                now,
            )
            .await
            .unwrap();

        let vulns = graph
            .vulnerabilities_touching("run-graph", NODE_ROUTE, "route:/api/admin")
            .await
            .unwrap();
        assert_eq!(vulns.len(), 1);
        assert_eq!(vulns[0].ref_id.as_deref(), Some("vuln-admin"));
    }
}

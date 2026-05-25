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
    EDGE_DERIVED_CANDIDATE, EDGE_LEARNED_FROM, EDGE_OBSERVED_ACCESS, EDGE_TARGETS,
    EDGE_TOUCHES_OBJECT, EDGE_USES_ROLE, EDGE_VERIFIED_AS, NODE_AUTHZ_MATRIX_ENTRY,
    NODE_BUSINESS_LOGIC_TEMPLATE, NODE_CANDIDATE, NODE_CHAIN, NODE_ENDPOINT, NODE_FORM,
    NODE_OBJECT, NODE_PARAMETER, NODE_ROLE, NODE_ROUTE, NODE_SIGNAL, NODE_VERIFICATION_ATTEMPT,
    NODE_VERIFIED_VULNERABILITY,
};
use nyctos_types::chain::{
    ChainReasoningEdge, ChainReasoningInput, ChainReasoningNode, ChainRecord,
    CHAIN_REASONING_DEFAULT_MAX, NODE_KIND_ENTRY, NODE_KIND_OTHER, NODE_KIND_SINK,
};
use nyctos_types::product::{
    canonical_risk_rating, clamp_risk_score, ApiClientCallModel, AuthzMatrixEntryRecord, FormModel,
    FrontendRouteModel, NyxSignalRecord, PentestCandidateRecord, RouteModelEndpoint,
    RouteModelRecord, VerificationAttemptRecord, VerifiedVulnerabilityRecord,
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

    pub async fn candidate_to_route(
        &self,
        run_id: &str,
        candidate_id: &str,
    ) -> Result<Option<AttackGraphEvidenceTrail>, StoreError> {
        let Some(focus) = self.get_node_by_ref(run_id, NODE_CANDIDATE, candidate_id).await? else {
            return Ok(None);
        };
        self.context_trail_from_focus(
            focus,
            &[
                EDGE_DERIVED_CANDIDATE,
                EDGE_TARGETS,
                EDGE_USES_ROLE,
                EDGE_TOUCHES_OBJECT,
                EDGE_VERIFIED_AS,
            ],
            3,
        )
        .await
        .map(Some)
    }

    pub async fn route_to_role_object(
        &self,
        run_id: &str,
        route_stable_key: &str,
    ) -> Result<Option<AttackGraphEvidenceTrail>, StoreError> {
        let Some(focus) = self.get_node_by_stable_key(run_id, NODE_ROUTE, route_stable_key).await?
        else {
            return Ok(None);
        };
        self.context_trail_from_focus(
            focus,
            &[EDGE_TARGETS, EDGE_USES_ROLE, EDGE_TOUCHES_OBJECT, EDGE_OBSERVED_ACCESS],
            2,
        )
        .await
        .map(Some)
    }

    pub async fn vuln_to_object_role(
        &self,
        run_id: &str,
        vulnerability_id: &str,
    ) -> Result<Option<AttackGraphEvidenceTrail>, StoreError> {
        let Some(focus) =
            self.get_node_by_ref(run_id, NODE_VERIFIED_VULNERABILITY, vulnerability_id).await?
        else {
            return Ok(None);
        };
        self.context_trail_from_focus(
            focus,
            &[
                EDGE_TARGETS,
                EDGE_USES_ROLE,
                EDGE_TOUCHES_OBJECT,
                EDGE_VERIFIED_AS,
                EDGE_CHAINED_WITH,
            ],
            3,
        )
        .await
        .map(Some)
    }

    pub async fn cross_repo_service_edges(
        &self,
        run_id: &str,
    ) -> Result<Vec<AttackGraphEdgeRecord>, StoreError> {
        let nodes = self.list_nodes_by_run(run_id).await?;
        let node_by_id: HashMap<String, AttackGraphNodeRecord> =
            nodes.into_iter().map(|n| (n.id.clone(), n)).collect();
        let mut out = Vec::new();
        for edge in self.list_edges_by_run(run_id).await? {
            if edge.kind != EDGE_TOUCHES_OBJECT && edge.kind != EDGE_TARGETS {
                continue;
            }
            let Some(from) = node_by_id.get(&edge.from_node_id) else { continue };
            let Some(to) = node_by_id.get(&edge.to_node_id) else { continue };
            let from_repo = graph_repo(from);
            let to_repo = graph_repo(to);
            let service_like = graph_object_kind(from).as_deref() == Some("service")
                || graph_object_kind(to).as_deref() == Some("service")
                || from.properties.get("service_calls").is_some()
                || to.properties.get("service_calls").is_some();
            if service_like
                && from_repo.is_some()
                && to_repo.is_some()
                && from_repo.as_deref() != to_repo.as_deref()
            {
                out.push(edge);
            }
        }
        out.sort_by(|a, b| {
            (&a.kind, &a.from_node_id, &a.to_node_id).cmp(&(
                &b.kind,
                &b.from_node_id,
                &b.to_node_id,
            ))
        });
        Ok(out)
    }

    pub async fn chain_planning_input(
        &self,
        run_id: &str,
        max_chains: u32,
    ) -> Result<Option<ChainReasoningInput>, StoreError> {
        let nodes = self.list_nodes_by_run(run_id).await?;
        let mut selected = HashMap::new();
        for node in nodes {
            if is_chain_planning_node(&node) {
                selected.insert(node.id.clone(), node);
            }
        }
        if selected.len() < 2 {
            return Ok(None);
        }

        let mut graph_edges = Vec::new();
        let mut edge_ref_by_pair: HashMap<(String, String), Vec<String>> = HashMap::new();
        for edge in self.list_edges_by_run(run_id).await? {
            if !is_chain_planning_edge(&edge.kind) {
                continue;
            }
            if !selected.contains_key(&edge.from_node_id)
                || !selected.contains_key(&edge.to_node_id)
            {
                continue;
            }
            edge_ref_by_pair
                .entry((edge.from_node_id.clone(), edge.to_node_id.clone()))
                .or_default()
                .push(edge.evidence_ref.clone().unwrap_or_else(|| edge.id.clone()));
            graph_edges.push(edge);
        }
        if graph_edges.is_empty() {
            return Ok(None);
        }

        let mut repos = selected.values().filter_map(graph_repo).collect::<Vec<_>>();
        repos.sort();
        repos.dedup();

        let mut reasoning_nodes = Vec::new();
        for node in selected.values() {
            reasoning_nodes.push(graph_node_to_chain_node(node, &graph_edges, &selected));
        }
        reasoning_nodes.sort_by(|a, b| {
            chain_node_rank(a)
                .cmp(&chain_node_rank(b))
                .then_with(|| severity_value(&b.severity).cmp(&severity_value(&a.severity)))
                .then_with(|| a.label.cmp(&b.label))
                .then_with(|| a.id.cmp(&b.id))
        });

        let mut reasoning_edges = graph_edges
            .iter()
            .map(|edge| {
                let from_repo = selected.get(&edge.from_node_id).and_then(graph_repo);
                let to_repo = selected.get(&edge.to_node_id).and_then(graph_repo);
                ChainReasoningEdge {
                    from: edge.from_node_id.clone(),
                    to: edge.to_node_id.clone(),
                    label: edge.kind.clone(),
                    cross_repo: from_repo.is_some()
                        && to_repo.is_some()
                        && from_repo.as_deref() != to_repo.as_deref(),
                    edge_id: Some(edge.id.clone()),
                    evidence_ref: edge.evidence_ref.clone(),
                    source: edge
                        .properties
                        .get("source")
                        .and_then(|v| v.as_str())
                        .map(str::to_string),
                }
            })
            .collect::<Vec<_>>();
        reasoning_edges.sort_by(|a, b| {
            (&a.from, &a.to, &a.label, &a.edge_id).cmp(&(&b.from, &b.to, &b.label, &b.edge_id))
        });

        Ok(Some(ChainReasoningInput {
            run_id: run_id.to_string(),
            repos,
            nodes: reasoning_nodes,
            edges: reasoning_edges,
            max_chains: if max_chains == 0 { CHAIN_REASONING_DEFAULT_MAX } else { max_chains },
        }))
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
        if let Some(provenance) = business_logic_template_provenance(&rec.affected_components) {
            let template = self
                .upsert_node_by_key(
                    &rec.run_id,
                    &rec.project_id,
                    NODE_BUSINESS_LOGIC_TEMPLATE,
                    &business_logic_template_key(&provenance.template_id, &provenance.version),
                    &provenance.title,
                    Some(&provenance.template_id),
                    serde_json::json!({
                        "template_id": provenance.template_id,
                        "template_version": provenance.version,
                        "title": provenance.title,
                        "category": provenance.category,
                        "mutability": provenance.mutability,
                    }),
                    now,
                )
                .await?;
            self.upsert_edge_by_key(
                &rec.run_id,
                &rec.project_id,
                EDGE_DERIVED_CANDIDATE,
                &template.id,
                &node.id,
                Some(&provenance.template_id),
                serde_json::json!({"source": "business_logic_template"}),
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

    pub async fn record_authz_matrix_entry(
        &self,
        rec: &AuthzMatrixEntryRecord,
    ) -> Result<(), StoreError> {
        let now = rec.created_at;
        let node = self
            .upsert_node_by_key(
                &rec.run_id,
                &rec.project_id,
                NODE_AUTHZ_MATRIX_ENTRY,
                &format!("authz-matrix:{}", rec.id),
                &format!("{} {} {}", rec.role, rec.action, rec.resource),
                Some(&rec.id),
                serde_json::json!({
                    "candidate_id": rec.candidate_id,
                    "verification_attempt_id": rec.verification_attempt_id,
                    "probe_kind": rec.probe_kind,
                    "role": rec.role,
                    "owner_role": rec.owner_role,
                    "tenant": rec.tenant,
                    "resource": rec.resource,
                    "object_id": rec.object_id,
                    "action": rec.action,
                    "endpoint": rec.endpoint,
                    "expected_decision": rec.expected_decision,
                    "observed_decision": rec.observed_decision,
                    "observed_status": rec.observed_status,
                    "body_marker_result": rec.body_marker_result,
                    "confidence": rec.confidence,
                    "evidence": rec.evidence,
                }),
                now,
            )
            .await?;
        let attempt = self
            .ensure_verification_attempt_node(
                &rec.run_id,
                &rec.project_id,
                &rec.verification_attempt_id,
                now,
            )
            .await?;
        self.upsert_edge_by_key(
            &rec.run_id,
            &rec.project_id,
            EDGE_OBSERVED_ACCESS,
            &attempt.id,
            &node.id,
            Some(&rec.verification_attempt_id),
            serde_json::json!({"source": "authz_matrix"}),
            now,
        )
        .await?;
        let role = self.upsert_role_node(&rec.run_id, &rec.project_id, &rec.role, now).await?;
        self.upsert_edge_by_key(
            &rec.run_id,
            &rec.project_id,
            EDGE_USES_ROLE,
            &node.id,
            &role.id,
            Some(&rec.id),
            serde_json::json!({"source": "authz_matrix.role"}),
            now,
        )
        .await?;
        if let Some(owner_role) = rec.owner_role.as_deref().filter(|s| !s.trim().is_empty()) {
            let owner =
                self.upsert_role_node(&rec.run_id, &rec.project_id, owner_role, now).await?;
            self.upsert_edge_by_key(
                &rec.run_id,
                &rec.project_id,
                EDGE_USES_ROLE,
                &node.id,
                &owner.id,
                Some(&rec.id),
                serde_json::json!({"source": "authz_matrix.owner_role"}),
                now,
            )
            .await?;
        }
        let endpoint =
            self.upsert_endpoint_node(&rec.run_id, &rec.project_id, &rec.endpoint, now).await?;
        self.upsert_edge_by_key(
            &rec.run_id,
            &rec.project_id,
            EDGE_TARGETS,
            &node.id,
            &endpoint.id,
            Some(&rec.id),
            serde_json::json!({"source": "authz_matrix.endpoint"}),
            now,
        )
        .await?;
        let object_label = rec.object_id.as_deref().unwrap_or(&rec.resource);
        let object =
            self.upsert_resource_object(&rec.run_id, &rec.project_id, object_label, now).await?;
        self.upsert_edge_by_key(
            &rec.run_id,
            &rec.project_id,
            EDGE_TOUCHES_OBJECT,
            &node.id,
            &object.id,
            Some(&rec.id),
            serde_json::json!({"source": "authz_matrix.resource"}),
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
                    "risk_score": clamp_risk_score(rec.risk_score),
                    "risk_rating": canonical_risk_rating(&rec.risk_rating, rec.risk_score),
                    "risk_score_source": rec.risk_score_source,
                    "risk_score_rationale": rec.risk_score_rationale,
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
                    "framework": route.framework,
                    "handler_file": route.handler_file,
                    "handler_name": route.handler_name,
                    "line": route.line,
                    "params": route.params,
                    "query_params": route.query_params,
                    "middleware": route.middleware,
                    "auth_checks": route.auth_checks,
                    "role_checks": route.role_checks,
                    "body_fields": route.body_fields,
                    "request_fields": route.request_fields,
                    "response_hints": route.response_hints,
                    "service_calls": route.service_calls,
                    "model_names": route.model_names,
                    "resource_names": route.resource_names,
                    "tenant_fields": route.tenant_fields,
                    "owner_fields": route.owner_fields,
                    "side_effects": route.side_effects,
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
            &route.query_params,
            &route.body_fields,
            &route.request_fields,
            &route.auth_checks,
            &route.role_checks,
            &route.service_calls,
            &route.model_names,
            &route.resource_names,
            &route.tenant_fields,
            &route.owner_fields,
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
                &[],
                &form.fields,
                &form.fields,
                &form.csrf_markers,
                &[],
                &[],
                &[],
                &[],
                &[],
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
        query_params: &[String],
        body_fields: &[String],
        request_fields: &[String],
        auth_checks: &[String],
        role_checks: &[String],
        service_calls: &[String],
        model_names: &[String],
        resource_names: &[String],
        tenant_fields: &[String],
        owner_fields: &[String],
        now: i64,
    ) -> Result<(), StoreError> {
        self.record_route_objects(run_id, project_id, route_id, path, now).await?;
        self.record_route_objects(run_id, project_id, endpoint_id, path, now).await?;
        for object in resource_names {
            self.record_named_object(run_id, project_id, endpoint_id, "resource", object, now)
                .await?;
            self.record_named_object(run_id, project_id, route_id, "resource", object, now).await?;
        }
        for service in service_calls {
            self.record_named_object(run_id, project_id, endpoint_id, "service", service, now)
                .await?;
        }
        for model in model_names {
            self.record_named_object(run_id, project_id, endpoint_id, "model", model, now).await?;
        }
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
        for param in query_params {
            let node =
                self.upsert_parameter_node(run_id, project_id, path, "query", param, now).await?;
            self.upsert_edge_by_key(
                run_id,
                project_id,
                EDGE_TARGETS,
                endpoint_id,
                &node.id,
                None,
                serde_json::json!({"source": "query_param"}),
                now,
            )
            .await?;
        }
        let mut fields = body_fields.to_vec();
        fields.extend_from_slice(request_fields);
        fields.sort();
        fields.dedup();
        for field in fields {
            let node =
                self.upsert_parameter_node(run_id, project_id, path, "body", &field, now).await?;
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
        for field in tenant_fields {
            let node =
                self.upsert_parameter_node(run_id, project_id, path, "tenant", field, now).await?;
            self.upsert_edge_by_key(
                run_id,
                project_id,
                EDGE_TARGETS,
                endpoint_id,
                &node.id,
                None,
                serde_json::json!({"source": "tenant_field"}),
                now,
            )
            .await?;
        }
        for field in owner_fields {
            let node =
                self.upsert_parameter_node(run_id, project_id, path, "owner", field, now).await?;
            self.upsert_edge_by_key(
                run_id,
                project_id,
                EDGE_TARGETS,
                endpoint_id,
                &node.id,
                None,
                serde_json::json!({"source": "owner_field"}),
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

    async fn record_named_object(
        &self,
        run_id: &str,
        project_id: &str,
        from_node_id: &str,
        object_kind: &str,
        name: &str,
        now: i64,
    ) -> Result<(), StoreError> {
        if name.trim().is_empty() {
            return Ok(());
        }
        let stable_key = format!("{}:{}", object_kind, name.trim().to_ascii_lowercase());
        let node = self
            .upsert_node_by_key(
                run_id,
                project_id,
                NODE_OBJECT,
                &stable_key,
                name.trim(),
                None,
                serde_json::json!({
                    "object_kind": object_kind,
                    "name": name.trim(),
                    "source": "route_model.semantic",
                }),
                now,
            )
            .await?;
        self.upsert_edge_by_key(
            run_id,
            project_id,
            EDGE_TOUCHES_OBJECT,
            from_node_id,
            &node.id,
            None,
            serde_json::json!({"source": "route_model.semantic", "object_kind": object_kind}),
            now,
        )
        .await?;
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
                .or_else(|| obj.get("url_path"))
                .or_else(|| obj.get("route_path"))
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

    async fn upsert_endpoint_node(
        &self,
        run_id: &str,
        project_id: &str,
        endpoint: &str,
        now: i64,
    ) -> Result<AttackGraphNodeRecord, StoreError> {
        self.upsert_node_by_key(
            run_id,
            project_id,
            NODE_ENDPOINT,
            &format!("endpoint:authz-matrix:{}", normalise_key(endpoint)),
            endpoint,
            None,
            serde_json::json!({"source": "authz_matrix", "endpoint": endpoint}),
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

    async fn context_trail_from_focus(
        &self,
        focus: AttackGraphNodeRecord,
        edge_kinds: &[&str],
        max_depth: usize,
    ) -> Result<AttackGraphEvidenceTrail, StoreError> {
        let allowed: HashSet<&str> = edge_kinds.iter().copied().collect();
        let mut nodes: HashMap<String, AttackGraphNodeRecord> =
            HashMap::from([(focus.id.clone(), focus.clone())]);
        let mut edges: HashMap<String, AttackGraphEdgeRecord> = HashMap::new();
        let mut visited: HashSet<String> = HashSet::from([focus.id.clone()]);
        let mut frontier = vec![focus.id.clone()];
        for _ in 0..max_depth {
            let mut next = Vec::new();
            for current in frontier {
                for edge in self.list_incident_edges(&current).await? {
                    if !allowed.contains(edge.kind.as_str()) {
                        continue;
                    }
                    let other_id = if edge.from_node_id == current {
                        edge.to_node_id.clone()
                    } else {
                        edge.from_node_id.clone()
                    };
                    edges.insert(edge.id.clone(), edge);
                    if visited.insert(other_id.clone()) {
                        if let Some(node) = self.get_node(&other_id).await? {
                            next.push(node.id.clone());
                            nodes.insert(node.id.clone(), node);
                        }
                    }
                }
            }
            if next.is_empty() {
                break;
            }
            frontier = next;
        }
        Ok(AttackGraphEvidenceTrail {
            focus,
            nodes: sorted_nodes(nodes),
            edges: sorted_edges(edges),
        })
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

fn business_logic_template_key(template_id: &str, version: &str) -> String {
    format!("business_logic_template:{template_id}:{version}")
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

struct BusinessLogicTemplateGraphProvenance {
    template_id: String,
    version: String,
    title: String,
    category: String,
    mutability: String,
}

fn business_logic_template_provenance(
    components: &[serde_json::Value],
) -> Option<BusinessLogicTemplateGraphProvenance> {
    for component in components {
        let Some(obj) = component.as_object() else {
            continue;
        };
        let provenance = obj.get("template_provenance").and_then(|v| v.as_object()).unwrap_or(obj);
        let template_id = provenance
            .get("template_id")
            .or_else(|| provenance.get("id"))
            .and_then(|v| v.as_str())?;
        let version = provenance
            .get("template_version")
            .or_else(|| provenance.get("version"))
            .and_then(|v| v.as_str())
            .unwrap_or("unknown");
        return Some(BusinessLogicTemplateGraphProvenance {
            template_id: template_id.to_string(),
            version: version.to_string(),
            title: provenance
                .get("title")
                .or_else(|| obj.get("template_name"))
                .and_then(|v| v.as_str())
                .unwrap_or(template_id)
                .to_string(),
            category: provenance
                .get("category")
                .and_then(|v| v.as_str())
                .unwrap_or("business_logic")
                .to_string(),
            mutability: provenance
                .get("mutability")
                .and_then(|v| v.as_str())
                .unwrap_or("unknown")
                .to_string(),
        });
    }
    None
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

fn is_chain_planning_node(node: &AttackGraphNodeRecord) -> bool {
    matches!(
        node.kind.as_str(),
        NODE_CANDIDATE
            | NODE_SIGNAL
            | NODE_VERIFIED_VULNERABILITY
            | NODE_VERIFICATION_ATTEMPT
            | NODE_ROUTE
            | NODE_ENDPOINT
            | NODE_FORM
            | NODE_PARAMETER
            | NODE_ROLE
            | NODE_OBJECT
            | NODE_AUTHZ_MATRIX_ENTRY
            | NODE_BUSINESS_LOGIC_TEMPLATE
    )
}

fn is_chain_planning_edge(kind: &str) -> bool {
    matches!(
        kind,
        EDGE_TARGETS
            | EDGE_USES_ROLE
            | EDGE_TOUCHES_OBJECT
            | EDGE_DERIVED_CANDIDATE
            | EDGE_VERIFIED_AS
            | EDGE_OBSERVED_ACCESS
            | EDGE_LEARNED_FROM
    )
}

fn graph_node_to_chain_node(
    node: &AttackGraphNodeRecord,
    edges: &[AttackGraphEdgeRecord],
    nodes: &HashMap<String, AttackGraphNodeRecord>,
) -> ChainReasoningNode {
    let repo = graph_repo(node).unwrap_or_else(|| "*".to_string());
    let path = node
        .properties
        .get("path")
        .or_else(|| node.properties.get("handler_file"))
        .and_then(|v| v.as_str())
        .unwrap_or(&node.stable_key)
        .to_string();
    let line =
        node.properties.get("line").and_then(|v| v.as_i64()).and_then(|v| u32::try_from(v).ok());
    let cap = node
        .properties
        .get("cap")
        .or_else(|| node.properties.get("vuln_class"))
        .or_else(|| node.properties.get("object_kind"))
        .and_then(|v| v.as_str())
        .unwrap_or(&node.kind)
        .to_string();
    let rule = node
        .properties
        .get("rule")
        .or_else(|| node.properties.get("source"))
        .and_then(|v| v.as_str())
        .unwrap_or(&node.kind)
        .to_string();
    let severity =
        node.properties.get("severity").and_then(|v| v.as_str()).unwrap_or("Info").to_string();
    let mut routes = Vec::new();
    let mut roles = Vec::new();
    let mut objects = Vec::new();
    let mut evidence_refs = Vec::new();
    for edge in edges {
        if edge.from_node_id != node.id && edge.to_node_id != node.id {
            continue;
        }
        if let Some(evidence_ref) = &edge.evidence_ref {
            push_unique(&mut evidence_refs, evidence_ref.clone());
        }
        let other_id =
            if edge.from_node_id == node.id { &edge.to_node_id } else { &edge.from_node_id };
        let Some(other) = nodes.get(other_id) else { continue };
        match other.kind.as_str() {
            NODE_ROUTE | NODE_ENDPOINT | NODE_FORM => push_unique(&mut routes, other.label.clone()),
            NODE_ROLE => push_unique(&mut roles, other.label.clone()),
            NODE_OBJECT => push_unique(&mut objects, other.label.clone()),
            _ => {}
        }
    }
    ChainReasoningNode {
        id: node.id.clone(),
        graph_kind: Some(node.kind.clone()),
        label: Some(node.label.clone()),
        ref_id: node.ref_id.clone(),
        repo,
        path,
        line,
        cap,
        rule,
        severity,
        kind: graph_chain_kind(node).to_string(),
        routes,
        roles,
        objects,
        evidence_refs,
    }
}

fn graph_chain_kind(node: &AttackGraphNodeRecord) -> &'static str {
    match node.kind.as_str() {
        NODE_SIGNAL | NODE_CANDIDATE | NODE_ROUTE | NODE_ENDPOINT | NODE_FORM => NODE_KIND_ENTRY,
        NODE_VERIFIED_VULNERABILITY | NODE_VERIFICATION_ATTEMPT => NODE_KIND_SINK,
        NODE_ROLE | NODE_OBJECT | NODE_PARAMETER | NODE_AUTHZ_MATRIX_ENTRY => NODE_KIND_OTHER,
        _ => NODE_KIND_OTHER,
    }
}

fn chain_node_rank(node: &ChainReasoningNode) -> u8 {
    match node.graph_kind.as_deref() {
        Some(NODE_CANDIDATE) => 0,
        Some(NODE_SIGNAL) => 1,
        Some(NODE_VERIFIED_VULNERABILITY) => 2,
        Some(NODE_VERIFICATION_ATTEMPT) => 3,
        Some(NODE_ROUTE) | Some(NODE_ENDPOINT) | Some(NODE_FORM) => 4,
        Some(NODE_ROLE) | Some(NODE_OBJECT) | Some(NODE_PARAMETER) => 5,
        _ => 9,
    }
}

fn graph_repo(node: &AttackGraphNodeRecord) -> Option<String> {
    node.properties
        .get("repo")
        .or_else(|| node.properties.get("repo_id"))
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty())
        .map(str::to_string)
}

fn graph_object_kind(node: &AttackGraphNodeRecord) -> Option<String> {
    node.properties
        .get("object_kind")
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty())
        .map(str::to_string)
}

fn severity_value(severity: &str) -> u8 {
    match severity.to_ascii_lowercase().as_str() {
        "critical" => 5,
        "high" => 4,
        "medium" => 3,
        "low" => 2,
        "info" | "informational" => 1,
        _ => 0,
    }
}

fn push_unique(values: &mut Vec<String>, value: String) {
    if !value.is_empty() && !values.iter().any(|v| v == &value) {
        values.push(value);
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

    #[tokio::test]
    async fn route_model_dual_write_records_semantic_v2_nodes() {
        let (_tmp, s) = fresh_store().await;
        seed_run_project(&s).await;
        let rec = RouteModelRecord {
            id: "routes-run-graph".to_string(),
            run_id: "run-graph".to_string(),
            project_id: "p-graph".to_string(),
            model: nyctos_types::product::RouteModel {
                backend_routes: vec![RouteModelEndpoint {
                    method: "PATCH".to_string(),
                    path: "/api/projects/:id".to_string(),
                    framework: "nest".to_string(),
                    repo: Some("web".to_string()),
                    handler_file: Some("src/projects.controller.ts".to_string()),
                    handler_name: Some("updateProject".to_string()),
                    line: Some(17),
                    params: vec!["id".to_string()],
                    query_params: vec!["include".to_string()],
                    middleware: vec!["JwtAuthGuard".to_string()],
                    auth_checks: vec!["jwt".to_string()],
                    role_checks: vec!["admin".to_string()],
                    body_fields: vec!["name".to_string()],
                    request_fields: vec!["name".to_string()],
                    response_hints: vec!["project".to_string()],
                    service_calls: vec!["ProjectsService".to_string()],
                    model_names: vec!["ProjectEntity".to_string()],
                    resource_names: vec!["project".to_string()],
                    tenant_fields: vec!["tenant_id".to_string()],
                    owner_fields: vec!["owner_id".to_string()],
                    side_effects: vec!["update_resource".to_string()],
                    state_changing: true,
                    confidence: 0.92,
                    evidence: Vec::new(),
                }],
                ..nyctos_types::product::RouteModel::default()
            },
            created_at: 2_000,
        };
        s.route_models().upsert(&rec).await.unwrap();

        let graph = s.attack_graph();
        let nodes = graph.list_nodes_by_run("run-graph").await.unwrap();
        assert!(nodes.iter().any(|n| {
            n.kind == NODE_OBJECT
                && n.stable_key == "service:projectsservice"
                && n.properties.get("object_kind").and_then(|v| v.as_str()) == Some("service")
        }));
        assert!(nodes
            .iter()
            .any(|n| n.kind == NODE_OBJECT && n.stable_key == "model:projectentity"));
        assert!(nodes
            .iter()
            .any(|n| n.kind == NODE_PARAMETER && n.stable_key.contains(":query:include")));
        assert!(nodes
            .iter()
            .any(|n| n.kind == NODE_PARAMETER && n.stable_key.contains(":tenant:tenant-id")));
        assert!(nodes
            .iter()
            .any(|n| n.kind == NODE_PARAMETER && n.stable_key.contains(":owner:owner-id")));
        let endpoint = nodes
            .iter()
            .find(|n| n.kind == NODE_ENDPOINT && n.label == "PATCH /api/projects/:id")
            .expect("endpoint node");
        assert_eq!(endpoint.properties.get("framework").and_then(|v| v.as_str()), Some("nest"));
        assert_eq!(
            endpoint.properties.get("handler_name").and_then(|v| v.as_str()),
            Some("updateProject")
        );
    }

    #[tokio::test]
    async fn graph_chain_planning_input_ranks_graph_backed_candidate_path() {
        let (_tmp, s) = fresh_store().await;
        seed_run_project(&s).await;
        let graph = s.attack_graph();
        let now = 3_000;
        let candidate = graph
            .upsert_node_by_key(
                "run-graph",
                "p-graph",
                NODE_CANDIDATE,
                &candidate_key("cand-1"),
                "Weak IDOR lead",
                Some("cand-1"),
                serde_json::json!({"severity": "High", "confidence": 0.71, "vuln_class": "IDOR"}),
                now,
            )
            .await
            .unwrap();
        let route = graph
            .upsert_route_node("run-graph", "p-graph", "/api/projects/:id", "test", now)
            .await
            .unwrap();
        let role =
            graph.upsert_role_node("run-graph", "p-graph", "authenticated", now).await.unwrap();
        let object =
            graph.upsert_resource_object("run-graph", "p-graph", "project", now).await.unwrap();
        graph
            .upsert_edge_by_key(
                "run-graph",
                "p-graph",
                EDGE_TARGETS,
                &candidate.id,
                &route.id,
                Some("cand-1"),
                serde_json::json!({"source": "fixture"}),
                now,
            )
            .await
            .unwrap();
        graph
            .upsert_edge_by_key(
                "run-graph",
                "p-graph",
                EDGE_USES_ROLE,
                &route.id,
                &role.id,
                None,
                serde_json::json!({"source": "fixture"}),
                now,
            )
            .await
            .unwrap();
        graph
            .upsert_edge_by_key(
                "run-graph",
                "p-graph",
                EDGE_TOUCHES_OBJECT,
                &route.id,
                &object.id,
                None,
                serde_json::json!({"source": "fixture"}),
                now,
            )
            .await
            .unwrap();

        let trail = graph.candidate_to_route("run-graph", "cand-1").await.unwrap().unwrap();
        assert!(trail.nodes.iter().any(|n| n.kind == NODE_ROUTE && n.label == "/api/projects/:id"));
        assert!(trail
            .edges
            .iter()
            .any(|e| e.kind == EDGE_TARGETS && e.evidence_ref.as_deref() == Some("cand-1")));

        let input = graph.chain_planning_input("run-graph", 10).await.unwrap().expect("input");
        assert_eq!(input.nodes[0].id, candidate.id);
        let candidate_input = input.nodes.iter().find(|n| n.id == candidate.id).unwrap();
        assert!(candidate_input.routes.iter().any(|r| r == "/api/projects/:id"));
        assert!(candidate_input.evidence_refs.iter().any(|r| r == "cand-1"));
        assert!(input.edges.iter().any(|e| {
            e.from == candidate.id
                && e.to == route.id
                && e.label == EDGE_TARGETS
                && e.evidence_ref.as_deref() == Some("cand-1")
        }));
    }
}

//! Durable exploration memory learned from prior runs.

use sqlx::{Row, SqlitePool};

use nyctos_types::attack_graph::{
    EDGE_LEARNED_FROM, EDGE_TARGETS, EDGE_TOUCHES_OBJECT, EDGE_USES_ROLE, NODE_CANDIDATE,
    NODE_ENDPOINT, NODE_EXPLORATION_MEMORY, NODE_OBJECT, NODE_ROLE, NODE_VERIFICATION_ATTEMPT,
};
pub use nyctos_types::product::ExplorationMemoryRecord;

use super::attack_graph::{attack_graph_node_id, AttackGraphStore};
use crate::store::StoreError;

#[derive(Debug, Clone)]
pub struct ExplorationMemoryInput {
    pub project_id: String,
    pub repo: String,
    pub run_id: String,
    pub source: String,
    pub hypothesis: String,
    pub endpoint: Option<String>,
    pub role_context: Option<String>,
    pub object_context: Option<String>,
    pub result: String,
    pub reason: String,
    pub useful_markers: Vec<String>,
    pub auth_session_notes: Option<String>,
    pub follow_up_ideas: Vec<String>,
    pub candidate_id: Option<String>,
    pub verification_attempt_id: Option<String>,
    pub trace_id: Option<String>,
    pub created_at: i64,
}

pub struct ExplorationMemoryStore<'a> {
    pool: &'a SqlitePool,
}

impl<'a> ExplorationMemoryStore<'a> {
    pub fn new(pool: &'a SqlitePool) -> Self {
        Self { pool }
    }

    pub async fn upsert(
        &self,
        input: &ExplorationMemoryInput,
    ) -> Result<ExplorationMemoryRecord, StoreError> {
        let memory_key = memory_key(input);
        let id = format!("em-{}", short_hash(&[&input.project_id, &input.repo, &memory_key,]));
        sqlx::query(
            r#"
            INSERT INTO exploration_memory (
                id, project_id, repo, run_id, source, hypothesis, endpoint, role_context,
                object_context, result, reason, useful_markers_json, auth_session_notes,
                follow_up_ideas_json, candidate_id, verification_attempt_id, trace_id,
                memory_key, created_at, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(project_id, repo, memory_key) DO UPDATE SET
                run_id = excluded.run_id,
                source = excluded.source,
                hypothesis = excluded.hypothesis,
                endpoint = excluded.endpoint,
                role_context = excluded.role_context,
                object_context = excluded.object_context,
                result = excluded.result,
                reason = excluded.reason,
                useful_markers_json = excluded.useful_markers_json,
                auth_session_notes = excluded.auth_session_notes,
                follow_up_ideas_json = excluded.follow_up_ideas_json,
                candidate_id = COALESCE(excluded.candidate_id, exploration_memory.candidate_id),
                verification_attempt_id = COALESCE(excluded.verification_attempt_id, exploration_memory.verification_attempt_id),
                trace_id = COALESCE(excluded.trace_id, exploration_memory.trace_id),
                updated_at = excluded.updated_at
            "#,
        )
        .bind(&id)
        .bind(&input.project_id)
        .bind(&input.repo)
        .bind(&input.run_id)
        .bind(&input.source)
        .bind(&input.hypothesis)
        .bind(&input.endpoint)
        .bind(&input.role_context)
        .bind(&input.object_context)
        .bind(&input.result)
        .bind(&input.reason)
        .bind(serde_json::to_string(&input.useful_markers)?)
        .bind(&input.auth_session_notes)
        .bind(serde_json::to_string(&input.follow_up_ideas)?)
        .bind(&input.candidate_id)
        .bind(&input.verification_attempt_id)
        .bind(&input.trace_id)
        .bind(&memory_key)
        .bind(input.created_at)
        .bind(input.created_at)
        .execute(self.pool)
        .await?;

        let rec = self
            .get_by_key(&input.project_id, &input.repo, &memory_key)
            .await?
            .ok_or(StoreError::Sqlx(sqlx::Error::RowNotFound))?;
        AttackGraphStore::new(self.pool).record_exploration_memory(&rec).await?;
        Ok(rec)
    }

    pub async fn get_by_key(
        &self,
        project_id: &str,
        repo: &str,
        memory_key: &str,
    ) -> Result<Option<ExplorationMemoryRecord>, StoreError> {
        let row = sqlx::query(
            r#"
            SELECT id, project_id, repo, run_id, source, hypothesis, endpoint, role_context,
                   object_context, result, reason, useful_markers_json, auth_session_notes,
                   follow_up_ideas_json, candidate_id, verification_attempt_id, trace_id,
                   memory_key, created_at, updated_at
            FROM exploration_memory
            WHERE project_id = ? AND repo = ? AND memory_key = ?
            "#,
        )
        .bind(project_id)
        .bind(repo)
        .bind(memory_key)
        .fetch_optional(self.pool)
        .await?;
        row.map(row_to_memory).transpose()
    }

    pub async fn list_by_run(
        &self,
        run_id: &str,
    ) -> Result<Vec<ExplorationMemoryRecord>, StoreError> {
        let rows = sqlx::query(
            r#"
            SELECT id, project_id, repo, run_id, source, hypothesis, endpoint, role_context,
                   object_context, result, reason, useful_markers_json, auth_session_notes,
                   follow_up_ideas_json, candidate_id, verification_attempt_id, trace_id,
                   memory_key, created_at, updated_at
            FROM exploration_memory
            WHERE run_id = ?
            ORDER BY updated_at DESC, id ASC
            "#,
        )
        .bind(run_id)
        .fetch_all(self.pool)
        .await?;
        rows.into_iter().map(row_to_memory).collect()
    }

    pub async fn relevant_for_repo(
        &self,
        project_id: &str,
        repo: &str,
        limit: usize,
        hints: &[String],
    ) -> Result<Vec<ExplorationMemoryRecord>, StoreError> {
        let rows = sqlx::query(
            r#"
            SELECT id, project_id, repo, run_id, source, hypothesis, endpoint, role_context,
                   object_context, result, reason, useful_markers_json, auth_session_notes,
                   follow_up_ideas_json, candidate_id, verification_attempt_id, trace_id,
                   memory_key, created_at, updated_at
            FROM exploration_memory
            WHERE project_id = ? AND repo = ?
            ORDER BY updated_at DESC, id ASC
            LIMIT 200
            "#,
        )
        .bind(project_id)
        .bind(repo)
        .fetch_all(self.pool)
        .await?;
        let mut rows = rows.into_iter().map(row_to_memory).collect::<Result<Vec<_>, _>>()?;
        rank_memory(&mut rows, hints);
        rows.truncate(limit);
        Ok(rows)
    }
}

pub fn memory_key(input: &ExplorationMemoryInput) -> String {
    [
        normalise_key_part(&input.hypothesis),
        input.endpoint.as_deref().map(normalise_key_part).unwrap_or_default(),
        input.role_context.as_deref().map(normalise_key_part).unwrap_or_default(),
        input.object_context.as_deref().map(normalise_key_part).unwrap_or_default(),
        normalise_key_part(&input.result),
    ]
    .join("|")
}

pub fn compact_memory_for_prompt(rows: &[ExplorationMemoryRecord], max_rows: usize) -> Vec<String> {
    rows.iter()
        .take(max_rows)
        .map(|m| {
            let mut line = format!(
                "prior {}: {} [{}] - {}",
                m.result,
                compact(&m.hypothesis, 150),
                m.endpoint.as_deref().unwrap_or("no endpoint"),
                compact(&m.reason, 180)
            );
            if let Some(role) = &m.role_context {
                line.push_str(&format!(" role={}", compact(role, 80)));
            }
            if let Some(object) = &m.object_context {
                line.push_str(&format!(" object={}", compact(object, 80)));
            }
            if !m.useful_markers.is_empty() {
                line.push_str(&format!(" markers={}", compact(&m.useful_markers.join(","), 100)));
            }
            if !m.follow_up_ideas.is_empty() {
                line.push_str(&format!(" next={}", compact(&m.follow_up_ideas.join("; "), 140)));
            }
            line
        })
        .collect()
}

fn rank_memory(rows: &mut [ExplorationMemoryRecord], hints: &[String]) {
    rows.sort_by(|a, b| {
        memory_score(b, hints)
            .cmp(&memory_score(a, hints))
            .then_with(|| b.updated_at.cmp(&a.updated_at))
            .then_with(|| a.id.cmp(&b.id))
    });
}

fn memory_score(row: &ExplorationMemoryRecord, hints: &[String]) -> i64 {
    let mut score = match row.result.as_str() {
        "confirmed" => 80,
        "blocked" => 65,
        "rejected" => 60,
        "inconclusive" => 45,
        _ => 30,
    };
    let haystack = format!(
        "{} {} {} {} {}",
        row.hypothesis,
        row.endpoint.as_deref().unwrap_or(""),
        row.role_context.as_deref().unwrap_or(""),
        row.object_context.as_deref().unwrap_or(""),
        row.reason
    )
    .to_ascii_lowercase();
    for hint in hints {
        let hint = normalise_key_part(hint);
        if !hint.is_empty() && haystack.contains(&hint) {
            score += 20;
        }
    }
    score + (row.updated_at / 86_400_000).min(10_000)
}

fn row_to_memory(row: sqlx::sqlite::SqliteRow) -> Result<ExplorationMemoryRecord, StoreError> {
    let useful_markers_json: String = row.try_get("useful_markers_json")?;
    let follow_up_ideas_json: String = row.try_get("follow_up_ideas_json")?;
    Ok(ExplorationMemoryRecord {
        id: row.try_get("id")?,
        project_id: row.try_get("project_id")?,
        repo: row.try_get("repo")?,
        run_id: row.try_get("run_id")?,
        source: row.try_get("source")?,
        hypothesis: row.try_get("hypothesis")?,
        endpoint: row.try_get("endpoint")?,
        role_context: row.try_get("role_context")?,
        object_context: row.try_get("object_context")?,
        result: row.try_get("result")?,
        reason: row.try_get("reason")?,
        useful_markers: serde_json::from_str(&useful_markers_json).unwrap_or_default(),
        auth_session_notes: row.try_get("auth_session_notes")?,
        follow_up_ideas: serde_json::from_str(&follow_up_ideas_json).unwrap_or_default(),
        candidate_id: row.try_get("candidate_id")?,
        verification_attempt_id: row.try_get("verification_attempt_id")?,
        trace_id: row.try_get("trace_id")?,
        memory_key: row.try_get("memory_key")?,
        created_at: row.try_get("created_at")?,
        updated_at: row.try_get("updated_at")?,
    })
}

fn normalise_key_part(raw: &str) -> String {
    raw.split_whitespace().collect::<Vec<_>>().join(" ").to_ascii_lowercase()
}

fn compact(raw: &str, max_chars: usize) -> String {
    let compact = raw.split_whitespace().collect::<Vec<_>>().join(" ");
    if compact.chars().count() <= max_chars {
        return compact;
    }
    compact.chars().take(max_chars).collect::<String>() + "..."
}

fn short_hash(parts: &[&str]) -> String {
    let mut h = blake3::Hasher::new();
    for part in parts {
        h.update(part.as_bytes());
        h.update(b"\0");
    }
    let digest = h.finalize();
    digest.as_bytes()[..12].iter().map(|b| format!("{b:02x}")).collect()
}

impl AttackGraphStore<'_> {
    pub async fn record_exploration_memory(
        &self,
        rec: &ExplorationMemoryRecord,
    ) -> Result<(), StoreError> {
        let now = rec.updated_at;
        let node = self
            .upsert_node_by_key(
                &rec.run_id,
                &rec.project_id,
                NODE_EXPLORATION_MEMORY,
                &rec.id,
                &format!("{}: {}", rec.result, compact(&rec.hypothesis, 80)),
                Some(&rec.id),
                serde_json::json!({
                    "source": rec.source,
                    "result": rec.result,
                    "reason": rec.reason,
                    "endpoint": rec.endpoint,
                    "role_context": rec.role_context,
                    "object_context": rec.object_context,
                    "useful_markers": rec.useful_markers,
                    "follow_up_ideas": rec.follow_up_ideas,
                }),
                now,
            )
            .await?;
        if let Some(candidate_id) = &rec.candidate_id {
            let candidate_node_id = attack_graph_node_id(&rec.run_id, NODE_CANDIDATE, candidate_id);
            if self.get_node(&candidate_node_id).await?.is_some() {
                self.upsert_edge_by_key(
                    &rec.run_id,
                    &rec.project_id,
                    EDGE_LEARNED_FROM,
                    &node.id,
                    &candidate_node_id,
                    Some(&rec.id),
                    serde_json::json!({"source": "exploration_memory"}),
                    now,
                )
                .await?;
            }
        }
        if let Some(attempt_id) = &rec.verification_attempt_id {
            let attempt_node_id =
                attack_graph_node_id(&rec.run_id, NODE_VERIFICATION_ATTEMPT, attempt_id);
            if self.get_node(&attempt_node_id).await?.is_some() {
                self.upsert_edge_by_key(
                    &rec.run_id,
                    &rec.project_id,
                    EDGE_LEARNED_FROM,
                    &node.id,
                    &attempt_node_id,
                    Some(&rec.id),
                    serde_json::json!({"source": "exploration_memory"}),
                    now,
                )
                .await?;
            }
        }
        if let Some(endpoint) = &rec.endpoint {
            let endpoint_node = self
                .upsert_node_by_key(
                    &rec.run_id,
                    &rec.project_id,
                    NODE_ENDPOINT,
                    endpoint,
                    endpoint,
                    None,
                    serde_json::json!({"source": "exploration_memory"}),
                    now,
                )
                .await?;
            self.upsert_edge_by_key(
                &rec.run_id,
                &rec.project_id,
                EDGE_TARGETS,
                &node.id,
                &endpoint_node.id,
                Some(&rec.id),
                serde_json::json!({}),
                now,
            )
            .await?;
        }
        if let Some(role) = &rec.role_context {
            let role_node = self
                .upsert_node_by_key(
                    &rec.run_id,
                    &rec.project_id,
                    NODE_ROLE,
                    role,
                    role,
                    None,
                    serde_json::json!({"source": "exploration_memory"}),
                    now,
                )
                .await?;
            self.upsert_edge_by_key(
                &rec.run_id,
                &rec.project_id,
                EDGE_USES_ROLE,
                &node.id,
                &role_node.id,
                Some(&rec.id),
                serde_json::json!({}),
                now,
            )
            .await?;
        }
        if let Some(object) = &rec.object_context {
            let object_node = self
                .upsert_node_by_key(
                    &rec.run_id,
                    &rec.project_id,
                    NODE_OBJECT,
                    object,
                    object,
                    None,
                    serde_json::json!({"source": "exploration_memory"}),
                    now,
                )
                .await?;
            self.upsert_edge_by_key(
                &rec.run_id,
                &rec.project_id,
                EDGE_TOUCHES_OBJECT,
                &node.id,
                &object_node.id,
                Some(&rec.id),
                serde_json::json!({}),
                now,
            )
            .await?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::testutil::{fresh_store, sample_repo, sample_run};

    fn input(run_id: &str, result: &str, now: i64) -> ExplorationMemoryInput {
        ExplorationMemoryInput {
            project_id: crate::store::project::DEFAULT_PROJECT_ID.to_string(),
            repo: "repo".to_string(),
            run_id: run_id.to_string(),
            source: "test".to_string(),
            hypothesis: "admin export leaks invoices".to_string(),
            endpoint: Some("GET /admin/export".to_string()),
            role_context: Some("admin".to_string()),
            object_context: Some("invoice".to_string()),
            result: result.to_string(),
            reason: "403 proved normal user cannot reach export".to_string(),
            useful_markers: vec!["403".to_string()],
            auth_session_notes: Some("normal user session".to_string()),
            follow_up_ideas: vec!["try stale invite".to_string()],
            candidate_id: None,
            verification_attempt_id: None,
            trace_id: None,
            created_at: now,
        }
    }

    #[tokio::test]
    async fn persists_and_deduplicates_by_memory_key() {
        let (_tmp, s) = fresh_store().await;
        s.repos().upsert(&sample_repo("repo")).await.unwrap();
        s.runs().insert(&sample_run("run-1")).await.unwrap();
        s.runs().insert(&sample_run("run-2")).await.unwrap();
        let first =
            s.exploration_memory().upsert(&input("run-1", "rejected", 1_000)).await.unwrap();
        let second =
            s.exploration_memory().upsert(&input("run-2", "rejected", 2_000)).await.unwrap();
        assert_eq!(first.id, second.id);
        assert_eq!(second.run_id, "run-2");
        assert_eq!(s.exploration_memory().list_by_run("run-2").await.unwrap().len(), 1);
    }

    #[tokio::test]
    async fn relevance_ranking_prefers_hints_and_outcomes() {
        let mut rows = vec![
            ExplorationMemoryRecord {
                result: "inconclusive".to_string(),
                hypothesis: "other path".to_string(),
                updated_at: 2_000,
                ..record("a")
            },
            ExplorationMemoryRecord {
                result: "rejected".to_string(),
                hypothesis: "admin export".to_string(),
                endpoint: Some("GET /admin/export".to_string()),
                updated_at: 1_000,
                ..record("b")
            },
        ];
        rank_memory(&mut rows, &["admin export".to_string()]);
        assert_eq!(rows[0].id, "b");
    }

    #[test]
    fn prompt_compaction_includes_result_and_followups() {
        let rows = vec![record("m")];
        let lines = compact_memory_for_prompt(&rows, 4);
        assert!(lines[0].contains("prior rejected"));
        assert!(lines[0].contains("next=try stale invite"));
    }

    fn record(id: &str) -> ExplorationMemoryRecord {
        ExplorationMemoryRecord {
            id: id.to_string(),
            project_id: "project".to_string(),
            repo: "repo".to_string(),
            run_id: "run".to_string(),
            source: "test".to_string(),
            hypothesis: "admin export leaks invoices".to_string(),
            endpoint: Some("GET /admin/export".to_string()),
            role_context: Some("admin".to_string()),
            object_context: Some("invoice".to_string()),
            result: "rejected".to_string(),
            reason: "403 blocked normal user".to_string(),
            useful_markers: vec!["403".to_string()],
            auth_session_notes: Some("normal user".to_string()),
            follow_up_ideas: vec!["try stale invite".to_string()],
            candidate_id: None,
            verification_attempt_id: None,
            trace_id: None,
            memory_key: "key".to_string(),
            created_at: 1_000,
            updated_at: 1_000,
        }
    }
}

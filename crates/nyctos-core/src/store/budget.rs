//! `budgets` table - per-run AI spend caps keyed by `(run_id, kind)`.

use serde::{Deserialize, Serialize};
use sqlx::SqlitePool;

use crate::store::StoreError;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum BudgetKind {
    OneShot,
    AgentLoop,
    Total,
}

impl BudgetKind {
    pub fn as_str(self) -> &'static str {
        match self {
            BudgetKind::OneShot => "OneShot",
            BudgetKind::AgentLoop => "AgentLoop",
            BudgetKind::Total => "Total",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BudgetRecord {
    pub run_id: String,
    pub kind: String,
    pub cap_usd_micros: i64,
    pub spent_usd_micros: i64,
    pub halted: bool,
    pub halted_at: Option<i64>,
}

pub struct BudgetStore<'a> {
    pool: &'a SqlitePool,
}

impl<'a> BudgetStore<'a> {
    pub fn new(pool: &'a SqlitePool) -> Self {
        Self { pool }
    }

    /// Atomically insert a default `(run_id, kind)` row with the given
    /// cap and `spent_usd_micros = 0` *only if no row exists yet*.
    /// `INSERT OR IGNORE` is a single SQL statement so concurrent
    /// callers do not race; this is the lazy-init path used by
    /// `BudgetStoreTracker::ensure_row` where unconditional `upsert`
    /// would clobber any spend a peer task already recorded.
    /// Runtime-checked SQL to avoid expanding the `.sqlx/` cache for
    /// a one-call internal helper.
    pub async fn ensure_default(
        &self,
        run_id: &str,
        kind: &str,
        cap_usd_micros: i64,
    ) -> Result<(), StoreError> {
        sqlx::query(
            "INSERT OR IGNORE INTO budgets \
             (run_id, kind, cap_usd_micros, spent_usd_micros, halted, halted_at) \
             VALUES (?, ?, ?, 0, 0, NULL)",
        )
        .bind(run_id)
        .bind(kind)
        .bind(cap_usd_micros)
        .execute(self.pool)
        .await?;
        Ok(())
    }

    pub async fn upsert(&self, b: &BudgetRecord) -> Result<(), StoreError> {
        let halted = i64::from(b.halted);
        sqlx::query!(
            r#"
            INSERT INTO budgets (
                run_id, kind, cap_usd_micros, spent_usd_micros, halted, halted_at
            ) VALUES (?, ?, ?, ?, ?, ?)
            ON CONFLICT(run_id, kind) DO UPDATE SET
                cap_usd_micros   = excluded.cap_usd_micros,
                spent_usd_micros = excluded.spent_usd_micros,
                halted           = excluded.halted,
                halted_at        = excluded.halted_at
            "#,
            b.run_id,
            b.kind,
            b.cap_usd_micros,
            b.spent_usd_micros,
            halted,
            b.halted_at,
        )
        .execute(self.pool)
        .await?;
        Ok(())
    }

    pub async fn get(&self, run_id: &str, kind: &str) -> Result<Option<BudgetRecord>, StoreError> {
        let row = sqlx::query!(
            r#"
            SELECT run_id AS "run_id!", kind AS "kind!",
                   cap_usd_micros AS "cap_usd_micros!: i64",
                   spent_usd_micros AS "spent_usd_micros!: i64",
                   halted AS "halted!: i64",
                   halted_at
            FROM budgets WHERE run_id = ? AND kind = ?
            "#,
            run_id,
            kind
        )
        .fetch_optional(self.pool)
        .await?;
        Ok(row.map(|r| BudgetRecord {
            run_id: r.run_id,
            kind: r.kind,
            cap_usd_micros: r.cap_usd_micros,
            spent_usd_micros: r.spent_usd_micros,
            halted: r.halted != 0,
            halted_at: r.halted_at,
        }))
    }

    pub async fn list_for_run(&self, run_id: &str) -> Result<Vec<BudgetRecord>, StoreError> {
        let rows = sqlx::query!(
            r#"
            SELECT run_id AS "run_id!", kind AS "kind!",
                   cap_usd_micros AS "cap_usd_micros!: i64",
                   spent_usd_micros AS "spent_usd_micros!: i64",
                   halted AS "halted!: i64",
                   halted_at
            FROM budgets WHERE run_id = ?
            "#,
            run_id
        )
        .fetch_all(self.pool)
        .await?;
        Ok(rows
            .into_iter()
            .map(|r| BudgetRecord {
                run_id: r.run_id,
                kind: r.kind,
                cap_usd_micros: r.cap_usd_micros,
                spent_usd_micros: r.spent_usd_micros,
                halted: r.halted != 0,
                halted_at: r.halted_at,
            })
            .collect())
    }

    /// Atomically add to `spent_usd_micros`. Returns the new spent total.
    pub async fn add_spend(
        &self,
        run_id: &str,
        kind: &str,
        micros: i64,
    ) -> Result<i64, StoreError> {
        let row = sqlx::query!(
            r#"
            UPDATE budgets
               SET spent_usd_micros = spent_usd_micros + ?
             WHERE run_id = ? AND kind = ?
             RETURNING spent_usd_micros AS "spent!: i64"
            "#,
            micros,
            run_id,
            kind
        )
        .fetch_one(self.pool)
        .await?;
        Ok(row.spent)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::testutil::{fresh_store, sample_run};

    fn b(run_id: &str, kind: &str) -> BudgetRecord {
        BudgetRecord {
            run_id: run_id.to_string(),
            kind: kind.to_string(),
            cap_usd_micros: 10_000_000,
            spent_usd_micros: 0,
            halted: false,
            halted_at: None,
        }
    }

    #[tokio::test]
    async fn upsert_then_get_roundtrips() {
        let (_tmp, s) = fresh_store().await;
        s.runs().insert(&sample_run("run")).await.expect("run");
        let row = b("run", "Total");
        s.budgets().upsert(&row).await.expect("upsert");
        let got = s.budgets().get("run", "Total").await.expect("get").expect("row");
        assert_eq!(got, row);
    }

    #[tokio::test]
    async fn list_for_run_returns_all_kinds() {
        let (_tmp, s) = fresh_store().await;
        s.runs().insert(&sample_run("run")).await.expect("run");
        s.budgets().upsert(&b("run", "OneShot")).await.expect("a");
        s.budgets().upsert(&b("run", "AgentLoop")).await.expect("b");
        s.budgets().upsert(&b("run", "Total")).await.expect("c");
        let got = s.budgets().list_for_run("run").await.expect("list");
        assert_eq!(got.len(), 3);
    }

    #[tokio::test]
    async fn add_spend_returns_new_total() {
        let (_tmp, s) = fresh_store().await;
        s.runs().insert(&sample_run("run")).await.expect("run");
        s.budgets().upsert(&b("run", "Total")).await.expect("upsert");
        let after_a = s.budgets().add_spend("run", "Total", 100).await.expect("a");
        let after_b = s.budgets().add_spend("run", "Total", 250).await.expect("b");
        assert_eq!(after_a, 100);
        assert_eq!(after_b, 350);
    }

    #[tokio::test]
    async fn halted_flag_roundtrips() {
        let (_tmp, s) = fresh_store().await;
        s.runs().insert(&sample_run("run")).await.expect("run");
        let mut row = b("run", "Total");
        row.halted = true;
        row.halted_at = Some(9_999);
        s.budgets().upsert(&row).await.expect("upsert");
        let got = s.budgets().get("run", "Total").await.expect("get").expect("row");
        assert!(got.halted);
        assert_eq!(got.halted_at, Some(9_999));
    }

    #[tokio::test]
    async fn cascade_from_run_delete() {
        let (_tmp, s) = fresh_store().await;
        s.runs().insert(&sample_run("doomed")).await.expect("run");
        s.budgets().upsert(&b("doomed", "Total")).await.expect("upsert");
        s.runs().delete("doomed").await.expect("del");
        assert!(
            s.budgets().get("doomed", "Total").await.expect("get").is_none(),
            "budget should cascade-delete with parent run"
        );
    }
}

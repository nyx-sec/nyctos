//! Phase 27: cron-driven scan scheduler.
//!
//! Wakes once every `tick_interval` (production: 60s, tests: a few
//! milliseconds), evaluates every `[[schedule]]` entry in the running
//! config, and triggers a scan via the same [`ScanTrigger`] handle the
//! HTTP API uses. The cron expression is the standard 5-field shape
//! (`minute hour day-of-month month day-of-week`); on `(0 3 * * 1)`
//! the scheduler fires at 03:00 every Monday.
//!
//! The scheduler is fire-and-forget: it submits via `try_send` so a
//! saturated dispatcher returns a clean `Backpressure` error (logged
//! and skipped) instead of blocking the wake loop.
//!
//! Tests use `Clock::Manual` so they can advance time deterministically
//! without sleeping.
//!
//! Design notes:
//! - Each entry tracks `last_fired_minute` so a wake that lands in the
//!   same minute as the previous fire does not double-trigger.
//! - Parser bias: the underlying `cron` crate expects 6 fields
//!   (seconds first). [`expand_to_cron_crate`] prepends `"0 "` so the
//!   operator-facing config stays on the canonical 5-field shape.
//! - The scheduler does not block on the run completing; the API's
//!   `ScanTrigger` returns as soon as the run id is minted.

use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;

#[cfg(test)]
use chrono::{DateTime, TimeZone, Utc};
#[cfg(not(test))]
use chrono::{DateTime, Utc};
use cron::Schedule;
use nyx_agent_api::{ScanTrigger, ScanTriggerError};
use nyx_agent_core::ScheduleConfig;
use tokio::sync::watch;
use tracing::{debug, error, warn};

/// Minimum interval between wake-ups in production.
pub const DEFAULT_TICK_INTERVAL: Duration = Duration::from_secs(60);

/// One parsed schedule entry. The `cron` crate's [`Schedule`] holds the
/// parsed fields; `last_fired_minute` lets us debounce when wakes are
/// faster than the cron granularity (which is the case in tests and on
/// hosts whose clock drifts inside the same minute).
#[derive(Debug)]
struct Entry {
    cron_expr: String,
    repo: Option<String>,
    label: String,
    schedule: Schedule,
    /// `Some(minute_epoch)` once the entry has fired at least once.
    last_fired_minute: Option<i64>,
}

/// Errors surfaced when parsing the `[[schedule]]` array.
#[derive(Debug, thiserror::Error)]
pub enum SchedulerError {
    #[error("schedule `{label}`: invalid cron expression `{expr}`: {source}")]
    InvalidCron {
        label: String,
        expr: String,
        #[source]
        source: cron::error::Error,
    },
}

/// Time source. Production uses [`Clock::System`]; tests use
/// [`Clock::Manual`] so they can advance time without sleeping.
#[allow(dead_code)]
pub enum Clock {
    System,
    Manual(Arc<std::sync::Mutex<DateTime<Utc>>>),
}

impl Clock {
    pub fn now(&self) -> DateTime<Utc> {
        match self {
            Clock::System => Utc::now(),
            Clock::Manual(t) => *t.lock().expect("manual clock poisoned"),
        }
    }

    /// Helper for tests: advance the manual clock by `delta`.
    #[cfg(test)]
    fn advance(&self, delta: chrono::Duration) {
        if let Clock::Manual(t) = self {
            let mut g = t.lock().expect("manual clock poisoned");
            *g += delta;
        }
    }
}

/// Owns the parsed schedule entries + a handle to the scan trigger.
pub struct Scheduler {
    entries: Vec<Entry>,
    trigger: Arc<dyn ScanTrigger>,
    clock: Clock,
}

impl Scheduler {
    /// Parse the config snapshot and build a scheduler bound to
    /// `trigger`. Invalid cron expressions short-circuit with a clean
    /// error so the builder refuses to construct a scheduler with
    /// broken config rather than silently dropping the entry. (The
    /// daemon's `serve()` currently logs the error and starts without
    /// the scheduler; see the deferred item to escalate that to a
    /// hard refusal.)
    pub fn from_config(
        entries: &[ScheduleConfig],
        trigger: Arc<dyn ScanTrigger>,
    ) -> Result<Self, SchedulerError> {
        Self::with_clock(entries, trigger, Clock::System)
    }

    pub fn with_clock(
        entries: &[ScheduleConfig],
        trigger: Arc<dyn ScanTrigger>,
        clock: Clock,
    ) -> Result<Self, SchedulerError> {
        let mut parsed = Vec::with_capacity(entries.len());
        for cfg in entries {
            let expr = expand_to_cron_crate(&cfg.cron);
            let schedule =
                Schedule::from_str(&expr).map_err(|source| SchedulerError::InvalidCron {
                    label: cfg.label.clone(),
                    expr: cfg.cron.clone(),
                    source,
                })?;
            parsed.push(Entry {
                cron_expr: cfg.cron.clone(),
                repo: cfg.repo.clone(),
                label: cfg.label.clone(),
                schedule,
                last_fired_minute: None,
            });
        }
        Ok(Self { entries: parsed, trigger, clock })
    }

    /// Evaluate every entry exactly once against `now`. Any entry whose
    /// `prev_or_match` falls within the same minute as `now` AND has
    /// not yet fired for that minute triggers a scan. Returns the list
    /// of labels that fired (useful for tests).
    pub async fn tick(&mut self) -> Vec<FiredEntry> {
        let now = self.clock.now();
        let minute = floor_to_minute_epoch(now);
        let mut fired = Vec::new();
        for entry in &mut self.entries {
            if entry.last_fired_minute == Some(minute) {
                continue;
            }
            // `prev_or_match` does not exist on `cron::Schedule`; emulate
            // by walking forward from one cron-window-min ago and
            // checking whether the next fire time lies in [start, now].
            let one_year_ago = now - chrono::Duration::days(366);
            let due = entry.schedule.after(&one_year_ago).take_while(|t| *t <= now).last();
            let Some(scheduled_at) = due else { continue };
            if floor_to_minute_epoch(scheduled_at) != minute {
                continue;
            }
            entry.last_fired_minute = Some(minute);
            match self.trigger.trigger(entry.repo.clone()).await {
                Ok(run_id) => {
                    debug!(
                        schedule = %entry.label,
                        cron = %entry.cron_expr,
                        run_id = %run_id,
                        "scheduler: trigger ok"
                    );
                    fired.push(FiredEntry {
                        label: entry.label.clone(),
                        repo: entry.repo.clone(),
                        run_id,
                    });
                }
                Err(ScanTriggerError::Backpressure(msg)) => {
                    warn!(
                        schedule = %entry.label,
                        reason = %msg,
                        "scheduler: dispatcher saturated, skipping this fire"
                    );
                }
                Err(err) => {
                    error!(
                        schedule = %entry.label,
                        error = %err,
                        "scheduler: trigger failed"
                    );
                }
            }
        }
        fired
    }

    /// Drive the scheduler until `shutdown` flips to `true`. Sleeps
    /// `tick_interval` between iterations; one iteration runs every
    /// entry through [`Self::tick`].
    pub async fn run(mut self, tick_interval: Duration, mut shutdown: watch::Receiver<bool>) {
        loop {
            self.tick().await;
            tokio::select! {
                _ = tokio::time::sleep(tick_interval) => {}
                _ = shutdown.changed() => {
                    if *shutdown.borrow() {
                        break;
                    }
                }
            }
        }
    }
}

/// One scheduled fire. Returned by [`Scheduler::tick`] so tests can
/// observe which entries triggered without subscribing to the
/// dispatcher.
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct FiredEntry {
    pub label: String,
    pub repo: Option<String>,
    pub run_id: String,
}

fn floor_to_minute_epoch(t: DateTime<Utc>) -> i64 {
    t.timestamp() - (t.timestamp() % 60)
}

/// The `cron` crate (0.12) expects a 6- or 7-field expression with the
/// seconds field first AND its own day-of-week ordinal range
/// (`Sunday=1, Monday=2, ..., Saturday=7`). Operator-facing config uses
/// the canonical 5-field Unix cron shape
/// (`minute hour day-of-month month day-of-week`) where the day-of-week
/// is `Sunday=0|7, Monday=1, ..., Saturday=6`. This converter:
///
/// 1. Translates each numeric day-of-week token via
///    `cron_crate = (standard % 7) + 1` so `0 3 * * 1` (Mon 3am) maps
///    to `0 3 * * 2` (Mon 3am in cron crate terms).
/// 2. Prepends `"0"` for the seconds field.
///
/// A 6- or 7-field input passes through unchanged so test fixtures
/// that already include seconds keep working.
fn expand_to_cron_crate(expr: &str) -> String {
    let fields: Vec<&str> = expr.split_whitespace().collect();
    if fields.len() != 5 {
        return expr.to_string();
    }
    let dow = translate_dow_field(fields[4]);
    format!("0 {} {} {} {} {}", fields[0], fields[1], fields[2], fields[3], dow)
}

/// Map a standard-cron day-of-week field (Sunday=0|7, Monday=1, ...)
/// onto the `cron` crate's day-of-week ordinals (Sunday=1, Monday=2,
/// ...). Handles bare digits, comma-separated lists, ranges (`1-5`),
/// step values (`*/2`, `1-5/2`), and the wildcard `*`. Day-of-week
/// names (`MON`, `FRI`) pass through unchanged because the cron crate
/// already accepts them.
fn translate_dow_field(field: &str) -> String {
    field.split(',').map(translate_dow_item).collect::<Vec<_>>().join(",")
}

fn translate_dow_item(item: &str) -> String {
    // Split on `/` to peel off any step suffix.
    let (range_part, step) = match item.split_once('/') {
        Some((lhs, rhs)) => (lhs, Some(rhs.to_string())),
        None => (item, None),
    };
    let translated_range = if range_part == "*" || range_part.is_empty() {
        range_part.to_string()
    } else if let Some((lo, hi)) = range_part.split_once('-') {
        format!("{}-{}", translate_dow_token(lo), translate_dow_token(hi))
    } else {
        translate_dow_token(range_part)
    };
    match step {
        Some(s) => format!("{}/{}", translated_range, s),
        None => translated_range,
    }
}

fn translate_dow_token(token: &str) -> String {
    match token.parse::<u32>() {
        Ok(n) => ((n % 7) + 1).to_string(),
        Err(_) => token.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::future::Future;
    use std::pin::Pin;
    use std::sync::Mutex;
    use tokio::sync::Mutex as AsyncMutex;

    /// In-memory stub. Records each trigger call so tests can assert
    /// which schedules fired.
    #[derive(Default)]
    struct StubTrigger {
        calls: AsyncMutex<Vec<Option<String>>>,
    }

    impl ScanTrigger for StubTrigger {
        fn trigger<'a>(
            &'a self,
            repo: Option<String>,
        ) -> Pin<Box<dyn Future<Output = Result<String, ScanTriggerError>> + Send + 'a>> {
            Box::pin(async move {
                let mut g = self.calls.lock().await;
                let run_id = format!("run-{}", g.len());
                g.push(repo);
                Ok(run_id)
            })
        }
    }

    fn manual_clock(t: DateTime<Utc>) -> Clock {
        Clock::Manual(Arc::new(Mutex::new(t)))
    }

    #[test]
    fn five_field_expands_to_six_field() {
        // Monday=1 in standard cron → Monday=2 in the cron crate.
        assert_eq!(expand_to_cron_crate("0 3 * * 1"), "0 0 3 * * 2");
        // Pre-translated (6-field) inputs pass through verbatim.
        assert_eq!(expand_to_cron_crate("0 0 3 * * 2"), "0 0 3 * * 2");
        // Wildcards survive.
        assert_eq!(expand_to_cron_crate("0 3 * * *"), "0 0 3 * * *");
        // Sunday is `0` or `7` in standard cron → `1` in cron crate.
        assert_eq!(expand_to_cron_crate("0 3 * * 0"), "0 0 3 * * 1");
        assert_eq!(expand_to_cron_crate("0 3 * * 7"), "0 0 3 * * 1");
        // Range Mon-Fri (1-5) → Tue-Sat? No — Mon-Fri (1-5) maps to
        // cron-crate ords 2-6 which is the same Mon-Fri.
        assert_eq!(expand_to_cron_crate("0 3 * * 1-5"), "0 0 3 * * 2-6");
        // Step on a wildcard.
        assert_eq!(expand_to_cron_crate("0 3 * * */2"), "0 0 3 * * */2");
        // List.
        assert_eq!(expand_to_cron_crate("0 3 * * 1,3,5"), "0 0 3 * * 2,4,6");
    }

    #[test]
    fn invalid_cron_is_refused() {
        let trigger: Arc<dyn ScanTrigger> = Arc::new(StubTrigger::default());
        let result = Scheduler::from_config(
            &[ScheduleConfig {
                cron: "not a cron".to_string(),
                repo: None,
                label: "bad".to_string(),
            }],
            trigger,
        );
        match result {
            Err(SchedulerError::InvalidCron { .. }) => {}
            other => panic!("expected InvalidCron, got Ok or other err: {:?}", other.err()),
        }
    }

    #[tokio::test]
    async fn monday_3am_fires_on_a_monday_at_3am() {
        // 2026-05-18 is a Monday.
        let mon_3am = Utc.with_ymd_and_hms(2026, 5, 18, 3, 0, 0).unwrap();
        let clock = manual_clock(mon_3am);
        let trigger: Arc<StubTrigger> = Arc::new(StubTrigger::default());
        let mut sched = Scheduler::with_clock(
            &[ScheduleConfig {
                cron: "0 3 * * 1".to_string(),
                repo: Some("nyx-pro".to_string()),
                label: "weekly".to_string(),
            }],
            Arc::clone(&trigger) as Arc<dyn ScanTrigger>,
            clock,
        )
        .unwrap();
        let fired = sched.tick().await;
        assert_eq!(fired.len(), 1, "monday 3am must fire `0 3 * * 1`");
        assert_eq!(fired[0].label, "weekly");
        assert_eq!(fired[0].repo.as_deref(), Some("nyx-pro"));
        let calls = trigger.calls.lock().await.clone();
        assert_eq!(calls, vec![Some("nyx-pro".to_string())]);
    }

    #[tokio::test]
    async fn tuesday_does_not_fire_monday_schedule() {
        let tue_3am = Utc.with_ymd_and_hms(2026, 5, 19, 3, 0, 0).unwrap();
        let trigger: Arc<StubTrigger> = Arc::new(StubTrigger::default());
        let mut sched = Scheduler::with_clock(
            &[ScheduleConfig {
                cron: "0 3 * * 1".to_string(),
                repo: None,
                label: "weekly".to_string(),
            }],
            Arc::clone(&trigger) as Arc<dyn ScanTrigger>,
            manual_clock(tue_3am),
        )
        .unwrap();
        assert!(sched.tick().await.is_empty(), "tuesday 3am must not fire monday schedule");
        let calls = trigger.calls.lock().await.clone();
        assert!(calls.is_empty());
    }

    #[tokio::test]
    async fn second_tick_in_same_minute_does_not_double_fire() {
        let mon_3am = Utc.with_ymd_and_hms(2026, 5, 18, 3, 0, 0).unwrap();
        let clock = manual_clock(mon_3am);
        let trigger: Arc<StubTrigger> = Arc::new(StubTrigger::default());
        let entries = [ScheduleConfig {
            cron: "0 3 * * 1".to_string(),
            repo: None,
            label: "weekly".to_string(),
        }];
        let mut sched =
            Scheduler::with_clock(&entries, Arc::clone(&trigger) as Arc<dyn ScanTrigger>, clock)
                .unwrap();
        assert_eq!(sched.tick().await.len(), 1);
        // Advance 30 seconds — still inside 03:00 — second tick must
        // observe last_fired_minute and skip.
        sched.clock.advance(chrono::Duration::seconds(30));
        assert!(sched.tick().await.is_empty());
        let calls = trigger.calls.lock().await.clone();
        assert_eq!(calls.len(), 1);
    }

    #[tokio::test]
    async fn next_monday_3am_fires_after_a_week() {
        let mon_3am = Utc.with_ymd_and_hms(2026, 5, 18, 3, 0, 0).unwrap();
        let clock = manual_clock(mon_3am);
        let trigger: Arc<StubTrigger> = Arc::new(StubTrigger::default());
        let mut sched = Scheduler::with_clock(
            &[ScheduleConfig {
                cron: "0 3 * * 1".to_string(),
                repo: None,
                label: "weekly".to_string(),
            }],
            Arc::clone(&trigger) as Arc<dyn ScanTrigger>,
            clock,
        )
        .unwrap();
        assert_eq!(sched.tick().await.len(), 1);
        // Advance a week + 1 minute. Next monday at 03:01 the prior
        // fire window has closed AND the new minute matches; entry
        // must fire again.
        sched.clock.advance(chrono::Duration::days(7));
        assert_eq!(sched.tick().await.len(), 1);
        let calls = trigger.calls.lock().await.clone();
        assert_eq!(calls.len(), 2);
    }

    #[tokio::test]
    async fn backpressure_is_logged_and_skipped() {
        struct FullTrigger;
        impl ScanTrigger for FullTrigger {
            fn trigger<'a>(
                &'a self,
                _repo: Option<String>,
            ) -> Pin<Box<dyn Future<Output = Result<String, ScanTriggerError>> + Send + 'a>>
            {
                Box::pin(async { Err(ScanTriggerError::Backpressure("queue full".to_string())) })
            }
        }
        let mon_3am = Utc.with_ymd_and_hms(2026, 5, 18, 3, 0, 0).unwrap();
        let trigger: Arc<dyn ScanTrigger> = Arc::new(FullTrigger);
        let mut sched = Scheduler::with_clock(
            &[ScheduleConfig {
                cron: "0 3 * * 1".to_string(),
                repo: None,
                label: "weekly".to_string(),
            }],
            trigger,
            manual_clock(mon_3am),
        )
        .unwrap();
        let fired = sched.tick().await;
        // Backpressure does not surface as a `fired` row; the
        // dispatcher refused to mint a run id.
        assert!(fired.is_empty());
    }
}

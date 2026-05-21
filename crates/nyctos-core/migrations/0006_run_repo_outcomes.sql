-- v6 schema: run_repo_outcomes join table for per-repo outcome history.
--
-- The dispatcher emits a RepoOutcome (Success / Inconclusive /
-- Failed) per repo per run, but the persistence layer historically
-- recorded only the success branch (via `findings` rows + the
-- `repos.last_scan_*` columns) and dropped the inconclusive / failed
-- signal once the RunEvent stream closed. An operator opening a
-- historical run after the WebSocket disconnected had no way to see
-- which repos timed out, which ones the scanner crashed on, or how
-- long each took.
--
-- The table records (run_id, repo, outcome, reason, elapsed_ms) at
-- the moment the dispatcher finalised the per-repo bundle. Rows live
-- until the parent run is deleted (FK cascade). `repo` is plain TEXT
-- with no FK to `repos.name` so the table tolerates ad-hoc workspace
-- names the dispatcher may walk before / after a rename - matches
-- the shape of `findings.repo` for the same reason.

CREATE TABLE run_repo_outcomes (
    run_id      TEXT    NOT NULL,
    repo        TEXT    NOT NULL,
    outcome     TEXT    NOT NULL,
    reason      TEXT,
    elapsed_ms  INTEGER NOT NULL,
    PRIMARY KEY (run_id, repo),
    FOREIGN KEY (run_id) REFERENCES runs(id) ON DELETE CASCADE
);

CREATE INDEX idx_run_repo_outcomes_run_id  ON run_repo_outcomes(run_id);
CREATE INDEX idx_run_repo_outcomes_outcome ON run_repo_outcomes(outcome);

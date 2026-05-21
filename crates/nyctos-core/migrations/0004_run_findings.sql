-- v4 schema: run_findings join table for per-run finding membership.
--
-- `findings` collapses every observation of a stable id (the BLAKE3
-- truncation over `(repo, path, line, cap, rule)`) into one row that
-- carries the latest run_id / status. That collapse loses per-run
-- history, so `GET /api/v1/runs/:id/findings` previously could not
-- distinguish "this finding regressed against the prior run" from
-- "this finding is unchanged" and never surfaced "closed since the
-- prior run".
--
-- `run_findings` records the (run_id, finding_id, status) tuple at
-- the moment the finding was observed. `FindingStore::upsert` writes
-- one row per call; rows live until the parent run or finding is
-- deleted (FK cascade). The classifier joins current-vs-prior
-- membership to label each row as new / regressed / closed /
-- unchanged.
--
-- Backfill: each existing `findings` row carries the last observed
-- run_id / status, so the migration seeds one row per finding under
-- its last-known run. Older runs (whose findings have since been
-- re-observed on a later run) get no membership backfill because
-- the per-observation history was never recorded; classify_diff
-- degrades gracefully to `new` for those rows.

CREATE TABLE run_findings (
    run_id      TEXT NOT NULL,
    finding_id  TEXT NOT NULL,
    status      TEXT NOT NULL,
    PRIMARY KEY (run_id, finding_id),
    FOREIGN KEY (run_id)     REFERENCES runs(id)     ON DELETE CASCADE,
    FOREIGN KEY (finding_id) REFERENCES findings(id) ON DELETE CASCADE
);

CREATE INDEX idx_run_findings_run_id     ON run_findings(run_id);
CREATE INDEX idx_run_findings_finding_id ON run_findings(finding_id);

INSERT INTO run_findings (run_id, finding_id, status)
SELECT run_id, id, status FROM findings;

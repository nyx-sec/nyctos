-- Per-run business-logic template synthesis summary.
--
-- The candidates themselves remain normal pentest_candidates rows. This
-- table records which first-class templates were considered, how many
-- candidates they generated, and why a template was skipped.

CREATE TABLE business_logic_template_runs (
    run_id                    TEXT    NOT NULL,
    project_id                TEXT    NOT NULL,
    template_id               TEXT    NOT NULL,
    template_version          TEXT    NOT NULL,
    generated_count           INTEGER NOT NULL DEFAULT 0,
    skipped_count             INTEGER NOT NULL DEFAULT 0,
    skip_reasons_json         TEXT    NOT NULL DEFAULT '[]',
    dry_run                   INTEGER NOT NULL DEFAULT 0,
    created_at                INTEGER NOT NULL,
    updated_at                INTEGER NOT NULL,
    PRIMARY KEY (run_id, template_id, template_version),
    FOREIGN KEY (run_id)     REFERENCES runs(id)     ON DELETE CASCADE,
    FOREIGN KEY (project_id) REFERENCES projects(id) ON DELETE CASCADE
);

CREATE INDEX idx_business_logic_template_runs_run
    ON business_logic_template_runs(run_id);
CREATE INDEX idx_business_logic_template_runs_template
    ON business_logic_template_runs(template_id, template_version);

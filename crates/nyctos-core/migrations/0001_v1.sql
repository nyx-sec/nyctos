-- v1 schema for nyctos. This is the full forward-looking surface that
-- every later phase (payloads, chains, candidate findings, agent traces,
-- repro bundles, schedules, webhooks, feedback) needs to land against.
-- Migrations after v1 are append-only and field-additive only.

-- Singleton metadata row. agent_version is the binary that wrote it most
-- recently; created_at is the millisecond timestamp of the first install.
CREATE TABLE meta (
    id              INTEGER PRIMARY KEY CHECK (id = 1),
    schema_version  INTEGER NOT NULL,
    created_at      INTEGER NOT NULL,
    agent_version   TEXT    NOT NULL
);

CREATE TABLE projects (
    id                TEXT    PRIMARY KEY,
    name              TEXT    NOT NULL UNIQUE,
    description       TEXT,
    target_base_url   TEXT,
    env_config_json   TEXT,
    created_at        INTEGER NOT NULL,
    updated_at        INTEGER NOT NULL
);

CREATE INDEX idx_projects_name ON projects(name);

CREATE TABLE repos (
    name                 TEXT    PRIMARY KEY,
    project_id           TEXT    NOT NULL,
    source_kind          TEXT    NOT NULL,
    source_url_or_path   TEXT    NOT NULL,
    branch               TEXT,
    auth_ref             TEXT,
    i_own_this           INTEGER NOT NULL DEFAULT 0,
    last_scan_run_id     TEXT,
    created_at           INTEGER NOT NULL,
    updated_at           INTEGER NOT NULL,
    FOREIGN KEY (project_id) REFERENCES projects(id) ON DELETE CASCADE
);

CREATE TABLE runs (
    id                          TEXT    PRIMARY KEY,
    started_at                  INTEGER NOT NULL,
    finished_at                 INTEGER,
    status                      TEXT    NOT NULL,
    triggered_by                TEXT    NOT NULL,
    git_ref                     TEXT,
    parent_run_id               TEXT,
    wall_clock_ms               INTEGER,
    total_ai_spend_usd_micros   INTEGER NOT NULL DEFAULT 0,
    FOREIGN KEY (parent_run_id) REFERENCES runs(id) ON DELETE SET NULL
);

CREATE TABLE chains (
    id                   TEXT    PRIMARY KEY,
    run_id               TEXT    NOT NULL,
    cross_repo           INTEGER NOT NULL DEFAULT 0,
    member_ids           TEXT    NOT NULL,
    rationale_blob       TEXT,
    attack_provenance    TEXT,
    prompt_version       TEXT,
    FOREIGN KEY (run_id) REFERENCES runs(id) ON DELETE CASCADE
);

CREATE TABLE findings (
    id                     TEXT    PRIMARY KEY,
    run_id                 TEXT    NOT NULL,
    repo                   TEXT    NOT NULL,
    path                   TEXT    NOT NULL,
    line                   INTEGER,
    cap                    TEXT    NOT NULL,
    rule                   TEXT    NOT NULL,
    severity               TEXT    NOT NULL,
    status                 TEXT    NOT NULL,
    finding_origin         TEXT    NOT NULL,
    first_seen             INTEGER NOT NULL,
    last_seen              INTEGER NOT NULL,
    superseded_by          TEXT,
    triage_state           TEXT    NOT NULL DEFAULT 'Open',
    triage_assigned_to     TEXT,
    verdict_blob           TEXT,
    repro_path             TEXT,
    attack_provenance      TEXT,
    prompt_version         TEXT,
    chain_id               TEXT,
    FOREIGN KEY (run_id)        REFERENCES runs(id)     ON DELETE CASCADE,
    FOREIGN KEY (superseded_by) REFERENCES findings(id) ON DELETE SET NULL,
    FOREIGN KEY (chain_id)      REFERENCES chains(id)   ON DELETE SET NULL
);

CREATE TABLE payloads (
    id                  TEXT    PRIMARY KEY,
    finding_id          TEXT    NOT NULL,
    cap                 TEXT    NOT NULL,
    lang                TEXT    NOT NULL,
    vuln_bytes          BLOB    NOT NULL,
    benign_bytes        BLOB,
    oracle_blob         TEXT,
    attack_provenance   TEXT,
    prompt_version      TEXT,
    created_at          INTEGER NOT NULL,
    FOREIGN KEY (finding_id) REFERENCES findings(id) ON DELETE CASCADE
);

CREATE TABLE candidate_findings (
    id                       TEXT    PRIMARY KEY,
    run_id                   TEXT    NOT NULL,
    repo                     TEXT    NOT NULL,
    path                     TEXT    NOT NULL,
    line                     INTEGER,
    cap                      TEXT    NOT NULL,
    rule_hint                TEXT,
    rationale                TEXT,
    suggested_payload_hint   TEXT,
    status                   TEXT    NOT NULL DEFAULT 'Pending',
    prompt_version           TEXT,
    FOREIGN KEY (run_id) REFERENCES runs(id) ON DELETE CASCADE
);

CREATE TABLE agent_traces (
    id                       TEXT    PRIMARY KEY,
    finding_id               TEXT,
    task_kind                TEXT    NOT NULL,
    runtime_name             TEXT    NOT NULL,
    model                    TEXT    NOT NULL,
    prompt_version           TEXT,
    conversation_jsonl_path  TEXT,
    tokens_in                INTEGER NOT NULL DEFAULT 0,
    tokens_out               INTEGER NOT NULL DEFAULT 0,
    cost_usd_micros          INTEGER NOT NULL DEFAULT 0,
    cache_hits               INTEGER NOT NULL DEFAULT 0,
    cache_misses             INTEGER NOT NULL DEFAULT 0,
    duration_ms              INTEGER,
    started_at               INTEGER NOT NULL,
    finished_at              INTEGER,
    FOREIGN KEY (finding_id) REFERENCES findings(id) ON DELETE SET NULL
);

CREATE TABLE budgets (
    run_id            TEXT    NOT NULL,
    kind              TEXT    NOT NULL,
    cap_usd_micros    INTEGER NOT NULL,
    spent_usd_micros  INTEGER NOT NULL DEFAULT 0,
    halted            INTEGER NOT NULL DEFAULT 0,
    halted_at         INTEGER,
    PRIMARY KEY (run_id, kind),
    FOREIGN KEY (run_id) REFERENCES runs(id) ON DELETE CASCADE
);

CREATE TABLE repro_bundles (
    id                   TEXT    PRIMARY KEY,
    finding_id           TEXT    NOT NULL,
    path                 TEXT    NOT NULL,
    sha256               TEXT    NOT NULL,
    created_at           INTEGER NOT NULL,
    last_replay_at       INTEGER,
    last_replay_status   TEXT,
    FOREIGN KEY (finding_id) REFERENCES findings(id) ON DELETE CASCADE
);

CREATE TABLE schedules (
    id              TEXT    PRIMARY KEY,
    repo            TEXT,
    cron_expr       TEXT    NOT NULL,
    enabled         INTEGER NOT NULL DEFAULT 1,
    last_fired_at   INTEGER,
    FOREIGN KEY (repo) REFERENCES repos(name) ON DELETE CASCADE
);

CREATE TABLE webhooks (
    id               TEXT    PRIMARY KEY,
    repo             TEXT    NOT NULL,
    hmac_secret_ref  TEXT    NOT NULL,
    branch_filter    TEXT,
    enabled          INTEGER NOT NULL DEFAULT 1,
    FOREIGN KEY (repo) REFERENCES repos(name) ON DELETE CASCADE
);

CREATE TABLE feedback (
    id                 INTEGER PRIMARY KEY AUTOINCREMENT,
    finding_id         TEXT    NOT NULL,
    operator_verdict   TEXT    NOT NULL,
    notes              TEXT,
    created_at         INTEGER NOT NULL,
    FOREIGN KEY (finding_id) REFERENCES findings(id) ON DELETE CASCADE
);

-- FK indexes + UI-filter indexes.
CREATE INDEX idx_repos_last_scan_run_id        ON repos(last_scan_run_id);
CREATE INDEX idx_repos_project                 ON repos(project_id);

CREATE INDEX idx_runs_parent_run_id            ON runs(parent_run_id);
CREATE INDEX idx_runs_status_started_at        ON runs(status, started_at);
CREATE INDEX idx_runs_started_at               ON runs(started_at);

CREATE INDEX idx_findings_run_id               ON findings(run_id);
CREATE INDEX idx_findings_superseded_by        ON findings(superseded_by);
CREATE INDEX idx_findings_chain_id             ON findings(chain_id);
CREATE INDEX idx_findings_repo_cap_status_origin
    ON findings(repo, cap, status, finding_origin);
CREATE INDEX idx_findings_last_seen            ON findings(last_seen);
CREATE INDEX idx_findings_triage_state         ON findings(triage_state);
CREATE INDEX idx_findings_severity             ON findings(severity);

CREATE INDEX idx_chains_run_id                 ON chains(run_id);

CREATE INDEX idx_payloads_finding_id           ON payloads(finding_id);
CREATE INDEX idx_payloads_cap                  ON payloads(cap);

CREATE INDEX idx_candidate_findings_run_id     ON candidate_findings(run_id);
CREATE INDEX idx_candidate_findings_status     ON candidate_findings(status);
CREATE INDEX idx_candidate_findings_repo_cap   ON candidate_findings(repo, cap);

CREATE INDEX idx_agent_traces_finding_id       ON agent_traces(finding_id);
CREATE INDEX idx_agent_traces_task_kind        ON agent_traces(task_kind);
CREATE INDEX idx_agent_traces_started_at       ON agent_traces(started_at);

CREATE INDEX idx_budgets_run_id                ON budgets(run_id);

CREATE INDEX idx_repro_bundles_finding_id      ON repro_bundles(finding_id);

CREATE INDEX idx_schedules_repo                ON schedules(repo);
CREATE INDEX idx_schedules_enabled             ON schedules(enabled);

CREATE INDEX idx_webhooks_repo                 ON webhooks(repo);
CREATE INDEX idx_webhooks_enabled              ON webhooks(enabled);

CREATE INDEX idx_feedback_finding_id           ON feedback(finding_id);

INSERT INTO meta (id, schema_version, created_at, agent_version)
VALUES (1, 1, 0, '0.0.0')
ON CONFLICT(id) DO NOTHING;

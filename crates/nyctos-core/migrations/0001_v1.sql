-- Baseline schema for nyctos.
--
-- The project has not shipped with persisted user databases yet, so the
-- early local migration history has been squashed into this single
-- baseline. Future schema changes after an external release should add
-- new numbered migrations instead of editing this file.

CREATE TABLE meta (
    id              INTEGER PRIMARY KEY CHECK (id = 1),
    schema_version  INTEGER NOT NULL,
    created_at      INTEGER NOT NULL,
    agent_version   TEXT    NOT NULL
);

CREATE TABLE projects (
    id                    TEXT    PRIMARY KEY,
    name                  TEXT    NOT NULL UNIQUE,
    description           TEXT,
    target_base_url       TEXT,
    env_config_json       TEXT,
    runtime_profile_json  TEXT,
    created_at            INTEGER NOT NULL,
    updated_at            INTEGER NOT NULL
);

CREATE TABLE repos (
    id                   TEXT    PRIMARY KEY,
    name                 TEXT    NOT NULL,
    project_id           TEXT    NOT NULL,
    source_kind          TEXT    NOT NULL,
    source_url_or_path   TEXT    NOT NULL,
    branch               TEXT,
    auth_ref             TEXT,
    i_own_this           INTEGER NOT NULL DEFAULT 0,
    last_scan_run_id     TEXT,
    created_at           INTEGER NOT NULL,
    updated_at           INTEGER NOT NULL,
    UNIQUE(project_id, name),
    FOREIGN KEY (project_id) REFERENCES projects(id) ON DELETE CASCADE
);

CREATE TABLE runs (
    id                          TEXT    PRIMARY KEY,
    project_id                  TEXT,
    kind                        TEXT    NOT NULL DEFAULT 'Scan',
    started_at                  INTEGER NOT NULL,
    finished_at                 INTEGER,
    status                      TEXT    NOT NULL,
    triggered_by                TEXT    NOT NULL,
    git_ref                     TEXT,
    parent_run_id               TEXT,
    wall_clock_ms               INTEGER,
    total_ai_spend_usd_micros   INTEGER NOT NULL DEFAULT 0,
    FOREIGN KEY (project_id)    REFERENCES projects(id) ON DELETE SET NULL,
    FOREIGN KEY (parent_run_id) REFERENCES runs(id)    ON DELETE SET NULL
);

CREATE TABLE harness_specs (
    id                  TEXT    PRIMARY KEY,
    cap                 TEXT    NOT NULL,
    lang                TEXT    NOT NULL,
    spec_blob           TEXT    NOT NULL,
    attack_provenance   TEXT,
    prompt_version      TEXT,
    created_at          INTEGER NOT NULL
);

CREATE TABLE chains (
    id                       TEXT    PRIMARY KEY,
    run_id                   TEXT    NOT NULL,
    cross_repo               INTEGER NOT NULL DEFAULT 0,
    member_ids               TEXT    NOT NULL,
    rationale_blob           TEXT,
    attack_provenance        TEXT,
    prompt_version           TEXT,
    status                   TEXT    NOT NULL DEFAULT 'Proposed',
    verification_attempt_id  TEXT,
    evidence_blob            TEXT,
    severity                 TEXT,
    FOREIGN KEY (run_id)                  REFERENCES runs(id)                  ON DELETE CASCADE,
    FOREIGN KEY (verification_attempt_id) REFERENCES verification_attempts(id) ON DELETE SET NULL
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
    spec_id                TEXT,
    FOREIGN KEY (run_id)        REFERENCES runs(id)          ON DELETE CASCADE,
    FOREIGN KEY (superseded_by) REFERENCES findings(id)      ON DELETE SET NULL,
    FOREIGN KEY (chain_id)      REFERENCES chains(id)        ON DELETE SET NULL,
    FOREIGN KEY (spec_id)       REFERENCES harness_specs(id) ON DELETE SET NULL
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
    trace_id                 TEXT,
    FOREIGN KEY (run_id)   REFERENCES runs(id)         ON DELETE CASCADE,
    FOREIGN KEY (trace_id) REFERENCES agent_traces(id) ON DELETE SET NULL
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
    verifier_blob            TEXT,
    run_id                   TEXT,
    project_id               TEXT,
    candidate_id             TEXT,
    vulnerability_id         TEXT,
    phase                    TEXT,
    FOREIGN KEY (finding_id)       REFERENCES findings(id)                 ON DELETE SET NULL,
    FOREIGN KEY (run_id)           REFERENCES runs(id)                     ON DELETE SET NULL,
    FOREIGN KEY (project_id)       REFERENCES projects(id)                 ON DELETE SET NULL,
    FOREIGN KEY (candidate_id)     REFERENCES pentest_candidates(id)       ON DELETE SET NULL,
    FOREIGN KEY (vulnerability_id) REFERENCES verified_vulnerabilities(id) ON DELETE SET NULL
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
    last_fired_at   INTEGER
);

CREATE TABLE webhooks (
    id               TEXT    PRIMARY KEY,
    repo             TEXT    NOT NULL,
    hmac_secret_ref  TEXT    NOT NULL,
    branch_filter    TEXT,
    enabled          INTEGER NOT NULL DEFAULT 1
);

CREATE TABLE feedback (
    id                 INTEGER PRIMARY KEY AUTOINCREMENT,
    finding_id         TEXT    NOT NULL,
    operator_verdict   TEXT    NOT NULL,
    notes              TEXT,
    created_at         INTEGER NOT NULL,
    FOREIGN KEY (finding_id) REFERENCES findings(id) ON DELETE CASCADE
);

CREATE TABLE run_findings (
    run_id      TEXT NOT NULL,
    finding_id  TEXT NOT NULL,
    status      TEXT NOT NULL,
    PRIMARY KEY (run_id, finding_id),
    FOREIGN KEY (run_id)     REFERENCES runs(id)     ON DELETE CASCADE,
    FOREIGN KEY (finding_id) REFERENCES findings(id) ON DELETE CASCADE
);

CREATE TABLE run_repo_outcomes (
    run_id      TEXT    NOT NULL,
    repo        TEXT    NOT NULL,
    outcome     TEXT    NOT NULL,
    reason      TEXT,
    elapsed_ms  INTEGER NOT NULL,
    PRIMARY KEY (run_id, repo),
    FOREIGN KEY (run_id) REFERENCES runs(id) ON DELETE CASCADE
);

CREATE TABLE project_launch_profiles (
    id                    TEXT    PRIMARY KEY,
    project_id            TEXT    NOT NULL,
    name                  TEXT    NOT NULL DEFAULT 'local dev',
    mode                  TEXT    NOT NULL DEFAULT 'custom-commands',
    build_steps_json      TEXT    NOT NULL DEFAULT '[]',
    start_steps_json      TEXT    NOT NULL DEFAULT '[]',
    stop_steps_json       TEXT    NOT NULL DEFAULT '[]',
    health_checks_json    TEXT    NOT NULL DEFAULT '[]',
    target_urls_json      TEXT    NOT NULL DEFAULT '[]',
    env_refs_json         TEXT    NOT NULL DEFAULT '[]',
    working_dirs_json     TEXT    NOT NULL DEFAULT '[]',
    readiness             TEXT    NOT NULL DEFAULT 'Incomplete',
    created_at            INTEGER NOT NULL,
    updated_at            INTEGER NOT NULL,
    is_default            INTEGER NOT NULL DEFAULT 0,
    FOREIGN KEY (project_id) REFERENCES projects(id) ON DELETE CASCADE
);

CREATE TABLE environment_runs (
    id                  TEXT    PRIMARY KEY,
    run_id              TEXT    NOT NULL,
    project_id          TEXT    NOT NULL,
    profile_id          TEXT    NOT NULL,
    status              TEXT    NOT NULL,
    started_at          INTEGER,
    ready_at            INTEGER,
    stopped_at          INTEGER,
    target_urls_json    TEXT    NOT NULL DEFAULT '[]',
    health_blob         TEXT,
    logs_dir            TEXT,
    teardown_blob       TEXT,
    FOREIGN KEY (run_id)     REFERENCES runs(id)                    ON DELETE CASCADE,
    FOREIGN KEY (project_id) REFERENCES projects(id)                ON DELETE CASCADE,
    FOREIGN KEY (profile_id) REFERENCES project_launch_profiles(id) ON DELETE CASCADE
);

CREATE TABLE nyx_signals (
    id                    TEXT    PRIMARY KEY,
    run_id                TEXT    NOT NULL,
    project_id            TEXT    NOT NULL,
    repo_id               TEXT    NOT NULL,
    repo                  TEXT    NOT NULL,
    path                  TEXT    NOT NULL,
    line                  INTEGER,
    cap                   TEXT    NOT NULL,
    rule                  TEXT    NOT NULL,
    severity              TEXT    NOT NULL,
    message               TEXT,
    evidence_blob         TEXT,
    signal_kind           TEXT    NOT NULL,
    meaningful            INTEGER NOT NULL DEFAULT 0,
    suppressed_reason     TEXT,
    agent_candidate_id    TEXT,
    created_at            INTEGER NOT NULL,
    FOREIGN KEY (run_id)     REFERENCES runs(id)     ON DELETE CASCADE,
    FOREIGN KEY (project_id) REFERENCES projects(id) ON DELETE CASCADE,
    FOREIGN KEY (repo_id)    REFERENCES repos(id)    ON DELETE CASCADE
);

CREATE TABLE pentest_candidates (
    id                         TEXT    PRIMARY KEY,
    run_id                     TEXT    NOT NULL,
    project_id                 TEXT    NOT NULL,
    source                     TEXT    NOT NULL,
    source_ids_json            TEXT    NOT NULL DEFAULT '[]',
    title                      TEXT    NOT NULL,
    vuln_class                 TEXT    NOT NULL,
    severity_guess             TEXT    NOT NULL,
    affected_components_json   TEXT    NOT NULL DEFAULT '[]',
    hypothesis                 TEXT    NOT NULL,
    test_plan                  TEXT    NOT NULL,
    status                     TEXT    NOT NULL,
    rejection_reason           TEXT,
    confidence                 REAL    NOT NULL DEFAULT 0.0,
    trace_id                   TEXT,
    created_at                 INTEGER NOT NULL,
    updated_at                 INTEGER NOT NULL,
    FOREIGN KEY (run_id)     REFERENCES runs(id)         ON DELETE CASCADE,
    FOREIGN KEY (project_id) REFERENCES projects(id)     ON DELETE CASCADE,
    FOREIGN KEY (trace_id)   REFERENCES agent_traces(id) ON DELETE SET NULL
);

CREATE TABLE verification_attempts (
    id                         TEXT    PRIMARY KEY,
    run_id                     TEXT    NOT NULL,
    project_id                 TEXT    NOT NULL,
    environment_run_id         TEXT    NOT NULL,
    candidate_id               TEXT,
    chain_id                   TEXT,
    method                     TEXT    NOT NULL,
    status                     TEXT    NOT NULL,
    started_at                 INTEGER NOT NULL,
    finished_at                INTEGER,
    duration_ms                INTEGER,
    request_blob               TEXT,
    response_blob              TEXT,
    oracle_blob                TEXT,
    artifact_paths_json        TEXT    NOT NULL DEFAULT '[]',
    error                      TEXT,
    replay_stable              INTEGER,
    FOREIGN KEY (run_id)             REFERENCES runs(id)                ON DELETE CASCADE,
    FOREIGN KEY (project_id)         REFERENCES projects(id)            ON DELETE CASCADE,
    FOREIGN KEY (environment_run_id) REFERENCES environment_runs(id)    ON DELETE CASCADE,
    FOREIGN KEY (candidate_id)       REFERENCES pentest_candidates(id)  ON DELETE SET NULL,
    FOREIGN KEY (chain_id)           REFERENCES chains(id)              ON DELETE SET NULL
);

CREATE TABLE verified_vulnerabilities (
    id                                TEXT    PRIMARY KEY,
    run_id                            TEXT    NOT NULL,
    project_id                        TEXT    NOT NULL,
    title                             TEXT    NOT NULL,
    severity                          TEXT    NOT NULL,
    confidence                        REAL    NOT NULL,
    vuln_class                        TEXT    NOT NULL,
    affected_components_json          TEXT    NOT NULL DEFAULT '[]',
    business_impact                   TEXT    NOT NULL,
    evidence_summary                  TEXT    NOT NULL,
    repro_steps                       TEXT    NOT NULL,
    remediation                       TEXT    NOT NULL,
    source_candidate_ids_json         TEXT    NOT NULL DEFAULT '[]',
    source_signal_ids_json            TEXT    NOT NULL DEFAULT '[]',
    verification_attempt_ids_json     TEXT    NOT NULL DEFAULT '[]',
    chain_id                          TEXT,
    status                            TEXT    NOT NULL DEFAULT 'Open',
    first_seen                        INTEGER NOT NULL,
    last_seen                         INTEGER NOT NULL,
    FOREIGN KEY (run_id)     REFERENCES runs(id)     ON DELETE CASCADE,
    FOREIGN KEY (project_id) REFERENCES projects(id) ON DELETE CASCADE,
    FOREIGN KEY (chain_id)   REFERENCES chains(id)   ON DELETE SET NULL
);

CREATE TABLE route_models (
    id            TEXT    PRIMARY KEY,
    run_id        TEXT    NOT NULL,
    project_id    TEXT    NOT NULL,
    model_blob    TEXT    NOT NULL,
    created_at    INTEGER NOT NULL,
    FOREIGN KEY (run_id)     REFERENCES runs(id)     ON DELETE CASCADE,
    FOREIGN KEY (project_id) REFERENCES projects(id) ON DELETE CASCADE
);

CREATE TABLE run_phase_events (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id        TEXT    NOT NULL,
    project_id    TEXT    NOT NULL,
    phase         TEXT    NOT NULL,
    status        TEXT    NOT NULL,
    message       TEXT,
    created_at    INTEGER NOT NULL,
    FOREIGN KEY (run_id)     REFERENCES runs(id)     ON DELETE CASCADE,
    FOREIGN KEY (project_id) REFERENCES projects(id) ON DELETE CASCADE
);

CREATE INDEX idx_projects_name                  ON projects(name);

CREATE INDEX idx_repos_last_scan_run_id         ON repos(last_scan_run_id);
CREATE INDEX idx_repos_project                  ON repos(project_id);
CREATE UNIQUE INDEX idx_repos_project_name      ON repos(project_id, name);
CREATE INDEX idx_repos_name                     ON repos(name);

CREATE INDEX idx_runs_parent_run_id             ON runs(parent_run_id);
CREATE INDEX idx_runs_status_started_at         ON runs(status, started_at);
CREATE INDEX idx_runs_started_at                ON runs(started_at);
CREATE INDEX idx_runs_project_id                ON runs(project_id);
CREATE INDEX idx_runs_kind_started_at           ON runs(kind, started_at);

CREATE INDEX idx_harness_specs_cap              ON harness_specs(cap);

CREATE INDEX idx_findings_run_id                ON findings(run_id);
CREATE INDEX idx_findings_superseded_by         ON findings(superseded_by);
CREATE INDEX idx_findings_chain_id              ON findings(chain_id);
CREATE INDEX idx_findings_spec_id               ON findings(spec_id);
CREATE INDEX idx_findings_repo_cap_status_origin
    ON findings(repo, cap, status, finding_origin);
CREATE INDEX idx_findings_last_seen             ON findings(last_seen);
CREATE INDEX idx_findings_triage_state          ON findings(triage_state);
CREATE INDEX idx_findings_severity              ON findings(severity);

CREATE INDEX idx_chains_run_id                  ON chains(run_id);
CREATE INDEX idx_chains_status                  ON chains(status);

CREATE INDEX idx_payloads_finding_id            ON payloads(finding_id);
CREATE INDEX idx_payloads_cap                   ON payloads(cap);

CREATE INDEX idx_candidate_findings_run_id      ON candidate_findings(run_id);
CREATE INDEX idx_candidate_findings_status      ON candidate_findings(status);
CREATE INDEX idx_candidate_findings_repo_cap    ON candidate_findings(repo, cap);
CREATE INDEX idx_candidate_findings_trace_id    ON candidate_findings(trace_id);

CREATE INDEX idx_agent_traces_finding_id        ON agent_traces(finding_id);
CREATE INDEX idx_agent_traces_task_kind         ON agent_traces(task_kind);
CREATE INDEX idx_agent_traces_started_at        ON agent_traces(started_at);
CREATE INDEX idx_agent_traces_run_id            ON agent_traces(run_id);
CREATE INDEX idx_agent_traces_project_id        ON agent_traces(project_id);
CREATE INDEX idx_agent_traces_candidate_id      ON agent_traces(candidate_id);
CREATE INDEX idx_agent_traces_vulnerability_id  ON agent_traces(vulnerability_id);
CREATE INDEX idx_agent_traces_phase             ON agent_traces(phase);

CREATE INDEX idx_budgets_run_id                 ON budgets(run_id);

CREATE INDEX idx_repro_bundles_finding_id       ON repro_bundles(finding_id);

CREATE INDEX idx_schedules_repo                 ON schedules(repo);
CREATE INDEX idx_schedules_enabled              ON schedules(enabled);

CREATE INDEX idx_webhooks_repo                  ON webhooks(repo);
CREATE INDEX idx_webhooks_enabled               ON webhooks(enabled);

CREATE INDEX idx_feedback_finding_id            ON feedback(finding_id);

CREATE INDEX idx_run_findings_run_id            ON run_findings(run_id);
CREATE INDEX idx_run_findings_finding_id        ON run_findings(finding_id);

CREATE INDEX idx_run_repo_outcomes_run_id       ON run_repo_outcomes(run_id);
CREATE INDEX idx_run_repo_outcomes_outcome      ON run_repo_outcomes(outcome);

CREATE UNIQUE INDEX idx_project_launch_profiles_default
    ON project_launch_profiles(project_id)
    WHERE is_default = 1;
CREATE INDEX idx_project_launch_profiles_project ON project_launch_profiles(project_id);

CREATE INDEX idx_environment_runs_run_id        ON environment_runs(run_id);
CREATE INDEX idx_environment_runs_project_id    ON environment_runs(project_id);
CREATE INDEX idx_environment_runs_status        ON environment_runs(status);

CREATE INDEX idx_nyx_signals_run_id             ON nyx_signals(run_id);
CREATE INDEX idx_nyx_signals_project_id         ON nyx_signals(project_id);
CREATE INDEX idx_nyx_signals_repo_id            ON nyx_signals(repo_id);
CREATE INDEX idx_nyx_signals_meaningful         ON nyx_signals(meaningful);
CREATE INDEX idx_nyx_signals_severity           ON nyx_signals(severity);

CREATE INDEX idx_pentest_candidates_run_id      ON pentest_candidates(run_id);
CREATE INDEX idx_pentest_candidates_project_id  ON pentest_candidates(project_id);
CREATE INDEX idx_pentest_candidates_status      ON pentest_candidates(status);
CREATE INDEX idx_pentest_candidates_source      ON pentest_candidates(source);

CREATE INDEX idx_verification_attempts_run_id       ON verification_attempts(run_id);
CREATE INDEX idx_verification_attempts_candidate_id ON verification_attempts(candidate_id);
CREATE INDEX idx_verification_attempts_status       ON verification_attempts(status);

CREATE INDEX idx_verified_vulnerabilities_run_id     ON verified_vulnerabilities(run_id);
CREATE INDEX idx_verified_vulnerabilities_project_id ON verified_vulnerabilities(project_id);
CREATE INDEX idx_verified_vulnerabilities_status     ON verified_vulnerabilities(status);
CREATE INDEX idx_verified_vulnerabilities_severity   ON verified_vulnerabilities(severity);

CREATE INDEX idx_route_models_run_id             ON route_models(run_id);
CREATE INDEX idx_route_models_project_id         ON route_models(project_id);

CREATE INDEX idx_run_phase_events_run_id        ON run_phase_events(run_id);
CREATE INDEX idx_run_phase_events_phase         ON run_phase_events(phase);

INSERT INTO meta (id, schema_version, created_at, agent_version)
VALUES (1, 1, 0, '0.0.0')
ON CONFLICT(id) DO NOTHING;

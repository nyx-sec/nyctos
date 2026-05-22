-- no-transaction
-- v8 product reset schema.
--
-- This migration introduces project-scoped repo identity, project-scoped
-- pentest runs, normalized launch profiles, environment-run lifecycle
-- records, raw Nyx signals, pentest candidates, verification attempts,
-- and verified vulnerabilities. Legacy findings/chains remain readable
-- for one compatibility window.

PRAGMA foreign_keys = OFF;

ALTER TABLE runs ADD COLUMN project_id TEXT REFERENCES projects(id) ON DELETE SET NULL;
ALTER TABLE runs ADD COLUMN kind TEXT NOT NULL DEFAULT 'Scan';

UPDATE runs
   SET project_id = (
       SELECT repos.project_id
         FROM findings
         JOIN repos ON repos.name = findings.repo
        WHERE findings.run_id = runs.id
        LIMIT 1
   )
 WHERE project_id IS NULL;

UPDATE runs
   SET project_id = (
       SELECT repos.project_id
         FROM run_repo_outcomes
         JOIN repos ON repos.name = run_repo_outcomes.repo
        WHERE run_repo_outcomes.run_id = runs.id
        LIMIT 1
   )
 WHERE project_id IS NULL;

CREATE INDEX idx_runs_project_id ON runs(project_id);
CREATE INDEX idx_runs_kind_started_at ON runs(kind, started_at);

ALTER TABLE schedules RENAME TO schedules_old;
CREATE TABLE schedules (
    id              TEXT    PRIMARY KEY,
    repo            TEXT,
    cron_expr       TEXT    NOT NULL,
    enabled         INTEGER NOT NULL DEFAULT 1,
    last_fired_at   INTEGER
);
INSERT INTO schedules (id, repo, cron_expr, enabled, last_fired_at)
SELECT id, repo, cron_expr, enabled, last_fired_at FROM schedules_old;
DROP TABLE schedules_old;

ALTER TABLE webhooks RENAME TO webhooks_old;
CREATE TABLE webhooks (
    id               TEXT    PRIMARY KEY,
    repo             TEXT    NOT NULL,
    hmac_secret_ref  TEXT    NOT NULL,
    branch_filter    TEXT,
    enabled          INTEGER NOT NULL DEFAULT 1
);
INSERT INTO webhooks (id, repo, hmac_secret_ref, branch_filter, enabled)
SELECT id, repo, hmac_secret_ref, branch_filter, enabled FROM webhooks_old;
DROP TABLE webhooks_old;

CREATE TABLE repos_v2 (
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

INSERT INTO repos_v2 (
    id, name, project_id, source_kind, source_url_or_path, branch, auth_ref,
    i_own_this, last_scan_run_id, created_at, updated_at
)
SELECT
    'repo-' ||
        replace(replace(replace(project_id, ' ', '-'), '/', '-'), ':', '-') || '-' ||
        replace(replace(replace(name, ' ', '-'), '/', '-'), ':', '-') || '-' ||
        printf('%x', created_at),
    name,
    project_id,
    source_kind,
    source_url_or_path,
    branch,
    auth_ref,
    i_own_this,
    last_scan_run_id,
    created_at,
    updated_at
FROM repos;

DROP TABLE repos;
ALTER TABLE repos_v2 RENAME TO repos;

CREATE INDEX idx_repos_last_scan_run_id ON repos(last_scan_run_id);
CREATE INDEX idx_repos_project ON repos(project_id);
CREATE UNIQUE INDEX idx_repos_project_name ON repos(project_id, name);
CREATE INDEX idx_repos_name ON repos(name);

CREATE INDEX idx_schedules_repo ON schedules(repo);
CREATE INDEX idx_schedules_enabled ON schedules(enabled);
CREATE INDEX idx_webhooks_repo ON webhooks(repo);
CREATE INDEX idx_webhooks_enabled ON webhooks(enabled);

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

CREATE UNIQUE INDEX idx_project_launch_profiles_default
    ON project_launch_profiles(project_id)
    WHERE is_default = 1;
CREATE INDEX idx_project_launch_profiles_project ON project_launch_profiles(project_id);

INSERT INTO project_launch_profiles (
    id, project_id, name, mode, build_steps_json, start_steps_json, stop_steps_json,
    health_checks_json, target_urls_json, env_refs_json, working_dirs_json,
    readiness, created_at, updated_at, is_default
)
SELECT
    'lp-' || projects.id || '-default',
    projects.id,
    'local dev',
    'custom-commands',
    CASE
        WHEN runtime_profile_json IS NOT NULL AND json_valid(runtime_profile_json)
        THEN COALESCE(json_extract(runtime_profile_json, '$.build_commands'), '[]')
        ELSE '[]'
    END,
    CASE
        WHEN runtime_profile_json IS NOT NULL AND json_valid(runtime_profile_json)
        THEN COALESCE(json_extract(runtime_profile_json, '$.start_commands'), '[]')
        ELSE '[]'
    END,
    '[]',
    CASE
        WHEN runtime_profile_json IS NOT NULL
             AND json_valid(runtime_profile_json)
             AND json_extract(runtime_profile_json, '$.health_check_url') IS NOT NULL
        THEN json_array(json_object(
            'kind', 'http',
            'url', json_extract(runtime_profile_json, '$.health_check_url')
        ))
        WHEN runtime_profile_json IS NOT NULL
             AND json_valid(runtime_profile_json)
             AND json_extract(runtime_profile_json, '$.health_check_command.command') IS NOT NULL
        THEN json_array(json_object(
            'kind', 'command',
            'command', json_extract(runtime_profile_json, '$.health_check_command')
        ))
        ELSE '[]'
    END,
    CASE
        WHEN runtime_profile_json IS NOT NULL
             AND json_valid(runtime_profile_json)
             AND json_extract(runtime_profile_json, '$.target_base_url') IS NOT NULL
        THEN json_array(json_extract(runtime_profile_json, '$.target_base_url'))
        WHEN target_base_url IS NOT NULL
        THEN json_array(target_base_url)
        ELSE '[]'
    END,
    CASE
        WHEN runtime_profile_json IS NOT NULL
             AND json_valid(runtime_profile_json)
             AND json_extract(runtime_profile_json, '$.env_file') IS NOT NULL
        THEN json_array(json_object(
            'kind', 'env-file',
            'value', json_extract(runtime_profile_json, '$.env_file'),
            'secret', false
        ))
        WHEN env_config_json IS NOT NULL
        THEN json_array(json_object(
            'kind', 'legacy-project-env-config',
            'value', 'projects.env_config_json',
            'secret', true
        ))
        ELSE '[]'
    END,
    '[]',
    CASE
        WHEN runtime_profile_json IS NOT NULL
             AND json_valid(runtime_profile_json)
             AND json_array_length(COALESCE(json_extract(runtime_profile_json, '$.start_commands'), '[]')) > 0
        THEN 'Ready'
        ELSE 'Incomplete'
    END,
    projects.created_at,
    projects.updated_at,
    1
FROM projects
WHERE NOT EXISTS (
    SELECT 1 FROM project_launch_profiles p
    WHERE p.project_id = projects.id AND p.is_default = 1
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
    FOREIGN KEY (run_id) REFERENCES runs(id) ON DELETE CASCADE,
    FOREIGN KEY (project_id) REFERENCES projects(id) ON DELETE CASCADE,
    FOREIGN KEY (profile_id) REFERENCES project_launch_profiles(id) ON DELETE CASCADE
);
CREATE INDEX idx_environment_runs_run_id ON environment_runs(run_id);
CREATE INDEX idx_environment_runs_project_id ON environment_runs(project_id);
CREATE INDEX idx_environment_runs_status ON environment_runs(status);

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
    FOREIGN KEY (run_id) REFERENCES runs(id) ON DELETE CASCADE,
    FOREIGN KEY (project_id) REFERENCES projects(id) ON DELETE CASCADE,
    FOREIGN KEY (repo_id) REFERENCES repos(id) ON DELETE CASCADE
);
CREATE INDEX idx_nyx_signals_run_id ON nyx_signals(run_id);
CREATE INDEX idx_nyx_signals_project_id ON nyx_signals(project_id);
CREATE INDEX idx_nyx_signals_repo_id ON nyx_signals(repo_id);
CREATE INDEX idx_nyx_signals_meaningful ON nyx_signals(meaningful);
CREATE INDEX idx_nyx_signals_severity ON nyx_signals(severity);

INSERT OR IGNORE INTO nyx_signals (
    id, run_id, project_id, repo_id, repo, path, line, cap, rule, severity,
    message, evidence_blob, signal_kind, meaningful, suppressed_reason,
    agent_candidate_id, created_at
)
SELECT
    'sig-' || COALESCE(runs.project_id, repos.project_id) || '-' || repos.id || '-' || findings.id,
    findings.run_id,
    COALESCE(runs.project_id, repos.project_id),
    repos.id,
    findings.repo,
    findings.path,
    findings.line,
    findings.cap,
    findings.rule,
    findings.severity,
    CASE
        WHEN findings.verdict_blob IS NOT NULL AND json_valid(findings.verdict_blob)
        THEN json_extract(findings.verdict_blob, '$.message')
        ELSE NULL
    END,
    findings.verdict_blob,
    CASE
        WHEN lower(findings.severity) = 'info' THEN 'info'
        ELSE 'security'
    END,
    CASE
        WHEN lower(findings.severity) IN ('medium', 'high', 'critical') THEN 1
        ELSE 0
    END,
    CASE
        WHEN lower(findings.severity) IN ('medium', 'high', 'critical') THEN NULL
        WHEN lower(findings.severity) = 'info' THEN 'below-threshold'
        ELSE 'below-threshold'
    END,
    NULL,
    findings.first_seen
FROM findings
JOIN repos ON repos.name = findings.repo
LEFT JOIN runs ON runs.id = findings.run_id
WHERE findings.finding_origin = 'Static'
  AND COALESCE(runs.project_id, repos.project_id) IS NOT NULL;

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
    FOREIGN KEY (run_id) REFERENCES runs(id) ON DELETE CASCADE,
    FOREIGN KEY (project_id) REFERENCES projects(id) ON DELETE CASCADE,
    FOREIGN KEY (trace_id) REFERENCES agent_traces(id) ON DELETE SET NULL
);
CREATE INDEX idx_pentest_candidates_run_id ON pentest_candidates(run_id);
CREATE INDEX idx_pentest_candidates_project_id ON pentest_candidates(project_id);
CREATE INDEX idx_pentest_candidates_status ON pentest_candidates(status);
CREATE INDEX idx_pentest_candidates_source ON pentest_candidates(source);

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
    FOREIGN KEY (run_id) REFERENCES runs(id) ON DELETE CASCADE,
    FOREIGN KEY (project_id) REFERENCES projects(id) ON DELETE CASCADE,
    FOREIGN KEY (environment_run_id) REFERENCES environment_runs(id) ON DELETE CASCADE,
    FOREIGN KEY (candidate_id) REFERENCES pentest_candidates(id) ON DELETE SET NULL,
    FOREIGN KEY (chain_id) REFERENCES chains(id) ON DELETE SET NULL
);
CREATE INDEX idx_verification_attempts_run_id ON verification_attempts(run_id);
CREATE INDEX idx_verification_attempts_candidate_id ON verification_attempts(candidate_id);
CREATE INDEX idx_verification_attempts_status ON verification_attempts(status);

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
    FOREIGN KEY (run_id) REFERENCES runs(id) ON DELETE CASCADE,
    FOREIGN KEY (project_id) REFERENCES projects(id) ON DELETE CASCADE,
    FOREIGN KEY (chain_id) REFERENCES chains(id) ON DELETE SET NULL
);
CREATE INDEX idx_verified_vulnerabilities_run_id ON verified_vulnerabilities(run_id);
CREATE INDEX idx_verified_vulnerabilities_project_id ON verified_vulnerabilities(project_id);
CREATE INDEX idx_verified_vulnerabilities_status ON verified_vulnerabilities(status);
CREATE INDEX idx_verified_vulnerabilities_severity ON verified_vulnerabilities(severity);

ALTER TABLE chains ADD COLUMN status TEXT NOT NULL DEFAULT 'Proposed';
ALTER TABLE chains ADD COLUMN verification_attempt_id TEXT REFERENCES verification_attempts(id) ON DELETE SET NULL;
ALTER TABLE chains ADD COLUMN evidence_blob TEXT;
ALTER TABLE chains ADD COLUMN severity TEXT;

ALTER TABLE agent_traces ADD COLUMN run_id TEXT REFERENCES runs(id) ON DELETE SET NULL;
ALTER TABLE agent_traces ADD COLUMN project_id TEXT REFERENCES projects(id) ON DELETE SET NULL;
ALTER TABLE agent_traces ADD COLUMN candidate_id TEXT REFERENCES pentest_candidates(id) ON DELETE SET NULL;
ALTER TABLE agent_traces ADD COLUMN vulnerability_id TEXT REFERENCES verified_vulnerabilities(id) ON DELETE SET NULL;
ALTER TABLE agent_traces ADD COLUMN phase TEXT;

CREATE INDEX idx_chains_status ON chains(status);
CREATE INDEX idx_agent_traces_run_id ON agent_traces(run_id);
CREATE INDEX idx_agent_traces_project_id ON agent_traces(project_id);
CREATE INDEX idx_agent_traces_candidate_id ON agent_traces(candidate_id);
CREATE INDEX idx_agent_traces_vulnerability_id ON agent_traces(vulnerability_id);
CREATE INDEX idx_agent_traces_phase ON agent_traces(phase);

CREATE TABLE run_phase_events (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id        TEXT    NOT NULL,
    project_id    TEXT    NOT NULL,
    phase         TEXT    NOT NULL,
    status        TEXT    NOT NULL,
    message       TEXT,
    created_at    INTEGER NOT NULL,
    FOREIGN KEY (run_id) REFERENCES runs(id) ON DELETE CASCADE,
    FOREIGN KEY (project_id) REFERENCES projects(id) ON DELETE CASCADE
);
CREATE INDEX idx_run_phase_events_run_id ON run_phase_events(run_id);
CREATE INDEX idx_run_phase_events_phase ON run_phase_events(phase);

PRAGMA foreign_keys = ON;

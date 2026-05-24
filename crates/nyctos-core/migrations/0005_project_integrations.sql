CREATE TABLE project_integrations (
    id                    TEXT    PRIMARY KEY,
    project_id            TEXT    NOT NULL,
    kind                  TEXT    NOT NULL,
    name                  TEXT    NOT NULL,
    enabled               INTEGER NOT NULL,
    events_json           TEXT    NOT NULL,
    min_severity          TEXT,
    config_json           TEXT    NOT NULL,
    target                TEXT    NOT NULL,
    created_at            INTEGER NOT NULL,
    updated_at            INTEGER NOT NULL,
    last_delivery_at      INTEGER,
    last_delivery_status  TEXT,
    last_delivery_error   TEXT,
    FOREIGN KEY (project_id) REFERENCES projects(id) ON DELETE CASCADE
);

CREATE INDEX idx_project_integrations_project ON project_integrations(project_id);
CREATE INDEX idx_project_integrations_enabled ON project_integrations(project_id, enabled);

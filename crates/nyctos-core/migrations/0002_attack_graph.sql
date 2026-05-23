-- Persisted attack graph index.
--
-- Domain artifacts remain in their owning tables. These rows provide a
-- connected, run-scoped graph over routes, endpoints, forms, parameters,
-- roles, objects, signals, candidates, verification attempts, verified
-- vulnerabilities, and chains.

CREATE TABLE attack_graph_nodes (
    id               TEXT    PRIMARY KEY,
    run_id           TEXT    NOT NULL,
    project_id       TEXT    NOT NULL,
    kind             TEXT    NOT NULL,
    stable_key       TEXT    NOT NULL,
    label            TEXT    NOT NULL,
    ref_id           TEXT,
    properties_json  TEXT    NOT NULL DEFAULT '{}',
    created_at       INTEGER NOT NULL,
    updated_at       INTEGER NOT NULL,
    UNIQUE(run_id, kind, stable_key),
    FOREIGN KEY (run_id)     REFERENCES runs(id)     ON DELETE CASCADE,
    FOREIGN KEY (project_id) REFERENCES projects(id) ON DELETE CASCADE
);

CREATE TABLE attack_graph_edges (
    id               TEXT    PRIMARY KEY,
    run_id           TEXT    NOT NULL,
    project_id       TEXT    NOT NULL,
    kind             TEXT    NOT NULL,
    from_node_id     TEXT    NOT NULL,
    to_node_id       TEXT    NOT NULL,
    evidence_ref     TEXT,
    properties_json  TEXT    NOT NULL DEFAULT '{}',
    created_at       INTEGER NOT NULL,
    FOREIGN KEY (run_id)       REFERENCES runs(id)                ON DELETE CASCADE,
    FOREIGN KEY (project_id)   REFERENCES projects(id)            ON DELETE CASCADE,
    FOREIGN KEY (from_node_id) REFERENCES attack_graph_nodes(id)  ON DELETE CASCADE,
    FOREIGN KEY (to_node_id)   REFERENCES attack_graph_nodes(id)  ON DELETE CASCADE
);

CREATE INDEX idx_attack_graph_nodes_run_kind
    ON attack_graph_nodes(run_id, kind);
CREATE INDEX idx_attack_graph_nodes_project_kind
    ON attack_graph_nodes(project_id, kind);
CREATE INDEX idx_attack_graph_nodes_ref
    ON attack_graph_nodes(kind, ref_id);
CREATE INDEX idx_attack_graph_nodes_stable
    ON attack_graph_nodes(run_id, kind, stable_key);

CREATE INDEX idx_attack_graph_edges_run_kind
    ON attack_graph_edges(run_id, kind);
CREATE INDEX idx_attack_graph_edges_from
    ON attack_graph_edges(from_node_id);
CREATE INDEX idx_attack_graph_edges_to
    ON attack_graph_edges(to_node_id);
CREATE INDEX idx_attack_graph_edges_evidence
    ON attack_graph_edges(evidence_ref);

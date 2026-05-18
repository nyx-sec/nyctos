-- v2 schema: harness_specs table + findings.spec_id back-link.
--
-- Phase 15 adds the SpecDerivation agent task, which produces a
-- structured `HarnessSpec` JSON for diags the static scanner marked as
-- `Inconclusive(SpecDerivationFailed)`. The spec lives in its own table
-- so the verifier (Phase 18+) can scan over rows independently of
-- findings, while the back-link on findings carries the one-to-one
-- relationship the plan calls out.
--
-- v1 + v2 round-trip is verified by the migrations-idempotent test on
-- `Store::open`; no other v1 columns are touched.

CREATE TABLE harness_specs (
    id                  TEXT    PRIMARY KEY,
    cap                 TEXT    NOT NULL,
    lang                TEXT    NOT NULL,
    spec_blob           TEXT    NOT NULL,
    attack_provenance   TEXT,
    prompt_version      TEXT,
    created_at          INTEGER NOT NULL
);

ALTER TABLE findings ADD COLUMN spec_id TEXT REFERENCES harness_specs(id) ON DELETE SET NULL;

CREATE INDEX idx_harness_specs_cap        ON harness_specs(cap);
CREATE INDEX idx_findings_spec_id         ON findings(spec_id);

-- v5 schema: candidate_findings.trace_id back-link to agent_traces.
--
-- NovelFindingDiscovery writes one agent_traces row per batch and N
-- candidate_findings rows for the candidates that batch produced. Prior
-- to this migration the trace was orphaned (trace.finding_id = NULL,
-- candidate had no pointer back), so the quarantine UI's
-- /findings/:id/traces lookup against a `cand-...` id returned an empty
-- list even though the proposing AI call had persisted a trace.
--
-- The schema picks the 1:N direction the data has: one batch trace
-- backs many candidates, so the FK lives on candidate_findings. Trace
-- rows still carry finding_id for the static-pass paths
-- (PayloadSynthesis / SpecDerivation / ChainReasoning) where the trace
-- is per-finding; candidate-backed traces leave finding_id NULL and
-- get reached via the new join.
--
-- ON DELETE SET NULL because deleting a trace row should not cascade
-- a candidate. Tracing is observational; the candidate stands on its
-- own.

ALTER TABLE candidate_findings
    ADD COLUMN trace_id TEXT REFERENCES agent_traces(id) ON DELETE SET NULL;

CREATE INDEX idx_candidate_findings_trace_id ON candidate_findings(trace_id);

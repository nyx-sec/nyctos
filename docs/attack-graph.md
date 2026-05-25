# Attack Graph

Nyctos stores an attack graph as a run-scoped index over the artifacts
the scanner and agent pipeline already persist. It does not replace the
source tables; `nyx_signals`, `pentest_candidates`,
`verification_attempts`, `verified_vulnerabilities`, `chains`,
`route_models`, and `business_logic_template_runs` remain
authoritative. The graph gives those records a
common set of nodes and edges so later UI and report surfaces can answer
provenance and blast-radius questions without hand-joining every table.

Source: `crates/nyctos-core/src/store/attack_graph.rs`,
`crates/nyctos-core/migrations/0001_v1.sql`,
`crates/nyctos-types/src/attack_graph.rs`.

## Schema

Two tables back the graph:

| Table | Purpose |
|---|---|
| `attack_graph_nodes` | Run-scoped nodes with `kind`, `stable_key`, optional `ref_id`, display `label`, and JSON properties. |
| `attack_graph_edges` | Directed relationships between nodes, with an edge `kind`, optional `evidence_ref`, and JSON properties. |

Node ids and edge ids are deterministic BLAKE3-derived ids over their
run, kind, and stable identity. Replaying the same artifact write for a
run converges on the same graph row.

`ref_id` points back to the owning artifact when there is one, such as a
`nyx_signals.id`, `pentest_candidates.id`, `verification_attempts.id`,
`verified_vulnerabilities.id`, or `chains.id`. Route, endpoint,
parameter, role, and object nodes usually rely on `stable_key` instead.

## Node Kinds

The shipped graph writers can represent these node kinds:

| Kind | Meaning |
|---|---|
| `route` | A discovered application path, shared across frontend, backend, and API-client evidence for the same run. |
| `endpoint` | A method-specific backend route, API client call, or concrete request target. |
| `form` | A discovered HTML/JSX form, including action, method, and field metadata when available. |
| `parameter` | Path, query, body, tenant, or owner parameter discovered from route models. |
| `role` | Auth role or role-like check such as `authenticated`. |
| `object` | Application resource, service, model, or source object, including route resources and file locations. |
| `signal` | Static or scanner signal, including placeholder source nodes for external scanner leads. |
| `candidate` | Pentest candidate from Nyx signals, optional scanners, or AI candidate finding discovery. |
| `business_logic_template` | Registered template provenance for template-generated candidates. |
| `verification_attempt` | Live verification attempt that exercised a candidate or chain. |
| `verified_vulnerability` | Confirmed vulnerability row. |
| `chain` | Chain reasoning row and its members. |

## Edge Kinds

The graph keeps edge labels intentionally small:

| Kind | Typical direction |
|---|---|
| `discovered_from` | Reserved for future importer provenance. |
| `targets` | Candidate, attempt, vulnerability, signal, or endpoint points at a route, endpoint, or parameter. |
| `uses_role` | Route, endpoint, candidate, or vulnerability depends on a role. |
| `touches_object` | Route, endpoint, signal, candidate, or vulnerability touches a resource or file object. |
| `derived_candidate` | Signal/source node produced a candidate. |
| `verified_as` | Candidate or verification attempt led to a verified vulnerability. |
| `chained_with` | Chain relates to member signals or vulnerabilities. |

## Population

Graph rows are dual-written by the existing store accessors:

- `RouteModelStore::upsert` records route, endpoint, form, parameter,
  role, and object nodes, then links route-source locations to existing
  Nyx signal nodes when line information overlaps. Semantic App Model v2
  fields are mirrored into endpoint properties and graph links:
  framework, handler, middleware/auth checks, role checks, path/query/body
  fields, tenant and owner fields, service calls, model names, resource
  names, response hints, and side-effect classifications.
- `NyxSignalStore::insert` records signal nodes and file object links.
- `PentestCandidateStore::insert` and `CandidateFindingStore::insert`
  record candidate nodes, source edges, and target/object/role links.
  Business-logic candidates additionally link their template node to
  the candidate and expose route, role, and object touch points from
  structured template metadata.
- `VerificationAttemptStore::insert` records attempt nodes and request
  targets.
- `VerifiedVulnerabilityStore::upsert` records verified vulnerability
  nodes and links source candidates, source signals, verification
  attempts, chains, and affected components.
- `ChainStore::insert` records chain nodes and `chained_with` edges to
  member nodes when possible.

Because the graph is derivative, reports remain compatible with older
consumers. Existing `report.json`, run cards, vulnerabilities, findings,
and chains keep their current shapes.

## Queries

`Store::attack_graph()` exposes the first two graph queries:

- `evidence_for_vulnerability(vulnerability_id)` walks inbound graph
  edges from a verified vulnerability and includes directly connected
  target, role, object, and chain context. This answers "what evidence
  led to this vuln?"
- `vulnerabilities_touching(run_id, kind, stable_key)` starts from a
  route, object, role, or other graph node and walks connected graph
  edges to verified vulnerabilities. This answers "what vulns touch this
  route/object/role?"

The intended next UI use is a vulnerability evidence panel that shows
the signal -> candidate -> verification attempt -> vulnerability path,
plus any route, object, role, and chain context. The intended report use
is an optional graph appendix or PR-comment detail section that can be
added without changing the existing report schema.

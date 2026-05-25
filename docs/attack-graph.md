# Attack Graph

Nyctos stores an attack graph as a run-scoped index over the artifacts
the scanner and agent pipeline already persist. It does not replace the
source tables; `nyx_signals`, `pentest_candidates`,
`verification_attempts`, `verified_vulnerabilities`, `chains`,
`route_models`, `business_logic_template_runs`, and
`exploration_memory` remain
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
| `exploration_memory` | Durable lesson from a prior exploration or verifier result. |

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
| `learned_from` | Exploration memory points back to the candidate or verification attempt that produced the lesson. |

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
- `ExplorationMemoryStore::upsert` records memory nodes, links them to
  candidate and verification-attempt provenance when available, and
  mirrors endpoint, role, and object context as graph links. These rows
  are durable across runs and are consumed by future AI exploration
  prompts and relevance ranking.

Because the graph is derivative, reports remain compatible with older
consumers. Existing `report.json`, run cards, vulnerabilities, findings,
and chains keep their current shapes.

## Queries

`Store::attack_graph()` exposes graph queries for vulnerability evidence,
blast-radius lookup, and chain planning:

- `evidence_for_vulnerability(vulnerability_id)` walks inbound graph
  edges from a verified vulnerability and includes directly connected
  target, role, object, and chain context. This answers "what evidence
  led to this vuln?"
- `vulnerabilities_touching(run_id, kind, stable_key)` starts from a
  route, object, role, or other graph node and walks connected graph
  edges to verified vulnerabilities. This answers "what vulns touch this
  route/object/role?"
- `candidate_to_route(run_id, candidate_id)` returns the candidate's
  graph-backed route, endpoint, parameter, role, object, source-signal,
  and verification context.
- `route_to_role_object(run_id, route_stable_key)` returns the route's
  endpoint/form context plus role and object edges. This is the compact
  "what does this route require and touch?" query.
- `vuln_to_object_role(run_id, vulnerability_id)` returns a confirmed
  vulnerability's target, role, object, candidate, verification, and
  chain context.
- `cross_repo_service_edges(run_id)` returns service-like target/object
  edges that cross repository boundaries when both sides carry repo
  metadata.
- `chain_planning_input(run_id, max_chains)` builds the compact
  ChainReasoning input from graph nodes and edges. It includes candidates,
  signals, routes, endpoints, forms, parameters, roles, objects,
  verification attempts, verified vulnerabilities, and business-logic
  template provenance.

## Chain Planning

ChainReasoning is now graph-native. The planner consumes the attack graph
neighborhood instead of only static finding-flow summaries. Graph nodes
are passed with stable graph ids, artifact `ref_id`s when present, route,
role, object, and evidence-ref context. Graph edges are passed with edge
ids, labels, evidence refs, source tags, and cross-repo flags.

The model contract ranks chains with:

| Field | Meaning |
|---|---|
| `member_ids` | Ordered graph node ids. Every adjacent pair must be connected by an input graph edge. |
| `rationale` | Human-readable exploitability rationale. |
| `prerequisites` | Required attacker state, roles, tenant/object state, or route reachability. |
| `evidence` | Specific graph-backed facts supporting the chain. |
| `blast_radius` | Affected routes, roles, objects, services, repos, or tenant boundaries. |
| `confidence` | Integer confidence from 0 to 100. |
| `missing_verification_steps` | Proof still needed before the chain is confirmed. |
| `edge_provenance` | Edge ids or evidence refs supporting the member-to-member links. |

The AI task validates that every member id exists and that every adjacent
member pair is backed by an input edge. This prevents weak leads from
being promoted into serious chains unless the graph contains route,
object, role, signal, candidate, verification, or service evidence for
the link.

Persisted `chains.member_ids` remains the ordered member id list for
compatibility. The structured graph proof is persisted in
`chains.evidence_blob` with `schema_version = 1`, including member
metadata, edge provenance, prerequisites, evidence, blast radius,
confidence, and missing verification steps. `ChainStore::insert` still
dual-writes the chain node and `chained_with` member edges into the graph.

The chain UI reads the structured `evidence_blob` to show graph-backed
paths, edge evidence, confidence, blast radius, and missing proof gaps.
Older chains without this blob still render their rationale and member
ids.

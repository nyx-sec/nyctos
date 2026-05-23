# Business Logic Templates

Nyctos includes reusable business-logic pentest templates for bugs
normal scanners tend to miss. Templates are first-class metadata, but
not a separate executor: they create normal `pentest_candidates` with
normal live test plans, then the existing verifier handles auth
sessions, policy gates, evidence review, verification attempts, and
verified vulnerability storage.

Templates run during candidate synthesis after route-model extraction.
They inspect discovered backend routes, configured auth profiles, and
the run safety settings.

## Discovering Templates

CLI:

```bash
nyctos business-logic templates
nyctos business-logic templates --json
```

API:

```bash
curl http://127.0.0.1:8765/api/v1/business-logic/templates
```

Each template exposes a stable `id`, `version`, `title`, `category`,
`mutability`, required role descriptor, seed-data description,
supported route patterns, oracle description, default severity, and
whether it is executable or metadata-only.

## Safety

Executable templates may create objects, submit checkout data, change
file permissions, deliver webhook payloads, or create chatbot
conversation state. Nyctos only generates these state-changing
template candidates when both run gates are enabled:

```toml
[run]
exploit_mode_enabled = true
allow_state_changing_live_probes = true
```

The project detail page's **Start pentest** action and
`POST /api/v1/projects/:id/pentest` can set the same per-run gates
without making a persistent config change. If the gates are not
enabled, the run records structured skip reasons in
`business_logic_template_runs`.

Generated plans still pass through the normal live-verifier policy:
request caps, rate limiting, dry-run mode, target URL scope checks,
auth-session acquisition, and environment reset after state-changing
actions.

## Configuration

Business-logic template synthesis is enabled by default. Disable it
globally:

```toml
[run]
business_logic_templates_enabled = false
```

Select a subset by id:

```toml
[run]
business_logic_template_ids = [
  "tenant_object_isolation",
  "webhook_callback_trust_boundary",
]
```

The same selection can be supplied per run:

```bash
nyctos scan \
  --exploit-mode \
  --allow-state-changing-live-probes \
  --business-template tenant_object_isolation \
  --business-template webhook_callback_trust_boundary
```

Dry-run keeps candidate synthesis visible while the verifier policy
blocks live traffic:

```toml
[run]
exploit_mode_enabled = true
allow_state_changing_live_probes = true
exploit_dry_run = true
business_logic_template_ids = ["webhook_callback_trust_boundary"]
```

Run summary example:

```json
{
  "run_id": "run-...",
  "templates_considered": 1,
  "candidates_generated": 1,
  "templates_skipped": 0,
  "dry_run": true,
  "templates": [
    {
      "template_id": "webhook_callback_trust_boundary",
      "template_version": "1",
      "generated_count": 1,
      "skipped_count": 0,
      "skip_reasons": [],
      "dry_run": true
    }
  ]
}
```

## Shipped Templates

### Tenant / Object Isolation

Looks for a `POST` collection route paired with a `GET` detail route,
for example:

```text
POST /api/projects
GET  /api/projects/:id
```

Required roles: two configured non-anonymous roles such as `user_a`
and `user_b`.

The template seeds an object as the first role, captures the returned
object id, and asks whether the second role can read the first role's
object. Confirmation requires the forbidden-role response to contain
the seeded marker.

```json
{
  "kind": "http_workflow",
  "template_provenance": {
    "template_id": "tenant_object_isolation",
    "template_version": "1",
    "title": "Tenant/object isolation",
    "category": "authorization",
    "mutability": "state_changing"
  },
  "required_roles": ["user_a", "user_b"],
  "seed_data": {
    "object_marker": "nyctos-tenant-object-isolation-abc12345",
    "owner_role": "user_a",
    "peer_role": "user_b"
  },
  "steps": [
    {
      "as": "user_a",
      "method": "POST",
      "path": "/api/projects",
      "json": { "name": "nyctos-tenant-object-isolation-abc12345" },
      "destructive": true,
      "captures": {
        "object_id": {
          "from": "body",
          "regex": "\"(?:id|uuid|object_id|project_id|account_id)\"\\s*:\\s*\"?([A-Za-z0-9_.:-]+)\"?"
        }
      }
    },
    {
      "as": "user_b",
      "method": "GET",
      "path": "/api/projects/{{object_id}}"
    }
  ],
  "oracle": {
    "step": 1,
    "status_range": "2xx",
    "body_contains": "nyctos-tenant-object-isolation-abc12345"
  }
}
```

### Coupon / Price Manipulation

Looks for state-changing checkout, cart, coupon, payment, billing,
order, invoice, price, amount, total, discount, or promo surfaces.

Required roles: one configured role if available; otherwise anonymous.

The template submits a marker coupon plus a low controlled price value.
Confirmation requires the response to echo the marker, so a mere 200
status is not enough.

```json
{
  "kind": "http_workflow",
  "required_roles": ["user"],
  "seed_data": {
    "coupon_marker": "nyctos-coupon-price-manipulation-def67890",
    "forced_price": "0.01",
    "role": "user"
  },
  "steps": [
    {
      "as": "user",
      "method": "POST",
      "path": "/api/checkout/coupon",
      "json": {
        "coupon_code": "nyctos-coupon-price-manipulation-def67890",
        "total": 0.01
      },
      "destructive": true
    }
  ],
  "oracle": {
    "step": 0,
    "status_range": "2xx",
    "body_contains": "nyctos-coupon-price-manipulation-def67890"
  }
}
```

### AI Chatbot Exploitability

Looks for state-changing AI/chat/assistant/bot/LLM/copilot routes or
message-like request fields.

Required roles: one configured role if available; otherwise anonymous.

The template sends a prompt-injection probe that asks the app to emit a
unique marker only when hidden system/developer instructions are
exposed. Confirmation requires both the marker and `system prompt`
evidence in the live response.

### File Access After Permission Change

Looks for a `POST` file/document collection route, a `GET` detail
route, and a state-changing share/permission/access/collaborator
route. Required roles: two configured non-anonymous roles.

The template creates a file-like object as the owner role, performs a
permission-change step, then asks whether the peer role can still read
the seeded file marker. Confirmation requires a 2xx peer read response
containing that marker.

### Webhook / Callback Trust Boundary

Looks for state-changing webhook/callback/receiver/integration/event
routes or signature/event payload fields. Required role: anonymous
when the route has no auth checks, otherwise one configured role.

The template submits an unsigned event marker. Confirmation requires a
2xx live response that reflects the marker.

## Metadata-Only Templates

Invite acceptance / privilege escalation and password reset token
misuse are registered as metadata-only templates. Current route/auth
models do not expose safe application-issued invite or reset-token
seed data, so Nyctos records skip reasons instead of emitting weak
executable plans.

## Provenance

Template-generated candidates include structured provenance in
`affected_components[*].template_provenance` and in the verifier plan.
Verification attempts copy that provenance into `request` and `oracle`
under `business_logic_template`. Verified vulnerabilities inherit the
candidate's affected components, so reports can show the source
template without parsing `source` strings.

Example verified vulnerability fragment:

```json
{
  "id": "vuln-bl-...",
  "source_candidate_ids": ["pc-bl-..."],
  "affected_components": [
    {
      "kind": "business_logic_template",
      "template_provenance": {
        "template_id": "tenant_object_isolation",
        "template_version": "1"
      },
      "route_path": "/api/projects/:id",
      "roles": ["user_b"]
    }
  ]
}
```

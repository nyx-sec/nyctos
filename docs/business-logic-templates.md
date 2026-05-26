# Business Logic Templates

Nyx Agent includes reusable business-logic pentest templates for bugs
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
nyx-agent business-logic templates
nyx-agent business-logic templates --json
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
conversation state. Nyx Agent only generates these state-changing
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

Authorization templates and research candidates that use role
comparison or object ownership also populate the Authorization Matrix.
Each live verification attempt writes an allowed-control row and a
challenged-access row with expected and observed decisions, endpoint,
resource/object id, owner role, tenant metadata when configured, body
marker result, confidence, candidate id, verification attempt id, and
evidence. The run detail UI groups these rows by endpoint/resource, and
`GET /api/v1/runs/:id/authz-matrix` exposes the same data.

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
  "webhook_replay_freshness",
  "invite_accept_reuse",
]
```

The same selection can be supplied per run:

```bash
nyx-agent scan \
  --exploit-mode \
  --allow-state-changing-live-probes \
  --research-mode \
  --business-template invite_accept_reuse \
  --business-template password_reset_token_replay \
  --business-template webhook_replay_freshness
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

Vuln Research Mode complements templates. Templates create curated,
template-provenance candidates for known business-logic patterns.
Research mode adds separate `ResearchMode` candidates from the semantic
route model and prior candidate memory when a product invariant looks
risky but no concrete template applies yet. These include lifecycle
bugs, stale access, replay, downgrade or entitlement mismatch,
invite/team/org transitions, webhook/event consistency, AI-agent
indirect actions, and background job side effects. Research-mode
candidates still enter the same live verifier and safety gates as
template candidates.

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

First-class IDOR/authz plans can also describe the ownership boundary
directly. This shape runs the owner request and peer request through
separate named sessions and verifies only when both live responses carry
the same object-specific marker:

```json
{
  "kind": "authz_object_ownership",
  "object": {
    "name": "project",
    "owner_role": "user_a",
    "id": "proj-user-a-1",
    "route": "/api/projects/{id}",
    "positive_markers": ["nyx-agent-user-a-project", "proj-user-a-1"]
  },
  "accessor_role": "user_b",
  "owner_request": {
    "method": "GET",
    "path": "/api/projects/{{object_id}}"
  },
  "accessor_request": {
    "method": "GET",
    "path": "/api/projects/{{object_id}}"
  },
  "oracle": {
    "type": "object_ownership_break",
    "forbidden_status": [401, 403, 404],
    "positive_markers": ["nyx-agent-user-a-project", "proj-user-a-1"]
  }
}
```

For UI-only authorization boundaries, the live verifier can compare the
same browser workflow under two roles. The workflow below verifies only
when both `admin` and `user` sessions render the same positive admin UI
marker:

```json
{
  "kind": "authz_browser_role_comparison",
  "allowed_role": "admin",
  "challenged_role": "user",
  "workflow": {
    "url": "/app/admin",
    "steps": [
      {"action": "wait_for_selector", "selector": "main"}
    ],
    "oracle": {
      "text_contains": "Admin Console"
    }
  }
}
```

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
    "object_marker": "nyx-agent-tenant-object-isolation-abc12345",
    "owner_role": "user_a",
    "peer_role": "user_b"
  },
  "steps": [
    {
      "as": "user_a",
      "method": "POST",
      "path": "/api/projects",
      "json": { "name": "nyx-agent-tenant-object-isolation-abc12345" },
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
    "body_contains": "nyx-agent-tenant-object-isolation-abc12345"
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
    "coupon_marker": "nyx-agent-coupon-price-manipulation-def67890",
    "forced_price": "0.01",
    "role": "user"
  },
  "steps": [
    {
      "as": "user",
      "method": "POST",
      "path": "/api/checkout/coupon",
      "json": {
        "coupon_code": "nyx-agent-coupon-price-manipulation-def67890",
        "total": 0.01
      },
      "destructive": true
    }
  ],
  "oracle": {
    "step": 0,
    "status_range": "2xx",
    "body_contains": "nyx-agent-coupon-price-manipulation-def67890"
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

### AI / Chatbot Indirect Action Abuse

Looks for the same AI/chat/assistant surfaces, especially agent/tool or
action-oriented routes. Required role: one configured role if available;
otherwise anonymous.

The template asks the assistant to perform a harmless indirect action,
such as creating a labelled test draft/note, using a unique marker.
Confirmation requires both the marker and explicit action-execution
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

### Webhook Replay / Freshness

Looks for webhook/callback routes with event id, timestamp, signature,
payload, or callback-like fields. Required role: anonymous when the
route has no auth checks, otherwise one configured role.

The template sends the same stale event id and timestamp twice.
Confirmation requires the replay response to return 2xx and reflect the
unique marker. This catches handlers that do not enforce freshness,
signature timestamp windows, or idempotency.

```json
{
  "kind": "http_workflow",
  "required_roles": ["anonymous"],
  "seed_data": {
    "event_marker": "nyx-agent-webhook-replay-freshness-1234abcd",
    "timestamp": "2000-01-01T00:00:00Z",
    "role": "anonymous"
  },
  "steps": [
    {
      "as": "anonymous",
      "method": "POST",
      "path": "/webhooks/stripe",
      "json": {
        "event_id": "nyx-agent-webhook-replay-freshness-1234abcd",
        "timestamp": "2000-01-01T00:00:00Z",
        "signature": "unsigned"
      },
      "destructive": true
    },
    {
      "as": "anonymous",
      "method": "POST",
      "path": "/webhooks/stripe",
      "json": {
        "event_id": "nyx-agent-webhook-replay-freshness-1234abcd",
        "timestamp": "2000-01-01T00:00:00Z",
        "signature": "unsigned"
      },
      "destructive": true
    }
  ],
  "oracle": {
    "step": 1,
    "status_range": "2xx",
    "body_contains": "nyx-agent-webhook-replay-freshness-1234abcd"
  }
}
```

### Invite Accept / Reuse

Looks for an invite creation route paired with an invite accept/join
route. Required roles: two configured non-anonymous roles, such as
`owner` and `invitee`.

The template creates an invite, captures an invite token/id from the
creation response, accepts it, then replays the same acceptance.
Confirmation requires the replay response to reflect the invite marker.
If no accept route or no second role is configured, Nyx Agent records a
skip reason instead of emitting a weak plan.

### Password Reset Token Replay

Looks for password-reset request and reset-confirmation routes.
Required roles: disposable victim and attacker/test accounts.

The template requests a reset for a disposable marker email, captures a
reset token/code from the response in test harnesses, submits the reset,
then replays the same token. Confirmation requires the replay reset to
reflect the marker. If the route model does not expose a request and
confirmation pair, or the project lacks the required test accounts,
Nyx Agent records a skip reason.

### Email Change Without Reauth

Looks for account/profile/settings email-change routes with email-like
fields and no current-password, old-password, reauth, or MFA fields.
Required role: one configured non-anonymous role.

The template submits a disposable email marker. Confirmation requires a
2xx response that reflects the new email marker, indicating the route
accepted a sensitive account change without a reauth challenge.

### Subscription Downgrade / Feature Retention

Looks for subscription, billing, plan, tier, downgrade, cancel, or
change routes paired with premium feature/export/report/API routes.
Required role: one configured non-anonymous role.

The template downgrades a disposable subscription marker and then calls
the premium feature route. Confirmation requires the post-downgrade
feature response to reflect the marker.

### Refund / Replay

Looks for refund, return, reversal, chargeback, credit, payment id,
order id, and amount routes. Required role: one configured
non-anonymous role.

The template submits the same refund marker twice with the same
idempotency key. Confirmation requires the replay response to reflect
the marker, which indicates replay/idempotency handling needs review.

### OAuth Callback State Confusion

Looks for OAuth/OIDC/SSO callback or redirect routes with `state`,
`code`, or `redirect_uri` fields. Required role: one configured role if
available; otherwise anonymous.

The template calls the callback with mismatched `state` and `code`
markers and no prior browser session seed. Confirmation requires the
callback response to reflect the mismatched state marker.

### Credit Exhaustion Bypass

Looks for credit, quota, usage, metering, token, or generation routes.
Required role: one configured non-anonymous role.

The template replays a credit-consuming request with the same
idempotency marker and zero-credit/quota hints. Confirmation requires
the replay response to reflect the marker after the credit-exhaustion
shape.

## Safe Skips

All shipped business-logic templates are executable, but only when the
safety gates and enough route/auth/seed context are present. Missing
gates produce the standard state-changing skip:

```text
state-changing workflow requires exploit mode and allow_state_changing_live_probes
```

Missing roles or route pairs produce template-specific reasons, for
example:

```text
invite_accept_reuse: required auth profiles are missing for roles ["inviter_role", "invitee_role"]
password_reset_token_replay: needs password reset request and confirmation routes with a reset token/code seed
subscription_downgrade_feature_retention: needs a downgrade route paired with a premium feature route
```

## Provenance

Template-generated candidates include structured provenance in
`affected_components[*].template_provenance` and in the verifier plan.
Verification attempts copy that provenance into `request` and `oracle`
under `business_logic_template`. Verified vulnerabilities inherit the
candidate's affected components, so reports can show the source
template without parsing `source` strings.

Research-mode candidates use `source = "ResearchMode"` and include
`affected_components[*].research_mode_provenance` with the mode
version, source (`semantic_route_model` or `exploration_memory`),
category, invariant, and related memory candidate ids when present.

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

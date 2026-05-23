# Business Logic Templates

Nyctos includes a small set of reusable business-logic pentest
templates for bugs normal scanners tend to miss. Templates are not a
separate executor: they create `pentest_candidates` with normal live
test plans, then the existing verifier handles auth sessions, policy
gates, evidence review, verification attempts, and verified
vulnerability storage.

Templates run during candidate synthesis after route-model extraction.
They inspect discovered backend routes, configured auth profiles, and
the run safety settings.

## Safety

The first shipped templates may create objects, submit checkout data,
or create chatbot conversation state. Nyctos only generates these
state-changing template candidates when both run gates are enabled:

```toml
[run]
exploit_mode_enabled = true
allow_state_changing_live_probes = true
```

The project detail page's **Start pentest** action can set the same
per-run gates without making a persistent config change. If the gates
are not enabled, the run records a candidate-synthesis note explaining
which templates were skipped.

Generated plans still pass through the normal live-verifier policy:
request caps, rate limiting, dry-run mode, target URL scope checks,
auth-session acquisition, and environment reset after state-changing
actions.

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

## Future Templates

The template model is intentionally small and composable. The next
natural additions are invite acceptance / privilege escalation,
password reset token misuse, file access after permission change, and
webhook or callback trust-boundary probes. They should follow the same
shape: explicit roles, seed data, steps, captures, and at least one
positive evidence oracle.

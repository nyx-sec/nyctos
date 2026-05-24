Explore the running service in Vuln Research Mode and surface product-logic vulnerabilities the static pass missed.

ALLOWED HOSTS
{allowed}

TARGETS
{targets}

KNOWN SCANNER LEADS
{known_leads}

RESEARCH FOCUS
{research_focus}

WORKSPACE ROOT
{workspace_root}

CONSTRAINTS
- max_actions:  {max_actions}
- max_wall_clock: {max_secs}s
- sentinel_path: {sentinel}

RESEARCH CHECKLIST
- Lifecycle bugs: invalid state jumps, repeat transition, stale status,
  action after cancel/delete/archive, race-prone accept/revoke flows.
- Stale access: membership/share/revoke/delete changes that do not
  invalidate cached permissions, sessions, links, or object access.
- Replay: token, invite, OTP, callback, webhook, and event reuse or
  out-of-order delivery.
- Downgrade or entitlement mismatch: plan, role, quota, seat, price,
  trial, and billing changes not reflected in protected actions.
- Invite/team/org transitions: actor/target/org binding, expiration,
  role escalation, cross-org acceptance, and removed-member actions.
- Webhook/event consistency: signature/origin, deduplication, event id,
  retry semantics, and side effects.
- AI agent indirect actions: prompt or retrieved content causing tool
  calls, privileged reads/writes, workflow actions, or data exfiltration.
- Background job side effects: queued exports/imports/sync/report jobs
  that outlive authz, cross tenants, replay callbacks, or leak artifacts.

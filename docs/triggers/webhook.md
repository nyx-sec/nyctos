# Git webhook trigger

`POST /webhook/git` accepts a push payload from any self-hosted git
server, verifies an HMAC-SHA256 signature against a configured shared
secret, optionally filters by branch, and triggers a scan. The
endpoint bypasses bearer-token auth because the HMAC IS the auth.

## Config

```toml
[triggers]
# Shared secret resolution:
#   - `env:NAME`  → reads the named environment variable (recommended)
#   - any other value → treated as the literal secret (testing only)
webhook_secret_ref = "env:NYX_WEBHOOK_SECRET"
# Optional branch filter; `None` accepts any branch.
webhook_branch = "main"
```

Set `NYX_WEBHOOK_SECRET` in the daemon's environment (e.g. via a
systemd `EnvironmentFile=` drop-in or the macOS launchd plist's
`EnvironmentVariables` dict). The handler returns HTTP 503 when the
ref is configured but the env var is unset, so a misconfigured host
cannot accept unauthenticated triggers.

## Wire format

| Field | Value |
|-------|-------|
| Method | `POST` |
| Path | `/webhook/git` |
| Header | `X-Hub-Signature-256: sha256=<hex>` |
| Body | JSON with at least `"ref": "refs/heads/<branch>"` |

`X-Hub-Signature-256` is the GitHub / Gitea / Forgejo / Sourcehut
convention; the value is `sha256=` followed by the lowercase hex
encoding of `HMAC-SHA256(secret, body_bytes)`.

Other fields in the payload are ignored, so a thin Gitea or Bitbucket
push shape is accepted as-is.

## Response

| Status | Meaning |
|--------|---------|
| `202 Accepted` | HMAC valid, branch matched (or filter unset), scan triggered. Body: `{ "triggered": true, "run_id": "...", "message": "" }`. |
| `200 OK` | HMAC valid but branch filter rejected the delivery. Body: `{ "triggered": false, "run_id": null, "message": "branch filter rejected..." }`. |
| `401 Unauthorized` | Missing header, malformed signature, or HMAC mismatch. |
| `429 Too Many Requests` | Daemon dispatcher is saturated; the upstream git server should back off and retry. |
| `503 Service Unavailable` | `webhook_secret_ref` configured but the secret cannot be resolved (unset env var). |

The `200`-on-branch-skip shape is deliberate: upstream git servers
mark the delivery as successful and stop retrying, while the operator
can still tell from the JSON whether a scan fired.

## Worked example

Operator config:

```toml
[triggers]
webhook_secret_ref = "env:NYX_WEBHOOK_SECRET"
webhook_branch = "main"
```

Daemon env: `NYX_WEBHOOK_SECRET=hunter2`.

Sign + send:

```bash
BODY='{"ref":"refs/heads/main","after":"deadbeef"}'
SIG="sha256=$(printf '%s' "$BODY" | openssl dgst -sha256 -hmac "$NYX_WEBHOOK_SECRET" -hex | awk '{print $2}')"
curl -X POST http://127.0.0.1:4747/webhook/git \
  -H "X-Hub-Signature-256: $SIG" \
  -H 'content-type: application/json' \
  -d "$BODY"
# → 202 Accepted, body: {"triggered":true,"run_id":"...","message":""}
```

## Self-hosted git servers

| Server | Where to paste the URL + secret |
|--------|---------------------------------|
| GitHub Enterprise | Settings → Webhooks → Add webhook; content type `application/json`; choose "Just the push event"; secret = your `NYX_WEBHOOK_SECRET`. |
| Gitea / Forgejo | Settings → Webhooks → Gitea → URL + secret; default events include push. |
| Bitbucket Server | Repository → Webhooks → secret + push event. |
| Sourcehut | hg/builds webhook config; signature header name is the same. |

## Security model

- The token never leaves the daemon: the HMAC verifies the body the
  upstream server sent, the body must match the signature, and the
  comparison is constant-time (`subtle::ConstantTimeEq`).
- The endpoint bypasses the SPA's bearer-token gate because it carries
  its own auth, so do not put it behind a reverse proxy that strips
  the `X-Hub-Signature-256` header.
- Body size is capped at 1 MiB; payloads above that return HTTP 400.
- The handler does not log the secret or the raw body. If a webhook
  fails verification, the failure surfaces as a 401 with no further
  detail.

## Operator checklist

- [ ] `[triggers].webhook_secret_ref` set in `nyx-agent.toml`.
- [ ] Matching env var exported in the daemon's process environment.
- [ ] Daemon reachable from the upstream git server (loopback if both
      run on the same host; otherwise put a TLS terminator in front).
- [ ] `[triggers].webhook_branch` matches the branch you actually want
      to scan, or leave it unset to accept every branch.
- [ ] Test delivery from the git server's webhook UI returns `202`.

# Triggers

Phase 27 wires two no-touch ways to kick a scan: a host-level cron
schedule and an HTTP webhook for self-hosted git servers.

| Path | Use case |
|------|----------|
| [cron.md](cron.md) | Cron expressions in `nyctos.toml`, plus systemd / launchd units that keep the daemon up. |
| [webhook.md](webhook.md) | `POST /webhook/git` with HMAC-SHA256 verification, branch filter, and a CI-friendly response shape. |

Manual triggers (the SPA's "Scan now" button and `nyx-agent scan` from
the CLI) keep working alongside these.

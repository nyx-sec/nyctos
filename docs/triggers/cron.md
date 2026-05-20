# Cron-driven scans

The daemon ships an in-process scheduler that wakes every 60 seconds,
evaluates every `[[schedule]]` entry in `nyctos.toml`, and triggers
a scan through the same path the SPA's "Scan now" button uses. There
is no external `cron` process to wire up. The scheduler runs inside
`nyx-agent serve`, so the daemon must be running for entries to fire.

## Config

```toml
[[schedule]]
cron = "0 3 * * 1"          # Monday at 03:00 local time
repo = "nyx-pro"            # optional; omit to scan every enabled repo
label = "weekly-monday-3am" # surfaced in tracing + the UI
```

The cron expression is the canonical 5-field Unix form
(`minute hour day-of-month month day-of-week`). Day-of-week uses the
standard `0=Sunday, 1=Monday, ..., 7=Sunday` convention; the scheduler
translates internally to the underlying `cron` crate's ordinals so
operator-facing config matches what `crontab(5)` documents.

Common patterns:

| Expression  | Fires |
|-------------|-------|
| `0 3 * * 1` | Every Monday at 03:00 |
| `0 * * * *` | Every hour on the hour |
| `*/15 * * * *` | Every 15 minutes |
| `0 3 1 * *` | Midnight UTC on the 1st of each month (use the local clock) |

The scheduler debounces within a minute, so a 60-second wake that
lands twice in the same minute fires the entry exactly once. The
trigger is fire-and-forget: a saturated dispatcher returns HTTP-429
backpressure to the API and the scheduler logs a `warn!` and skips
that fire (the next valid minute will retry).

## Keeping the daemon up

The scheduler relies on the daemon being alive. Two host-supervisor
recipes ship under `packaging/`.

### systemd (Linux)

```bash
sudo install -m 0644 packaging/nyx-agent.service /etc/systemd/system/
sudo install -m 0644 packaging/nyx-agent.timer /etc/systemd/system/
sudo install -m 0644 packaging/nyx-agent-scan.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now nyx-agent.service
# Optional: a host-managed timer that also kicks a one-shot scan.
sudo systemctl enable --now nyx-agent.timer
```

`nyx-agent.service` runs `nyx-agent serve --headless`. The
`nyx-agent.timer` + `nyx-agent-scan.service` pair is optional: pick
either the in-process `[[schedule]]` entries OR the systemd timer, not
both, to avoid double-firing.

### launchd (macOS)

The shipped plist is a per-user LaunchAgent, not a system
LaunchDaemon. Install it under your own `~/Library/LaunchAgents/`
so the daemon runs as your user account, not as root:

```bash
install -m 0644 packaging/com.nyx.agent.plist \
  "$HOME/Library/LaunchAgents/com.nyx.agent.plist"
launchctl bootstrap gui/$(id -u) "$HOME/Library/LaunchAgents/com.nyx.agent.plist"
```

The plist runs `nyx-agent serve --headless` with `KeepAlive=true`,
so the daemon stays up across login sessions. Periodic kicks come
from the in-process scheduler reading `[[schedule]]` entries out
of `nyctos.toml`; there is no separate launchd calendar trigger to
configure.

Do not install this file under `/Library/LaunchDaemons/`. That
path runs the daemon as root, which contradicts the systemd
recipe's `DynamicUser=yes` hardening and broadens the blast radius
of every OS_COMMAND / PATH_TRAVERSAL / SSRF surface the agent
exposes to its own configured repositories.

## Verifying

```bash
journalctl -u nyx-agent.service -f
# or, on macOS:
log stream --predicate 'subsystem == "com.nyx.agent"'
```

Look for a `scheduler: trigger ok` log line at the configured time.

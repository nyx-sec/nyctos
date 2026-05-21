# GitHub Actions integration

The `nyctos` repo ships a composite Action at
`.github/actions/nyctos/action.yml` that runs the scanner against a
pull request, writes a machine-readable report, and posts (or updates)
a single grouped PR comment summarising Confirmed + cross-repo chain
findings. Everything else (Open, Quarantine, Inconclusive, AI trace
viewer, repro bundles) stays in the operator's local UI.

## What the Action does

The Action runs in two steps:

1. **`nyctos scan`** against the current checkout. Writes a JSON
   report to `<state-dir>/report.json`. The `--since-ref` flag filters
   findings to paths the PR touched (the base ref's `git diff
   --name-only` view); the underlying scan still walks the whole
   repository but the emitted report contains only PR-relevant rows.
2. **`nyctos pr-comment`** reads the report, filters to findings
   with `status = Verified` (Confirmed by the dynamic verifier) or
   members of a cross-repo chain, groups them by `(repo, path)` and
   severity, and posts a Markdown comment via the GitHub REST API.

A hidden HTML marker (`<!-- nyctos:pr-comment v1 -->`) at the top
of the comment body is used to recognise an existing comment on
subsequent runs - the second push to the same PR updates the comment
in place rather than creating a new one.

## Permissions

The Action requires the `pull-requests: write` GitHub Actions
permission so the bot can create or update the comment. Read-only
forks (`pull_request_target` is recommended over `pull_request` for
this reason) only need their default `contents: read`. The Action
exits cleanly when the report carries no Confirmed or cross-repo
chain findings; no comment is posted in that case.

```yaml
permissions:
  contents: read
  pull-requests: write
```

## Inputs

| input | required | description |
|---|---|---|
| `nyctos-binary` | no | Path to the binary. Defaults to `nyctos` (PATH lookup). |
| `config` | no | Path to `nyctos.toml`. Defaults to `./nyctos.toml`. |
| `state-dir` | no | State directory override. Defaults to a per-run tempdir under `$RUNNER_TEMP`. |
| `ui-url` | no | Base URL of the operator's local UI. Used to deep-link the comment back to `<ui-url>/runs/<run_id>`. Empty = no link. |
| `gh-api` | no | GitHub REST base. Override for GHE; defaults to `https://api.github.com`. |
| `gh-token` | yes | Token with `pull-requests: write`. Use `${{ github.token }}`. |

## Workflow example

```yaml
name: nyctos
on:
  pull_request:
    branches: [main]

permissions:
  contents: read
  pull-requests: write

jobs:
  nyctos:
    runs-on: self-hosted   # nyctos binary must be installed
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0    # required for `git diff base_ref...HEAD`

      - uses: ./.github/actions/nyctos
        with:
          ui-url: https://nyx.example.internal
          gh-token: ${{ github.token }}
```

`fetch-depth: 0` is load-bearing: the scan computes
`git diff --name-only --diff-filter=AMR <base_ref>...HEAD` to drive
`--since-ref`, and the default shallow clone leaves the base ref
unreachable. Set `fetch-depth: 0` or pass `--no-shallow` to your
custom checkout step.

## `nyctos.toml` shape

Point the repo config at the PR checkout via `local-path` source:

```toml
[general]
log_level = "info"

[[repo]]
name        = "self"
i_own_this  = true
enabled     = true
source = { kind = "local-path", path = "." }
```

When the action runs from `$GITHUB_WORKSPACE`, the agent ingests the
checkout (`Phase 05` snapshot path), runs the static scan, and
proceeds through the AI passes if `[ai]` is configured with a key
from the runner's secrets store.

## Secrets handling

The `gh-token` input is consumed via the `GITHUB_TOKEN` environment
variable. It is **never** placed on argv and **never** echoed to
logs:

* The CLI reads the value from `$GITHUB_TOKEN` only when the
  `pr-comment` step runs, then forwards it via the `Authorization`
  header set on the `reqwest::Client` (with `set_sensitive(true)` so
  the `tracing` HTTP middleware does not log it).
* Anthropic / Claude Code keys (if you enable the AI passes) are read
  from `keyring` on the operator host or from `NYX_*` env vars per
  the Phase 09 secrets layout - not via this Action's inputs.

## Dedup contract

Re-running the workflow against the same PR (e.g. after a push) is a
**replace, not append** operation:

1. The `pr-comment` step `GET /repos/{owner}/{repo}/issues/{pr}/comments`
   and walks the result looking for the marker.
2. If found, the existing comment is updated via `PATCH
   /repos/{owner}/{repo}/issues/comments/{id}`.
3. If not found, a new comment is created.

This means the comment surface is bounded by the number of distinct
markers we ship. Right now there is exactly one
(`<!-- nyctos:pr-comment v1 -->`). Schema bumps will mint a new
marker so the older one becomes invisible to the new binary and a
fresh comment lands - giving operators a clean swap rather than an
update that mixes old and new shape.

## What lands on the PR vs. the local UI

| Where | Status |
|---|---|
| PR comment | `Verified` (Confirmed by Phase 19 verifier), or chain member where the chain has `cross_repo = true`. |
| Local UI only | Everything else: `Open` (static-pass only, unverified), `Quarantine` (AI-proposed, awaiting verifier), `Closed` (verifier rejected), `Inconclusive` (static pass timeouts / spec derivation failures). |

This split keeps the PR conversation focused on the high-signal rows
the verifier confirmed; the noisier static surface stays where
operators triage it, not where reviewers see it.

## Report JSON schema

The intermediate `report.json` is the only file the `pr-comment` step
reads. Its shape (`schema_version = 1`):

```json
{
  "schema_version": 1,
  "run_id": "...",
  "started_at": 1700000000000,
  "finished_at": 1700000010000,
  "status": "Succeeded",
  "triggered_by": "Manual",
  "repos": ["self"],
  "since_ref": "main",
  "findings": [
    {
      "id": "...",
      "repo": "self",
      "path": "src/handler.py",
      "line": 42,
      "cap": "sqli",
      "rule": "py.sqli.untainted-format-string",
      "severity": "High",
      "status": "Verified",
      "finding_origin": "Static",
      "chain_id": null
    }
  ],
  "chains": [
    {
      "id": "...",
      "cross_repo": true,
      "member_ids": ["...", "..."],
      "rationale": "controller-in-repo-A reaches sink-in-repo-B"
    }
  ]
}
```

External dashboards (Slack, JIRA, custom triage tools) can consume
this directly without re-running the scan; pass `--output` alone
(without `pr-comment`) to use the file as a JSON artefact.

## Diagnosing failures

* **`scan: \`git diff base_ref...HEAD\` ... failed`** - the base ref
  is not reachable. Set `fetch-depth: 0` on the checkout step.
* **`pr-comment: env var \`GITHUB_TOKEN\` is empty or unset`** -
  `gh-token` was not passed, or the workflow's `permissions:` block
  omits `pull-requests: write`.
* **`pr-comment: github api error: create comment returned 403`** -
  same as above; the token can read but not write the PR. Confirm
  the workflow has `permissions: pull-requests: write` and that the
  PR is not from a fork (`pull_request_target` is the standard
  recipe for fork-aware bot comments).
* **PR comment was not posted but the step succeeded** - the report
  contained no Confirmed or cross-repo chain findings. Open the
  operator's local UI to triage `Open` / `Quarantine` rows; only
  high-signal rows land on the PR by design.

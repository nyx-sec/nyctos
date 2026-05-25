#!/usr/bin/env node
/**
 * Capture fresh README screenshots from the current Nyctos frontend.
 *
 * The script serves the real React app, mocks the daemon API with a small
 * seeded pentest, captures raw frames, then frames the stills and builds a
 * paced demo GIF. It prefers the release bundle in frontend/dist and falls
 * back to the Vite dev server when dist is missing.
 */
import { execFileSync, spawn } from "node:child_process";
import {
  copyFileSync,
  mkdirSync,
  rmSync,
  statSync,
} from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { chromium } from "playwright";

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const OUT_DIR = join(ROOT, "assets", "screenshots");
const DOCS_OUT_DIR = join(ROOT, "docs", "assets", "screenshots");
const RAW_DIR = join(OUT_DIR, "raw");
const GIF_RAW_DIR = join(RAW_DIR, "gif");
const FRAMER = join(ROOT, "scripts", "frame-screenshots.py");
const PORT = Number(process.env.NYCTOS_SCREENSHOT_PORT ?? 4197);
const GIF_FRAME_MS = Number(process.env.NYCTOS_GIF_FRAME_MS ?? 1900);
const BASE_URL = `http://127.0.0.1:${PORT}`;
const VIEW = { width: 1600, height: 992 };
const PROJECT_ID = "proj-checkout";
const RUN_ID = "run-local-attack";
const DONE_RUN_ID = "run-baseline";
const BASE_TS = Date.now();

const args = new Set(process.argv.slice(2));
const wantAll = args.has("--all") || args.size === 0;
const wantStills = wantAll || args.has("--stills");
const wantGif = wantAll || args.has("--gif");

if (!wantStills && !wantGif) {
  console.error("usage: node scripts/capture-screenshots.mjs [--stills|--gif|--all]");
  process.exit(2);
}

const launchProfile = {
  id: "launch-default",
  project_id: PROJECT_ID,
  name: "default",
  mode: "managed",
  build_steps: [{ command: "npm ci", repo_name: "web", timeout_seconds: 120 }],
  start_steps: [{ command: "npm run dev", repo_name: "web", timeout_seconds: 60 }],
  seed_steps: [{ command: "npm run db:seed", repo_name: "api", timeout_seconds: 30 }],
  reset_steps: [{ command: "npm run db:reset", repo_name: "api", timeout_seconds: 45 }],
  login_steps: [],
  stop_steps: [],
  health_checks: [
    {
      kind: "http",
      url: "http://127.0.0.1:3000/health",
      timeout_seconds: 15,
    },
  ],
  target_urls: ["http://127.0.0.1:3000"],
  env_refs: [{ kind: "env-file", value: ".env.local", secret: false }],
  working_dirs: [
    { repo_name: "web", path: "/Users/you/work/checkout/web" },
    { repo_name: "api", path: "/Users/you/work/checkout/api" },
  ],
  readiness: "Ready",
  created_at: BASE_TS - 86_400_000,
  updated_at: BASE_TS - 180_000,
  is_default: true,
};

const project = {
  id: PROJECT_ID,
  name: "checkout-service",
  description: "Local checkout, billing, and account portal",
  target_base_url: "http://127.0.0.1:3000",
  env_config_json: null,
  runtime_profile: null,
  default_launch_profile: launchProfile,
  created_at: BASE_TS - 86_400_000,
  updated_at: BASE_TS - 120_000,
};

const repos = [
  repo("repo-web", "web", "local-path", "/Users/you/work/checkout/web", "main", RUN_ID),
  repo("repo-api", "api", "local-path", "/Users/you/work/checkout/api", "main", RUN_ID),
  repo("repo-jobs", "jobs", "local-path", "/Users/you/work/checkout/jobs", "main", DONE_RUN_ID),
];

const runningRun = {
  id: RUN_ID,
  project_id: PROJECT_ID,
  kind: "Pentest",
  started_at: BASE_TS - 92_000,
  finished_at: null,
  status: "Running",
  triggered_by: "manual",
  git_ref: "main@9f12c4a",
  parent_run_id: DONE_RUN_ID,
  wall_clock_ms: null,
  total_ai_spend_usd_micros: 118000,
};

const doneRun = {
  id: DONE_RUN_ID,
  project_id: PROJECT_ID,
  kind: "Pentest",
  started_at: BASE_TS - 3_600_000,
  finished_at: BASE_TS - 3_540_000,
  status: "Succeeded",
  triggered_by: "manual",
  git_ref: "main@6a13ee1",
  parent_run_id: null,
  wall_clock_ms: 60121,
  total_ai_spend_usd_micros: 74000,
};

const vulnerabilities = [
  vuln({
    id: "vuln-cart-price-tamper",
    title: "Checkout total can be lowered before payment intent creation",
    severity: "Critical",
    risk_score: 9.8,
    risk_rating: "Critical",
    vuln_class: "business-logic",
    evidence_summary:
      "The live verifier changed the cart total client side, submitted checkout, and received a payment intent for the lower amount while the order kept the original items.",
    business_impact:
      "An authenticated buyer can underpay for physical goods without needing admin access.",
    repro_steps:
      "1. Sign in as buyer@example.test\n2. Add SKU pro-plan-annual to the cart\n3. Change total_cents from 240000 to 2400 before POST /api/checkout\n4. Submit checkout and inspect the created payment intent",
    remediation:
      "Calculate totals on the server from trusted product records and reject client supplied totals.",
    affected_components: [
      { repo: "api", route: "POST /api/checkout", file: "src/routes/checkout.ts:88" },
      { repo: "web", route: "/checkout", file: "src/pages/Checkout.tsx:214" },
    ],
    source_candidate_ids: ["cand-price-tamper"],
    source_signal_ids: ["sig-client-total", "sig-payment-intent"],
    verification_attempt_ids: ["attempt-price-tamper"],
    chain_id: "chain-checkout-total",
    status: "Open",
    confidence: 0.98,
  }),
  vuln({
    id: "vuln-admin-id-grid",
    title: "Project invoice export ignores tenant ownership",
    severity: "High",
    risk_score: 8.7,
    risk_rating: "High",
    vuln_class: "idor",
    evidence_summary:
      "A user session for tenant alpha exported tenant beta invoices by changing the project_id query parameter.",
    business_impact:
      "Customer billing data can be pulled across tenants by any signed-in user who can guess an id.",
    repro_steps:
      "1. Sign in as alpha.owner@example.test\n2. Request GET /api/projects/beta/invoices/export\n3. Observe the CSV response contains beta invoice rows",
    remediation:
      "Authorize the project id against the current principal before building the export job.",
    affected_components: [
      { repo: "api", route: "GET /api/projects/:id/invoices/export", file: "src/routes/export.ts:44" },
    ],
    source_candidate_ids: ["cand-export-idor"],
    source_signal_ids: ["sig-project-route"],
    verification_attempt_ids: ["attempt-export-idor"],
    chain_id: "chain-tenant-export",
    status: "Open",
    confidence: 0.94,
  }),
  vuln({
    id: "vuln-reset-token-reuse",
    title: "Password reset token remains valid after first use",
    severity: "Medium",
    risk_score: 6.4,
    risk_rating: "Medium",
    vuln_class: "auth-token",
    evidence_summary:
      "The browser workflow used the same reset token twice and received two successful password-change responses.",
    business_impact:
      "A captured reset link can be replayed after the account owner has already recovered access.",
    repro_steps:
      "1. Request a password reset\n2. Use the token once through /reset-password\n3. Submit the same token again with a new password",
    remediation:
      "Mark reset tokens consumed inside the same transaction that changes the password.",
    affected_components: [
      { repo: "api", route: "POST /api/auth/reset-password", file: "src/auth/reset.ts:117" },
    ],
    source_candidate_ids: ["cand-reset-replay"],
    source_signal_ids: ["sig-reset-token"],
    verification_attempt_ids: ["attempt-reset-replay"],
    status: "InProgress",
    confidence: 0.86,
  }),
];

const candidates = [
  candidate({
    id: "cand-price-tamper",
    title: "Client supplied checkout total reaches payment intent",
    vuln_class: "business-logic",
    severity_guess: "Critical",
    status: "Confirmed",
    confidence: 0.97,
    source_ids: ["sig-client-total", "sig-payment-intent"],
    affected_components: [{ route: "POST /api/checkout", repo: "api" }],
    test_plan: {
      kind: "browser_workflow",
      path: "/checkout",
      why_this_confirms: "A lower payment intent proves the server trusted the client total.",
    },
  }),
  candidate({
    id: "cand-export-idor",
    title: "Invoice export accepts another tenant id",
    vuln_class: "idor",
    severity_guess: "High",
    status: "Confirmed",
    confidence: 0.93,
    source_ids: ["sig-project-route"],
    affected_components: [{ route: "GET /api/projects/:id/invoices/export", repo: "api" }],
    test_plan: {
      kind: "differential_http",
      path: "/api/projects/beta/invoices/export",
      why_this_confirms: "Alpha and beta sessions should not receive the same beta export.",
    },
  }),
  candidate({
    id: "cand-reset-replay",
    title: "Password reset token replay",
    vuln_class: "auth-token",
    severity_guess: "Medium",
    status: "NeedsReview",
    confidence: 0.79,
    source_ids: ["sig-reset-token"],
    affected_components: [{ route: "POST /api/auth/reset-password", repo: "api" }],
    test_plan: {
      kind: "http_workflow",
      path: "/api/auth/reset-password",
      why_this_confirms: "Second use of the same token should fail.",
    },
  }),
];

const attempts = [
  attempt({
    id: "attempt-price-tamper",
    candidate_id: "cand-price-tamper",
    method: "browser_workflow",
    status: "Confirmed",
    duration_ms: 4210,
    oracle: { baseline_clean: true, benign_clean: true, vuln_success: true, actual_status: 200 },
    response: { status: 200, payment_intent_total: 2400 },
    artifact_paths: [
      "/state/runs/run-local-attack/browser/checkout-total-before.png",
      "/state/runs/run-local-attack/browser/payment-intent-after.json",
    ],
  }),
  attempt({
    id: "attempt-export-idor",
    candidate_id: "cand-export-idor",
    method: "differential_http",
    status: "Confirmed",
    duration_ms: 1180,
    oracle: { baseline_clean: true, benign_clean: true, vuln_success: true, actual_status: 200 },
    response: { status: 200, rows: 47 },
    artifact_paths: ["/state/runs/run-local-attack/http/export-beta.csv"],
  }),
  attempt({
    id: "attempt-reset-replay",
    candidate_id: "cand-reset-replay",
    method: "http_workflow",
    status: "NeedsReview",
    duration_ms: 980,
    oracle: { baseline_clean: true, benign_clean: true, vuln_success: false, actual_status: 200 },
    response: { status: 200 },
    artifact_paths: ["/state/runs/run-local-attack/http/reset-replay.har"],
  }),
];

const integrations = [
  {
    id: "int-slack",
    project_id: PROJECT_ID,
    kind: "slack",
    name: "Security triage",
    enabled: true,
    events: ["run_finished", "finding_verified"],
    min_severity: "High",
    target: "#security-triage",
    created_at: BASE_TS - 1_000_000,
    updated_at: BASE_TS - 100_000,
    last_delivery_at: BASE_TS - 50_000,
    last_delivery_status: "delivered",
  },
  {
    id: "int-webhook",
    project_id: PROJECT_ID,
    kind: "webhook",
    name: "Jira intake",
    enabled: false,
    events: ["finding_verified"],
    min_severity: "Medium",
    target: "https://jira.example.test/hooks/nyctos",
    created_at: BASE_TS - 1_000_000,
    updated_at: BASE_TS - 100_000,
  },
];

const environmentRuns = [
  {
    id: "env-run-1",
    run_id: RUN_ID,
    project_id: PROJECT_ID,
    profile_id: "launch-default",
    status: "Ready",
    started_at: BASE_TS - 91_000,
    ready_at: BASE_TS - 86_000,
    stopped_at: null,
    target_urls: ["http://127.0.0.1:3000"],
    health: { status: 200, path: "/health" },
    logs_dir: "/state/runs/run-local-attack/env",
    teardown: null,
  },
];

function repo(id, name, source_kind, source_url_or_path, branch, last_scan_run_id) {
  return {
    id,
    name,
    project_id: PROJECT_ID,
    source_kind,
    source_url_or_path,
    branch,
    auth_ref: null,
    i_own_this: true,
    last_scan_run_id,
    last_scan_finished_at: last_scan_run_id === DONE_RUN_ID ? BASE_TS - 3_540_000 : null,
    created_at: BASE_TS - 86_400_000,
    updated_at: BASE_TS - 180_000,
  };
}

function vuln(input) {
  return {
    run_id: RUN_ID,
    project_id: PROJECT_ID,
    first_seen: BASE_TS - 60_000,
    last_seen: BASE_TS - 30_000,
    risk_score_source: "live-verifier",
    risk_score_rationale: "Live exploit proof, reachable authenticated workflow, direct business impact.",
    ...input,
  };
}

function candidate(input) {
  return {
    ...input,
    run_id: RUN_ID,
    project_id: PROJECT_ID,
    source: "exploration",
    hypothesis: input.title,
    rejection_reason: null,
    trace_id: `trace-${input.id}`,
    created_at: BASE_TS - 72_000,
    updated_at: BASE_TS - 28_000,
    test_plan: JSON.stringify(input.test_plan),
  };
}

function attempt(input) {
  return {
    run_id: RUN_ID,
    project_id: PROJECT_ID,
    environment_run_id: "env-run-1",
    chain_id: undefined,
    started_at: BASE_TS - 35_000,
    finished_at: BASE_TS - 30_000,
    replay_stable: true,
    error: null,
    request: { target: "http://127.0.0.1:3000" },
    ...input,
  };
}

async function main() {
  cleanScreenshots();
  const server = await startUiServer();
  let browser;
  try {
    browser = await chromium.launch({ headless: true });
    const context = await browser.newContext({
      viewport: VIEW,
      deviceScaleFactor: 1,
      reducedMotion: "reduce",
      colorScheme: "light",
    });
    await context.addInitScript(() => {
      window.localStorage.setItem("nyctos.communityEditionNoticeDismissed", "1");
    });
    await installMockWebSocket(context);

    if (wantStills) {
      await captureStills(context);
    }
    if (wantGif) {
      await captureGifFrames(context);
    }

    frameOutputs();
  } finally {
    if (browser) await browser.close();
    server.kill("SIGTERM");
  }
}

function cleanScreenshots() {
  rmSync(OUT_DIR, { recursive: true, force: true });
  rmSync(DOCS_OUT_DIR, { recursive: true, force: true });
  mkdirSync(RAW_DIR, { recursive: true });
  mkdirSync(GIF_RAW_DIR, { recursive: true });
  mkdirSync(DOCS_OUT_DIR, { recursive: true });
}

async function startUiServer() {
  const mode = chooseServerMode();
  const script = mode === "preview" ? "preview" : "dev";
  const child = spawn(
    "npm",
    [
      "--prefix",
      "frontend",
      "run",
      script,
      "--",
      "--host",
      "127.0.0.1",
      "--port",
      String(PORT),
      "--strictPort",
    ],
    {
      cwd: ROOT,
      stdio: ["ignore", "pipe", "pipe"],
      env: { ...process.env, BROWSER: "none" },
    },
  );

  let output = "";
  child.stdout.on("data", (chunk) => {
    output += chunk.toString();
  });
  child.stderr.on("data", (chunk) => {
    output += chunk.toString();
  });

  const deadline = Date.now() + 30_000;
  while (Date.now() < deadline) {
    if (child.exitCode !== null) {
      throw new Error(`vite ${script} exited early:\n${output}`);
    }
    try {
      const res = await fetch(BASE_URL);
      if (res.ok) return child;
    } catch {
      await sleep(250);
    }
  }
  child.kill("SIGTERM");
  throw new Error(`vite ${script} did not start at ${BASE_URL}:\n${output}`);
}

function chooseServerMode() {
  const requested = process.env.NYCTOS_SCREENSHOT_SERVER;
  if (requested === "dev" || requested === "preview") return requested;
  return exists(join(ROOT, "frontend", "dist", "index.html")) ? "preview" : "dev";
}

function exists(path) {
  try {
    statSync(path);
    return true;
  } catch {
    return false;
  }
}

async function captureStills(context) {
  const page = await newMockedPage(context);
  await goto(page, `/projects/${PROJECT_ID}`);
  await page.waitForTimeout(2300);
  await screenshot(page, "project-workspace");

  await goto(page, `/projects/${PROJECT_ID}/runs/${RUN_ID}`);
  await page.waitForTimeout(2600);
  await screenshot(page, "live-pentest");

  await goto(page, `/projects/${PROJECT_ID}/vulnerabilities`);
  await screenshot(page, "verified-vulnerabilities");

  await openFirstVulnerability(page);
  await screenshot(page, "vulnerability-detail");
  await page.close();
}

async function captureGifFrames(context) {
  const page = await newMockedPage(context);
  const frames = [];

  await goto(page, `/projects/${PROJECT_ID}`);
  frames.push(await gifFrame(page, "00-project"));

  await page.getByRole("button", { name: "Start pentest" }).click();
  await page.waitForSelector(".modal", { state: "visible" });
  frames.push(await gifFrame(page, "01-options"));

  await page.getByLabel("Browser verification", { exact: false }).check();
  await page.getByLabel("Unsafe attack agent", { exact: false }).check();
  await page.getByLabel("Exploit mode", { exact: false }).check();
  await page.getByLabel("State-changing probes", { exact: false }).check();
  frames.push(await gifFrame(page, "02-unsafe"));

  await page.getByRole("button", { name: "Start invasive attack run" }).click();
  await page.waitForURL(`${BASE_URL}/projects/${PROJECT_ID}/runs/${RUN_ID}`);
  await page.waitForTimeout(1600);
  frames.push(await gifFrame(page, "03-live"));

  await page.waitForTimeout(2700);
  frames.push(await gifFrame(page, "04-finished"));

  await goto(page, `/projects/${PROJECT_ID}/vulnerabilities`);
  frames.push(await gifFrame(page, "05-vulnerabilities"));

  await openFirstVulnerability(page);
  frames.push(await gifFrame(page, "06-detail"));

  await page.close();
  execFileSync(
    "python3",
    [
      FRAMER,
      "--gif",
      "--duration-ms",
      String(GIF_FRAME_MS),
      join(OUT_DIR, "demo.gif"),
      ...frames,
    ],
    {
      cwd: ROOT,
      stdio: "inherit",
    },
  );
}

async function newMockedPage(context) {
  const page = await context.newPage();
  page.setDefaultTimeout(15_000);
  await page.route("**/api/v1/**", routeApi);
  return page;
}

async function goto(page, path) {
  await page.goto(`${BASE_URL}${path}`, { waitUntil: "domcontentloaded" });
  await page.waitForLoadState("networkidle").catch(() => {});
  await page.waitForTimeout(500);
}

async function screenshot(page, name) {
  const path = join(RAW_DIR, `${name}.png`);
  await page.screenshot({ path, fullPage: false });
  return path;
}

async function gifFrame(page, name) {
  const path = join(GIF_RAW_DIR, `${name}.png`);
  await page.screenshot({ path, fullPage: false });
  return path;
}

async function openFirstVulnerability(page) {
  await Promise.all([
    page.waitForURL(new RegExp(`/vulnerabilities/${vulnerabilities[0].id}`)),
    page.getByText("Checkout total can be lowered", { exact: false }).click(),
  ]);
  await page.waitForLoadState("networkidle").catch(() => {});
  await page.waitForTimeout(500);
}

function frameOutputs() {
  if (wantStills) {
    execFileSync("python3", [FRAMER, "--defaults"], { cwd: ROOT, stdio: "inherit" });
    copyFileSync(
      join(OUT_DIR, "verified-vulnerabilities.png"),
      join(DOCS_OUT_DIR, "verified-vulnerabilities.png"),
    );
  }
}

async function routeApi(route) {
  const request = route.request();
  const url = new URL(request.url());
  const path = url.pathname.replace(/^\/api\/v1/, "");
  const method = request.method();

  if (method === "POST" && path === `/projects/${PROJECT_ID}/pentest`) {
    return json(route, { run_id: RUN_ID });
  }
  if (path === "/setup/status") return json(route, setupStatus());
  if (path === "/projects") return json(route, [project]);
  if (path === `/projects/${PROJECT_ID}`) return json(route, project);
  if (path === `/projects/${PROJECT_ID}/repos`) return json(route, repos);
  if (path === `/projects/${PROJECT_ID}/vulnerabilities`) return json(route, vulnerabilities);
  if (path === `/projects/${PROJECT_ID}/integrations`) return json(route, integrations);
  if (path === "/runs") return json(route, runsFor(url.searchParams));
  if (path === `/runs/${RUN_ID}`) return json(route, runningRun);
  if (path === `/runs/${DONE_RUN_ID}`) return json(route, doneRun);
  if (path === `/runs/${RUN_ID}/environment-runs`) return json(route, environmentRuns);
  if (path === `/runs/${RUN_ID}/vulnerabilities`) return json(route, vulnerabilities);
  if (path === `/runs/${RUN_ID}/candidates`) return json(route, candidates);
  if (path === `/runs/${RUN_ID}/verification-attempts`) return json(route, attempts);
  if (path === "/vulnerabilities") return json(route, vulnerabilities);
  const vulnerabilityMatch = path.match(/^\/vulnerabilities\/([^/]+)$/);
  if (vulnerabilityMatch) {
    const found = vulnerabilities.find((row) => row.id === decodeURIComponent(vulnerabilityMatch[1]));
    return found
      ? json(route, found)
      : route.fulfill({
          status: 404,
          contentType: "application/json",
          body: JSON.stringify({
            error: { code: "mock_missing", message: `No vulnerability ${vulnerabilityMatch[1]}` },
          }),
        });
  }
  if (path === `/runs/${RUN_ID}/events.jsonl`) {
    return route.fulfill({
      status: 200,
      contentType: "text/plain",
      body: "demo event log\n",
    });
  }

  return route.fulfill({
    status: 404,
    contentType: "application/json",
    body: JSON.stringify({ error: { code: "mock_missing", message: `No mock for ${path}` } }),
  });
}

function setupStatus() {
  return {
    complete: true,
    config_path: "/Users/you/.config/nyctos/nyctos.toml",
    ai_runtime: "codex",
    ai_provider: "codex",
    ai_model: "gpt-5",
    default_run_budget_usd_micros: 250000,
    sandbox_backend: "process",
    sandbox_enabled: true,
    sandbox_allow_network: false,
    ui_listen_addr: "127.0.0.1:8765",
    ui_open_browser: true,
    log_level: "info",
    state_dir: "/Users/you/Library/Application Support/nyctos",
    max_parallel_scans: 2,
    scan_timeout_secs: 600,
  };
}

function runsFor(params) {
  const status = params.get("status");
  const projectId = params.get("project_id");
  if (projectId && projectId !== PROJECT_ID) return [];
  if (status === "Running") return [runningRun];
  if (status === "Succeeded") return [doneRun];
  if (status === "Failed") return [];
  return [runningRun, doneRun];
}

function json(route, value) {
  return route.fulfill({
    status: 200,
    contentType: "application/json",
    body: JSON.stringify(value),
  });
}

async function installMockWebSocket(context) {
  await context.addInitScript(
    ({ runId, projectId, baseTs }) => {
      const NativeWebSocket = window.WebSocket;
      class MockNyctosWebSocket extends EventTarget {
        constructor(url, protocols) {
          super();
          const rawUrl = String(url);
          if (!rawUrl.includes("/api/v1/events")) {
            return new NativeWebSocket(url, protocols);
          }
          this.url = rawUrl;
          this.protocol = "";
          this.extensions = "";
          this.bufferedAmount = 0;
          this.binaryType = "blob";
          this.readyState = 0;
          setTimeout(() => {
            this.readyState = 1;
            this._dispatch("open", new Event("open"));
            const requested = new URL(rawUrl).searchParams.get("run_id");
            this._play(requested || runId);
          }, 40);
        }

        send() {}

        close() {
          this.readyState = 3;
          this._dispatch("close", new CloseEvent("close"));
        }

        _play(activeRunId) {
          for (const [delay, payload] of eventSequence(activeRunId, projectId, baseTs)) {
            setTimeout(() => {
              if (this.readyState !== 1) return;
              this._dispatch("message", new MessageEvent("message", { data: JSON.stringify(payload) }));
            }, delay);
          }
        }

        _dispatch(name, event) {
          const handler = this[`on${name}`];
          if (typeof handler === "function") handler.call(this, event);
          this.dispatchEvent(event);
        }
      }
      MockNyctosWebSocket.CONNECTING = 0;
      MockNyctosWebSocket.OPEN = 1;
      MockNyctosWebSocket.CLOSING = 2;
      MockNyctosWebSocket.CLOSED = 3;
      window.WebSocket = MockNyctosWebSocket;

      function eventSequence(activeRunId, activeProjectId, ts) {
        const phase = (delay, name, status, message = null) => [
          delay,
          {
            kind: "Run",
            data:
              status === "start"
                ? {
                    kind: "PhaseStarted",
                    run_id: activeRunId,
                    project_id: activeProjectId,
                    phase: name,
                    started_at_ms: ts + delay,
                  }
                : {
                    kind: "PhaseFinished",
                    run_id: activeRunId,
                    project_id: activeProjectId,
                    phase: name,
                    status,
                    message,
                    finished_at_ms: ts + delay,
                  },
          },
        ];
        return [
          [
            80,
            {
              kind: "Run",
              data: {
                kind: "RunStarted",
                run_id: activeRunId,
                project_id: activeProjectId,
                repos: ["web", "api", "jobs"],
                started_at_ms: ts,
              },
            },
          ],
          [
            180,
            {
              kind: "Run",
              data: {
                kind: "EnvironmentStatus",
                run_id: activeRunId,
                project_id: activeProjectId,
                environment_run_id: "env-run-1",
                status: "Ready",
                message: "Dev app healthy on 127.0.0.1:3000",
                target_urls: ["http://127.0.0.1:3000"],
                ts_ms: ts + 180,
              },
            },
          ],
          [280, repoStarted(activeRunId, activeProjectId, "web", ts + 280)],
          [430, repoStaticDone(activeRunId, activeProjectId, "web", 19, 910)],
          [560, repoFinished(activeRunId, activeProjectId, "web", "Success", 1180)],
          [670, repoStarted(activeRunId, activeProjectId, "api", ts + 670)],
          [850, repoStaticDone(activeRunId, activeProjectId, "api", 31, 1330)],
          [1010, repoFinished(activeRunId, activeProjectId, "api", "Success", 1580)],
          [1080, repoStarted(activeRunId, activeProjectId, "jobs", ts + 1080)],
          [1210, repoStaticDone(activeRunId, activeProjectId, "jobs", 8, 740)],
          [1340, repoFinished(activeRunId, activeProjectId, "jobs", "Success", 910)],
          phase(1450, "RouteModelStarted", "start", null),
          phase(1780, "RouteModelStarted", "Succeeded", "Mapped 27 routes and 8 forms"),
          [
            1940,
            {
              kind: "Run",
              data: {
                kind: "AuthSessionStatus",
                run_id: activeRunId,
                project_id: activeProjectId,
                role: "buyer",
                status: "verified",
                acquired_by: "browser_login",
                message: "Seeded checkout account ready",
                ts_ms: ts + 1940,
              },
            },
          ],
          phase(2080, "LiveVerificationStarted", "start", null),
          phase(2580, "LiveVerificationStarted", "Succeeded", "Confirmed 2 issues"),
          phase(2700, "BrowserVerificationStarted", "start", null),
          phase(3120, "BrowserVerificationStarted", "Succeeded", "Captured checkout proof"),
          phase(3300, "UnsafeAttackAgentStarted", "start", null),
          phase(3900, "UnsafeAttackAgentStarted", "Succeeded", "Promoted one destructive proof"),
          [
            4500,
            {
              kind: "Run",
              data: {
                kind: "RunFinished",
                run_id: activeRunId,
                project_id: activeProjectId,
                finished_at_ms: ts + 4500,
                wall_clock_ms: 64218,
                succeeded: 3,
                inconclusive: 0,
                failed: 0,
              },
            },
          ],
        ];
      }

      function repoStarted(activeRunId, activeProjectId, name, startedAt) {
        return {
          kind: "Run",
          data: {
            kind: "RepoStarted",
            run_id: activeRunId,
            project_id: activeProjectId,
            repo: name,
            started_at_ms: startedAt,
          },
        };
      }

      function repoStaticDone(activeRunId, activeProjectId, name, nDiags, elapsed) {
        return {
          kind: "Run",
          data: {
            kind: "RepoStaticDone",
            run_id: activeRunId,
            project_id: activeProjectId,
            repo: name,
            n_diags: nDiags,
            elapsed_ms: elapsed,
          },
        };
      }

      function repoFinished(activeRunId, activeProjectId, name, outcome, elapsed) {
        return {
          kind: "Run",
          data: {
            kind: "RepoFinished",
            run_id: activeRunId,
            project_id: activeProjectId,
            repo: name,
            outcome,
            elapsed_ms: elapsed,
          },
        };
      }
    },
    { runId: RUN_ID, projectId: PROJECT_ID, baseTs: BASE_TS },
  );
}

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});

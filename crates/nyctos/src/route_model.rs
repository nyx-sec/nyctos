use std::collections::BTreeMap;
use std::path::Path;

use ignore::WalkBuilder;
use nyctos_core::WorkspaceHandle;
use nyctos_types::product::{
    ApiClientCallModel, FrontendRouteModel, RouteEvidence, RouteModel, RouteModelEndpoint,
};
use regex::Regex;

const ROUTE_MODEL_MAX_FILE_BYTES: u64 = 512 * 1024;
const ROUTE_MODEL_MAX_FILES_PER_REPO: usize = 2_000;

pub fn extract_route_model(workspaces: &BTreeMap<String, WorkspaceHandle>) -> RouteModel {
    let mut model = RouteModel::default();
    for (repo, workspace) in workspaces {
        extract_repo_routes(repo, workspace.workspace(), &mut model);
    }
    model
        .backend_routes
        .sort_by(|a, b| (&a.repo, &a.path, &a.method).cmp(&(&b.repo, &b.path, &b.method)));
    model.frontend_routes.sort_by(|a, b| (&a.repo, &a.path).cmp(&(&b.repo, &b.path)));
    model
        .api_client_calls
        .sort_by(|a, b| (&a.repo, &a.path, &a.method).cmp(&(&b.repo, &b.path, &b.method)));
    model
}

fn extract_repo_routes(repo: &str, root: &Path, model: &mut RouteModel) {
    let mut backend: BTreeMap<(String, String, String), RouteModelEndpoint> = BTreeMap::new();
    let mut frontend: BTreeMap<(String, String), FrontendRouteModel> = BTreeMap::new();
    let mut clients: BTreeMap<(String, String, String), ApiClientCallModel> = BTreeMap::new();

    let mut seen_files = 0_usize;
    for entry in WalkBuilder::new(root)
        .hidden(false)
        .git_ignore(true)
        .git_exclude(true)
        .parents(true)
        .build()
        .filter_map(Result::ok)
    {
        if seen_files >= ROUTE_MODEL_MAX_FILES_PER_REPO {
            model.notes.push(format!(
                "route model for {repo} stopped after {ROUTE_MODEL_MAX_FILES_PER_REPO} files"
            ));
            break;
        }
        let path = entry.path();
        if !entry.file_type().is_some_and(|t| t.is_file()) || !is_route_source_file(path) {
            continue;
        }
        let Ok(meta) = entry.metadata() else {
            continue;
        };
        if meta.len() > ROUTE_MODEL_MAX_FILE_BYTES {
            continue;
        }
        let Ok(src) = std::fs::read_to_string(path) else {
            continue;
        };
        seen_files += 1;
        let rel = path.strip_prefix(root).unwrap_or(path).to_string_lossy().replace('\\', "/");
        extract_backend_routes(repo, &rel, &src, &mut backend);
        extract_frontend_routes(repo, &rel, &src, &mut frontend);
        extract_api_client_calls(repo, &rel, &src, &mut clients);
    }

    model.backend_routes.extend(backend.into_values());
    model.frontend_routes.extend(frontend.into_values());
    model.api_client_calls.extend(clients.into_values());
}

fn is_route_source_file(path: &Path) -> bool {
    let Some(ext) = path.extension().and_then(|e| e.to_str()).map(|e| e.to_ascii_lowercase())
    else {
        return false;
    };
    matches!(
        ext.as_str(),
        "js" | "jsx" | "ts" | "tsx" | "mjs" | "cjs" | "py" | "rb" | "go" | "rs" | "php"
    )
}

fn extract_backend_routes(
    repo: &str,
    rel: &str,
    src: &str,
    out: &mut BTreeMap<(String, String, String), RouteModelEndpoint>,
) {
    let express = Regex::new(
        r#"\b(?:app|router|server)\.(get|post|put|patch|delete|head|options)\s*\(\s*["']([^"']+)["']"#,
    )
    .expect("express route regex");
    let decorator = Regex::new(
        r#"@(?:app|router|bp|blueprint)\.(get|post|put|patch|delete|head|options)\s*\(\s*["']([^"']+)["']"#,
    )
    .expect("decorator route regex");
    let route_decorator =
        Regex::new(r#"@(?:app|router|bp|blueprint)\.route\s*\(\s*["']([^"']+)["']([^)]*)\)"#)
            .expect("route decorator regex");

    let lines: Vec<&str> = src.lines().collect();
    for (idx, line) in lines.iter().enumerate() {
        for cap in express.captures_iter(line) {
            push_backend_route(repo, rel, idx, &cap[1], &cap[2], &lines, out);
        }
        for cap in decorator.captures_iter(line) {
            push_backend_route(repo, rel, idx, &cap[1], &cap[2], &lines, out);
        }
        for cap in route_decorator.captures_iter(line) {
            let methods =
                methods_from_route_decorator(cap.get(2).map(|m| m.as_str()).unwrap_or(""));
            for method in methods {
                push_backend_route(repo, rel, idx, &method, &cap[1], &lines, out);
            }
        }
    }
}

fn push_backend_route(
    repo: &str,
    rel: &str,
    idx: usize,
    method: &str,
    path: &str,
    lines: &[&str],
    out: &mut BTreeMap<(String, String, String), RouteModelEndpoint>,
) {
    let method = method.to_ascii_uppercase();
    let path = normalise_route_path(path);
    if path.is_empty() {
        return;
    }
    let key = (repo.to_string(), method.clone(), path.clone());
    out.entry(key).or_insert_with(|| {
        let window = source_window(lines, idx, 12);
        RouteModelEndpoint {
            method: method.clone(),
            path: path.clone(),
            repo: Some(repo.to_string()),
            handler_file: Some(rel.to_string()),
            line: Some((idx + 1) as i64),
            params: route_params(&path),
            middleware: middleware_markers(&window),
            auth_checks: auth_markers(&window),
            role_checks: role_markers(&window),
            body_fields: body_fields(&window),
            state_changing: !matches!(method.as_str(), "GET" | "HEAD" | "OPTIONS"),
            confidence: route_confidence(&window),
            evidence: vec![RouteEvidence {
                path: rel.to_string(),
                line: Some((idx + 1) as i64),
                snippet: lines[idx].trim().chars().take(240).collect(),
            }],
        }
    });
}

fn extract_frontend_routes(
    repo: &str,
    rel: &str,
    src: &str,
    out: &mut BTreeMap<(String, String), FrontendRouteModel>,
) {
    let route_re =
        Regex::new(r#"<Route\b[^>]*\bpath=\{?["']([^"'}]+)["']"#).expect("frontend route regex");
    for (idx, line) in src.lines().enumerate() {
        for cap in route_re.captures_iter(line) {
            let path = normalise_route_path(&cap[1]);
            if path.is_empty() {
                continue;
            }
            out.entry((repo.to_string(), path.clone())).or_insert_with(|| FrontendRouteModel {
                path: path.clone(),
                repo: Some(repo.to_string()),
                file: Some(rel.to_string()),
                line: Some((idx + 1) as i64),
                confidence: 0.8,
                evidence: vec![RouteEvidence {
                    path: rel.to_string(),
                    line: Some((idx + 1) as i64),
                    snippet: line.trim().chars().take(240).collect(),
                }],
            });
        }
    }
}

fn extract_api_client_calls(
    repo: &str,
    rel: &str,
    src: &str,
    out: &mut BTreeMap<(String, String, String), ApiClientCallModel>,
) {
    let fetch_re = Regex::new(r#"\bfetch\s*\(\s*["']([^"']+)["']([^)]*)\)"#).expect("fetch regex");
    let axios_re = Regex::new(
        r#"\b(?:axios|client|api)\.(get|post|put|patch|delete|head|options)\s*\(\s*["']([^"']+)["']"#,
    )
    .expect("axios regex");
    let method_re = Regex::new(r#"\bmethod\s*:\s*["']([A-Za-z]+)["']"#).expect("method regex");
    for (idx, line) in src.lines().enumerate() {
        for cap in fetch_re.captures_iter(line) {
            let path = normalise_route_path(&cap[1]);
            if path.is_empty() || !looks_like_http_path(&path) {
                continue;
            }
            let method = cap
                .get(2)
                .and_then(|tail| method_re.captures(tail.as_str()))
                .map(|c| c[1].to_ascii_uppercase())
                .unwrap_or_else(|| "GET".to_string());
            push_api_client_call(repo, rel, idx, &method, &path, line, out);
        }
        for cap in axios_re.captures_iter(line) {
            let path = normalise_route_path(&cap[2]);
            if path.is_empty() || !looks_like_http_path(&path) {
                continue;
            }
            push_api_client_call(repo, rel, idx, &cap[1].to_ascii_uppercase(), &path, line, out);
        }
    }
}

fn push_api_client_call(
    repo: &str,
    rel: &str,
    idx: usize,
    method: &str,
    path: &str,
    line: &str,
    out: &mut BTreeMap<(String, String, String), ApiClientCallModel>,
) {
    out.entry((repo.to_string(), method.to_string(), path.to_string())).or_insert_with(|| {
        ApiClientCallModel {
            method: method.to_string(),
            path: path.to_string(),
            repo: Some(repo.to_string()),
            file: Some(rel.to_string()),
            line: Some((idx + 1) as i64),
            confidence: 0.75,
            evidence: vec![RouteEvidence {
                path: rel.to_string(),
                line: Some((idx + 1) as i64),
                snippet: line.trim().chars().take(240).collect(),
            }],
        }
    });
}

fn methods_from_route_decorator(raw: &str) -> Vec<String> {
    let method_re = Regex::new(r#"["']([A-Za-z]+)["']"#).expect("method list regex");
    let out: Vec<String> = method_re
        .captures_iter(raw)
        .filter_map(|cap| {
            let method = cap[1].to_ascii_uppercase();
            matches!(
                method.as_str(),
                "GET" | "POST" | "PUT" | "PATCH" | "DELETE" | "HEAD" | "OPTIONS"
            )
            .then_some(method)
        })
        .collect();
    if out.is_empty() {
        vec!["GET".to_string()]
    } else {
        out
    }
}

fn source_window(lines: &[&str], idx: usize, radius: usize) -> String {
    let start = idx.saturating_sub(radius);
    let end = (idx + radius + 1).min(lines.len());
    lines[start..end].join("\n")
}

fn normalise_route_path(raw: &str) -> String {
    let trimmed = raw.trim();
    if trimmed.starts_with("http://") || trimmed.starts_with("https://") {
        return reqwest::Url::parse(trimmed)
            .map(|u| {
                let mut path = u.path().to_string();
                if let Some(q) = u.query() {
                    path.push('?');
                    path.push_str(q);
                }
                path
            })
            .unwrap_or_default();
    }
    if trimmed.is_empty() {
        String::new()
    } else if trimmed.starts_with('/') {
        trimmed.to_string()
    } else {
        format!("/{trimmed}")
    }
}

fn looks_like_http_path(path: &str) -> bool {
    path.starts_with("/api/") || path.starts_with("/auth/") || path.starts_with("/admin/")
}

fn route_params(path: &str) -> Vec<String> {
    let colon = Regex::new(r#":([A-Za-z_][A-Za-z0-9_]*)"#).expect("colon params regex");
    let bracket = Regex::new(r#"<([A-Za-z_][A-Za-z0-9_]*)>"#).expect("bracket params regex");
    let mut params: Vec<String> = colon.captures_iter(path).map(|c| c[1].to_string()).collect();
    params.extend(bracket.captures_iter(path).map(|c| c[1].to_string()));
    params.sort();
    params.dedup();
    params
}

fn auth_markers(window: &str) -> Vec<String> {
    let lower = window.to_ascii_lowercase();
    let mut out = Vec::new();
    for marker in ["requireauth", "authenticate", "isauthenticated", "jwt", "session", "csrf"] {
        if lower.contains(marker) {
            out.push(marker.to_string());
        }
    }
    out
}

fn middleware_markers(window: &str) -> Vec<String> {
    let re = Regex::new(r#"\b(requireAuth|authenticate|authorize|csrf|rateLimit|guard)\b"#)
        .expect("middleware regex");
    let mut out: Vec<String> = re.captures_iter(window).map(|c| c[1].to_string()).collect();
    out.sort();
    out.dedup();
    out
}

fn role_markers(window: &str) -> Vec<String> {
    let re = Regex::new(
        r#"(?i)(?:role|roles|permission|permissions|authorize|requireRole)\s*(?:[=:,(]|\bin\b)\s*["']?([A-Za-z0-9_:-]+)"#,
    )
    .expect("role regex");
    let mut out: Vec<String> = re.captures_iter(window).map(|c| c[1].to_string()).collect();
    out.sort();
    out.dedup();
    out
}

fn body_fields(window: &str) -> Vec<String> {
    let dot =
        Regex::new(r#"\b(?:req|request)\.body\.([A-Za-z_][A-Za-z0-9_]*)"#).expect("body dot regex");
    let bracket = Regex::new(r#"\bbody\s*\[\s*["']([A-Za-z_][A-Za-z0-9_]*)["']\s*\]"#)
        .expect("body bracket regex");
    let mut out: Vec<String> = dot.captures_iter(window).map(|c| c[1].to_string()).collect();
    out.extend(bracket.captures_iter(window).map(|c| c[1].to_string()));
    out.sort();
    out.dedup();
    out
}

fn route_confidence(window: &str) -> f64 {
    let mut confidence = 0.68;
    if !auth_markers(window).is_empty() {
        confidence += 0.08;
    }
    if !body_fields(window).is_empty() {
        confidence += 0.06;
    }
    confidence
}

pub fn route_model_summary(model: &RouteModel) -> String {
    format!(
        "{} backend route(s), {} frontend route(s), {} API client call(s)",
        model.backend_routes.len(),
        model.frontend_routes.len(),
        model.api_client_calls.len()
    )
}

pub fn compact_route_model_for_prompt(model: &RouteModel, max_routes: usize) -> String {
    let mut lines = Vec::new();
    lines.push(route_model_summary(model));
    for route in model.backend_routes.iter().take(max_routes) {
        let auth = if route.auth_checks.is_empty() {
            "auth:unknown".to_string()
        } else {
            format!("auth:{}", route.auth_checks.join(","))
        };
        let roles = if route.role_checks.is_empty() {
            String::new()
        } else {
            format!(" roles:{}", route.role_checks.join(","))
        };
        lines.push(format!(
            "{} {} {}{} file:{}:{}",
            route.method,
            route.path,
            auth,
            roles,
            route.handler_file.as_deref().unwrap_or("?"),
            route.line.map(|l| l.to_string()).unwrap_or_else(|| "?".to_string())
        ));
    }
    lines.join("\n")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracts_express_routes_and_api_clients() {
        let tmp = tempfile::tempdir().unwrap();
        let app = tmp.path().join("app.js");
        std::fs::write(
            &app,
            r#"
const express = require("express");
router.get("/api/accounts/:id", requireAuth, (req, res) => res.json({ id: req.params.id }));
router.post("/api/accounts/:id/transfer", requireAuth, requireRole("admin"), (req, res) => {
  const amount = req.body.amount;
  res.json({ amount });
});
fetch("/api/accounts/123", { method: "GET" });
"#,
        )
        .unwrap();
        let mut workspaces = BTreeMap::new();
        workspaces.insert(
            "api".to_string(),
            WorkspaceHandle::for_local_path_test("api", tmp.path().to_path_buf()),
        );

        let model = extract_route_model(&workspaces);
        assert_eq!(model.backend_routes.len(), 2);
        let transfer = model
            .backend_routes
            .iter()
            .find(|r| r.path == "/api/accounts/:id/transfer")
            .expect("transfer route");
        assert_eq!(transfer.method, "POST");
        assert!(transfer.state_changing);
        assert!(transfer.auth_checks.iter().any(|m| m == "requireauth"));
        assert!(transfer.role_checks.iter().any(|m| m == "admin"));
        assert!(transfer.body_fields.iter().any(|f| f == "amount"));
        assert_eq!(model.api_client_calls.len(), 1);
    }

    #[test]
    fn extracts_fastapi_and_frontend_routes() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::write(
            tmp.path().join("main.py"),
            r#"
@app.get("/api/me")
def me():
    return current_user()

@app.route("/api/session", methods=["POST"])
def login():
    password = body["password"]
"#,
        )
        .unwrap();
        std::fs::write(
            tmp.path().join("routes.tsx"),
            r#"<Routes><Route path="/admin/users" element={<Users />} /></Routes>"#,
        )
        .unwrap();
        let mut workspaces = BTreeMap::new();
        workspaces.insert(
            "web".to_string(),
            WorkspaceHandle::for_local_path_test("web", tmp.path().to_path_buf()),
        );

        let model = extract_route_model(&workspaces);
        assert!(model.backend_routes.iter().any(|r| r.method == "GET" && r.path == "/api/me"));
        assert!(model
            .backend_routes
            .iter()
            .any(|r| r.method == "POST" && r.path == "/api/session"));
        assert!(model.frontend_routes.iter().any(|r| r.path == "/admin/users"));
    }
}

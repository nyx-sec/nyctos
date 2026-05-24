use std::collections::BTreeMap;
use std::path::Path;

use ignore::WalkBuilder;
use nyctos_core::WorkspaceHandle;
use nyctos_types::product::{
    ApiClientCallModel, FormModel, FrontendRouteModel, RouteEvidence, RouteModel,
    RouteModelEndpoint,
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
    model.forms.sort_by(|a, b| {
        (&a.repo, &a.action, &a.method, &a.file, &a.line)
            .cmp(&(&b.repo, &b.action, &b.method, &b.file, &b.line))
    });
    model
}

fn extract_repo_routes(repo: &str, root: &Path, model: &mut RouteModel) {
    let mut backend: BTreeMap<(String, String, String), RouteModelEndpoint> = BTreeMap::new();
    let mut frontend: BTreeMap<(String, String), FrontendRouteModel> = BTreeMap::new();
    let mut clients: BTreeMap<(String, String, String), ApiClientCallModel> = BTreeMap::new();
    let mut forms: BTreeMap<(String, String, String, i64), FormModel> = BTreeMap::new();

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
        if !entry.file_type().is_some_and(|t| t.is_file())
            || (!is_route_source_file(path) && !is_openapi_candidate_file(path))
        {
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
        if is_route_source_file(path) {
            extract_backend_routes(repo, &rel, &src, &mut backend);
            extract_frontend_routes(repo, &rel, &src, &mut frontend);
            extract_api_client_calls(repo, &rel, &src, &mut clients);
            extract_forms(repo, &rel, &src, &mut forms);
            extract_js_bundle_endpoints(repo, &rel, &src, &mut clients);
        }
        if is_openapi_candidate_file(path) {
            extract_openapi_routes(repo, &rel, &src, &mut backend, &mut model.notes);
        }
    }

    model.backend_routes.extend(backend.into_values());
    model.frontend_routes.extend(frontend.into_values());
    model.api_client_calls.extend(clients.into_values());
    model.forms.extend(forms.into_values());
}

fn is_route_source_file(path: &Path) -> bool {
    let Some(ext) = path.extension().and_then(|e| e.to_str()).map(|e| e.to_ascii_lowercase())
    else {
        return false;
    };
    matches!(
        ext.as_str(),
        "js" | "jsx"
            | "ts"
            | "tsx"
            | "mjs"
            | "cjs"
            | "py"
            | "rb"
            | "go"
            | "rs"
            | "php"
            | "html"
            | "htm"
    )
}

fn is_openapi_candidate_file(path: &Path) -> bool {
    let Some(ext) = path.extension().and_then(|e| e.to_str()).map(|e| e.to_ascii_lowercase())
    else {
        return false;
    };
    if !matches!(ext.as_str(), "json" | "yaml" | "yml") {
        return false;
    }
    let file = path.file_name().and_then(|f| f.to_str()).unwrap_or("").to_ascii_lowercase();
    file.contains("openapi") || file.contains("swagger")
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
    let worker_chain = Regex::new(
        r#"(?s)\.(get|post|put|patch|delete|head|options)_async\s*\(\s*["']([^"']+)["']"#,
    )
    .expect("worker route regex");

    let lines: Vec<&str> = src.lines().collect();
    for cap in worker_chain.captures_iter(src) {
        let Some(m) = cap.get(0) else {
            continue;
        };
        let idx = line_number_at(src, m.start()).saturating_sub(1) as usize;
        push_backend_route(
            repo,
            rel,
            idx.min(lines.len().saturating_sub(1)),
            &cap[1],
            &cap[2],
            &lines,
            out,
        );
    }
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
    let window = source_window(lines, idx, 12);
    merge_backend_route(
        out,
        key,
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
        },
    );
}

fn merge_backend_route(
    out: &mut BTreeMap<(String, String, String), RouteModelEndpoint>,
    key: (String, String, String),
    mut next: RouteModelEndpoint,
) {
    match out.get_mut(&key) {
        Some(existing) => {
            merge_strings(&mut existing.params, next.params);
            merge_strings(&mut existing.middleware, next.middleware);
            merge_strings(&mut existing.auth_checks, next.auth_checks);
            merge_strings(&mut existing.role_checks, next.role_checks);
            merge_strings(&mut existing.body_fields, next.body_fields);
            existing.state_changing |= next.state_changing;
            existing.confidence = existing.confidence.max(next.confidence);
            existing.evidence.append(&mut next.evidence);
            if existing.handler_file.is_none() {
                existing.handler_file = next.handler_file;
            }
            if existing.line.is_none() {
                existing.line = next.line;
            }
        }
        None => {
            out.insert(key, next);
        }
    }
}

fn merge_strings(out: &mut Vec<String>, incoming: Vec<String>) {
    out.extend(incoming.into_iter().filter(|s| !s.trim().is_empty()));
    out.sort();
    out.dedup();
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
    push_api_client_call_with_confidence(repo, rel, idx, method, path, line, 0.75, out);
}

fn push_api_client_call_with_confidence(
    repo: &str,
    rel: &str,
    idx: usize,
    method: &str,
    path: &str,
    line: &str,
    confidence: f64,
    out: &mut BTreeMap<(String, String, String), ApiClientCallModel>,
) {
    let key = (repo.to_string(), method.to_string(), path.to_string());
    let evidence = RouteEvidence {
        path: rel.to_string(),
        line: Some((idx + 1) as i64),
        snippet: line.trim().chars().take(240).collect(),
    };
    match out.get_mut(&key) {
        Some(existing) => {
            existing.confidence = existing.confidence.max(confidence);
            existing.evidence.push(evidence);
        }
        None => {
            out.insert(
                key,
                ApiClientCallModel {
                    method: method.to_string(),
                    path: path.to_string(),
                    repo: Some(repo.to_string()),
                    file: Some(rel.to_string()),
                    line: Some((idx + 1) as i64),
                    confidence,
                    evidence: vec![evidence],
                },
            );
        }
    }
}

fn extract_js_bundle_endpoints(
    repo: &str,
    rel: &str,
    src: &str,
    out: &mut BTreeMap<(String, String, String), ApiClientCallModel>,
) {
    if !looks_like_js_bundle(rel, src) {
        return;
    }
    let endpoint_re = Regex::new(
        r#"["'`]((?:https?://[^"'`\s<>]+|/(?:api|auth|admin|graphql|debug|metrics|internal|actuator|openapi|swagger)[^"'`\s<>{}]*))["'`]"#,
    )
    .expect("bundle endpoint regex");
    for cap in endpoint_re.captures_iter(src) {
        let Some(m) = cap.get(1) else {
            continue;
        };
        let path = normalise_route_path(m.as_str());
        if path.is_empty() || !looks_like_http_path(&path) {
            continue;
        }
        let line = line_number_at(src, m.start());
        let snippet = line_at(src, line as usize).unwrap_or_else(|| m.as_str().to_string());
        let method = infer_method_near(src, m.start()).unwrap_or_else(|| "GET".to_string());
        push_api_client_call_with_confidence(
            repo,
            rel,
            (line as usize).saturating_sub(1),
            &method,
            &path,
            &snippet,
            0.56,
            out,
        );
    }
}

fn looks_like_js_bundle(rel: &str, src: &str) -> bool {
    let lower = rel.to_ascii_lowercase();
    lower.ends_with(".js")
        && (lower.contains("/dist/")
            || lower.contains("/build/")
            || lower.contains("/public/")
            || lower.contains("/assets/")
            || lower.contains("bundle")
            || lower.contains(".min."))
        || (lower.ends_with(".js") && src.lines().next().map(|l| l.len() > 2_000).unwrap_or(false))
}

fn infer_method_near(src: &str, byte_idx: usize) -> Option<String> {
    let start = byte_idx.saturating_sub(160);
    let lower = src.get(start..byte_idx)?.to_ascii_lowercase();
    for (needle, method) in [
        ("method:\"post", "POST"),
        ("method:'post", "POST"),
        ("method:`post", "POST"),
        (".post(", "POST"),
        ("method:\"put", "PUT"),
        ("method:'put", "PUT"),
        (".put(", "PUT"),
        ("method:\"patch", "PATCH"),
        ("method:'patch", "PATCH"),
        (".patch(", "PATCH"),
        ("method:\"delete", "DELETE"),
        ("method:'delete", "DELETE"),
        (".delete(", "DELETE"),
    ] {
        if lower.contains(needle) {
            return Some(method.to_string());
        }
    }
    None
}

fn extract_forms(
    repo: &str,
    rel: &str,
    src: &str,
    out: &mut BTreeMap<(String, String, String, i64), FormModel>,
) {
    let form_re =
        Regex::new(r#"(?is)<form\b(?P<attrs>[^>]*)>(?P<body>.*?)</form>"#).expect("form regex");
    for cap in form_re.captures_iter(src) {
        let Some(full) = cap.get(0) else {
            continue;
        };
        let attrs = cap.name("attrs").map(|m| m.as_str()).unwrap_or("");
        let body = cap.name("body").map(|m| m.as_str()).unwrap_or("");
        let method =
            attr_value(attrs, "method").unwrap_or_else(|| "GET".to_string()).to_ascii_uppercase();
        let action = attr_value(attrs, "action")
            .map(|raw| normalise_route_path(&raw))
            .filter(|path| !path.is_empty())
            .unwrap_or_else(|| "(current page)".to_string());
        let line = line_number_at(src, full.start());
        let mut fields = form_fields(body);
        fields.sort();
        fields.dedup();
        let csrf_markers = csrf_markers(body, &fields);
        let state_changing = !matches!(method.as_str(), "GET" | "HEAD" | "OPTIONS");
        let confidence = 0.62 + if fields.is_empty() { 0.0 } else { 0.06 };
        let snippet = full.as_str().split_whitespace().collect::<Vec<_>>().join(" ");
        let key = (repo.to_string(), method.clone(), action.clone(), line);
        out.entry(key).or_insert_with(|| FormModel {
            method,
            action,
            repo: Some(repo.to_string()),
            file: Some(rel.to_string()),
            line: Some(line),
            fields,
            csrf_markers,
            state_changing,
            confidence,
            evidence: vec![RouteEvidence {
                path: rel.to_string(),
                line: Some(line),
                snippet: snippet.chars().take(240).collect(),
            }],
        });
    }
}

fn attr_value(raw: &str, name: &str) -> Option<String> {
    let re = Regex::new(&format!(r#"(?i)\b{}\s*=\s*["']([^"']+)["']"#, regex::escape(name)))
        .expect("attribute regex");
    re.captures(raw).map(|cap| cap[1].trim().to_string()).filter(|s| !s.is_empty())
}

fn form_fields(body: &str) -> Vec<String> {
    let field_re =
        Regex::new(r#"(?is)<(?:input|select|textarea)\b[^>]*\b(?:name|id)\s*=\s*["']([^"']+)["']"#)
            .expect("form field regex");
    field_re
        .captures_iter(body)
        .map(|cap| cap[1].trim().to_string())
        .filter(|s| !s.is_empty())
        .collect()
}

fn csrf_markers(body: &str, fields: &[String]) -> Vec<String> {
    let lower = body.to_ascii_lowercase();
    let mut out = fields
        .iter()
        .filter(|field| {
            let lower = field.to_ascii_lowercase();
            lower.contains("csrf") || lower.contains("xsrf")
        })
        .cloned()
        .collect::<Vec<_>>();
    if lower.contains("csrf") && out.is_empty() {
        out.push("csrf".to_string());
    }
    out.sort();
    out.dedup();
    out
}

fn extract_openapi_routes(
    repo: &str,
    rel: &str,
    src: &str,
    out: &mut BTreeMap<(String, String, String), RouteModelEndpoint>,
    notes: &mut Vec<String>,
) {
    let Some(root) = parse_openapi_value(rel, src) else {
        return;
    };
    let looks_like_spec = root.get("openapi").is_some() || root.get("swagger").is_some();
    if !looks_like_spec {
        return;
    }
    let Some(paths) = root.get("paths").and_then(|v| v.as_object()) else {
        return;
    };
    let root_security = security_names(root.get("security"));
    for (raw_path, path_item) in paths {
        let Some(item) = path_item.as_object() else {
            continue;
        };
        let item_params = openapi_parameters(path_item);
        for (method, operation) in item {
            let method = method.to_ascii_uppercase();
            if !matches!(
                method.as_str(),
                "GET" | "POST" | "PUT" | "PATCH" | "DELETE" | "HEAD" | "OPTIONS"
            ) {
                continue;
            }
            let path = normalise_route_path(raw_path);
            if path.is_empty() {
                continue;
            }
            let mut params = route_params(&path);
            params.extend(item_params.clone());
            params.extend(openapi_parameters(operation));
            params.sort();
            params.dedup();
            let body_fields = openapi_body_fields(operation);
            let mut auth_checks = security_names(operation.get("security"));
            if auth_checks.is_empty() {
                auth_checks = root_security.clone();
            }
            let line = find_line_containing(src, raw_path).unwrap_or(1);
            let snippet =
                line_at(src, line as usize).unwrap_or_else(|| format!("{method} {raw_path}"));
            let confidence = 0.78
                + if !body_fields.is_empty() { 0.04 } else { 0.0 }
                + if !auth_checks.is_empty() { 0.04 } else { 0.0 };
            let key = (repo.to_string(), method.clone(), path.clone());
            merge_backend_route(
                out,
                key,
                RouteModelEndpoint {
                    method: method.clone(),
                    path: path.clone(),
                    repo: Some(repo.to_string()),
                    handler_file: Some(rel.to_string()),
                    line: Some(line),
                    params,
                    middleware: vec!["openapi".to_string()],
                    auth_checks,
                    role_checks: Vec::new(),
                    body_fields,
                    state_changing: !matches!(method.as_str(), "GET" | "HEAD" | "OPTIONS"),
                    confidence,
                    evidence: vec![RouteEvidence {
                        path: rel.to_string(),
                        line: Some(line),
                        snippet: snippet.trim().chars().take(240).collect(),
                    }],
                },
            );
        }
    }
    notes.push(format!("parsed OpenAPI routes from {repo}:{rel}"));
}

fn parse_openapi_value(rel: &str, src: &str) -> Option<serde_json::Value> {
    if rel.to_ascii_lowercase().ends_with(".json") {
        serde_json::from_str(src).ok()
    } else {
        serde_norway::from_str(src).ok()
    }
}

fn openapi_parameters(value: &serde_json::Value) -> Vec<String> {
    let mut out = Vec::new();
    for param in value.get("parameters").and_then(|v| v.as_array()).into_iter().flatten() {
        if let Some(name) = param.get("name").and_then(|v| v.as_str()) {
            out.push(name.to_string());
        }
    }
    out
}

fn openapi_body_fields(value: &serde_json::Value) -> Vec<String> {
    let mut out = Vec::new();
    let Some(content) =
        value.get("requestBody").and_then(|v| v.get("content")).and_then(|v| v.as_object())
    else {
        return out;
    };
    for media in content.values() {
        collect_schema_properties(media.get("schema"), &mut out);
    }
    out.sort();
    out.dedup();
    out
}

fn collect_schema_properties(schema: Option<&serde_json::Value>, out: &mut Vec<String>) {
    let Some(schema) = schema else {
        return;
    };
    if let Some(properties) = schema.get("properties").and_then(|v| v.as_object()) {
        out.extend(properties.keys().cloned());
    }
    if let Some(all_of) = schema.get("allOf").and_then(|v| v.as_array()) {
        for item in all_of {
            collect_schema_properties(Some(item), out);
        }
    }
}

fn security_names(value: Option<&serde_json::Value>) -> Vec<String> {
    let mut out = Vec::new();
    for entry in value.and_then(|v| v.as_array()).into_iter().flatten() {
        if let Some(obj) = entry.as_object() {
            out.extend(obj.keys().cloned());
        }
    }
    out.sort();
    out.dedup();
    out
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

fn line_number_at(src: &str, byte_idx: usize) -> i64 {
    src.as_bytes().iter().take(byte_idx.min(src.len())).filter(|b| **b == b'\n').count() as i64 + 1
}

fn line_at(src: &str, line: usize) -> Option<String> {
    src.lines().nth(line.saturating_sub(1)).map(str::to_string)
}

fn find_line_containing(src: &str, needle: &str) -> Option<i64> {
    src.lines()
        .enumerate()
        .find_map(|(idx, line)| line.contains(needle).then_some((idx + 1) as i64))
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
    path == "/graphql"
        || path.starts_with("/api/")
        || path.starts_with("/auth/")
        || path.starts_with("/admin/")
        || path.starts_with("/graphql/")
        || path.starts_with("/debug")
        || path.starts_with("/metrics")
        || path.starts_with("/internal/")
        || path.starts_with("/actuator")
        || path.contains("swagger")
        || path.contains("openapi")
}

fn route_params(path: &str) -> Vec<String> {
    let colon = Regex::new(r#":([A-Za-z_][A-Za-z0-9_]*)"#).expect("colon params regex");
    let bracket = Regex::new(r#"<([A-Za-z_][A-Za-z0-9_]*)>"#).expect("bracket params regex");
    let braces = Regex::new(r#"\{([A-Za-z_][A-Za-z0-9_]*)\}"#).expect("braced params regex");
    let mut params: Vec<String> = colon.captures_iter(path).map(|c| c[1].to_string()).collect();
    params.extend(bracket.captures_iter(path).map(|c| c[1].to_string()));
    params.extend(braces.captures_iter(path).map(|c| c[1].to_string()));
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
        "{} backend route(s), {} frontend route(s), {} API client call(s), {} form(s)",
        model.backend_routes.len(),
        model.frontend_routes.len(),
        model.api_client_calls.len(),
        model.forms.len()
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
    let remaining = max_routes.saturating_sub(model.backend_routes.len().min(max_routes));
    for form in model.forms.iter().take(remaining.min(20)) {
        let fields = if form.fields.is_empty() {
            "fields:unknown".to_string()
        } else {
            format!("fields:{}", form.fields.join(","))
        };
        lines.push(format!(
            "FORM {} {} {} file:{}:{}",
            form.method,
            form.action,
            fields,
            form.file.as_deref().unwrap_or("?"),
            form.line.map(|l| l.to_string()).unwrap_or_else(|| "?".to_string())
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
    fn extracts_worker_async_router_chains() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::write(
            tmp.path().join("lib.rs"),
            r#"
let router = Router::new()
    .get_async("/api/dev/mail", handle_dev_mail_list)
    .delete_async("/api/dev/mail", handle_dev_mail_clear)
    .put_async(
        "/api/admin/bug-reports/:id/status",
        handle_admin_update_bug_status,
    )
    .get_async("/api/admin/users/search", handle_admin_user_search);
"#,
        )
        .unwrap();
        let mut workspaces = BTreeMap::new();
        workspaces.insert(
            "worker".to_string(),
            WorkspaceHandle::for_local_path_test("worker", tmp.path().to_path_buf()),
        );

        let model = extract_route_model(&workspaces);

        assert!(model
            .backend_routes
            .iter()
            .any(|r| r.method == "GET" && r.path == "/api/dev/mail"));
        assert!(model
            .backend_routes
            .iter()
            .any(|r| r.method == "DELETE" && r.path == "/api/dev/mail"));
        let update = model
            .backend_routes
            .iter()
            .find(|r| r.method == "PUT" && r.path == "/api/admin/bug-reports/:id/status")
            .expect("multiline worker route");
        assert!(update.state_changing);
        assert!(update.params.iter().any(|p| p == "id"));
        assert!(model
            .backend_routes
            .iter()
            .any(|r| r.method == "GET" && r.path == "/api/admin/users/search"));
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

    #[test]
    fn extracts_openapi_bundle_endpoints_and_forms() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(tmp.path().join("dist/assets")).unwrap();
        std::fs::write(
            tmp.path().join("openapi.yaml"),
            r#"
openapi: 3.0.0
security:
  - bearerAuth: []
paths:
  /api/orders/{id}:
    get:
      parameters:
        - name: id
          in: path
    patch:
      requestBody:
        content:
          application/json:
            schema:
              type: object
              properties:
                status:
                  type: string
"#,
        )
        .unwrap();
        std::fs::write(
            tmp.path().join("dist/assets/app.min.js"),
            r#"(()=>{const a="/api/admin/debug";fetch("/graphql",{method:"POST"});})();"#,
        )
        .unwrap();
        std::fs::write(
            tmp.path().join("login.html"),
            r#"<form action="/api/session" method="post"><input name="email"><input name="csrf_token"></form>"#,
        )
        .unwrap();
        let mut workspaces = BTreeMap::new();
        workspaces.insert(
            "web".to_string(),
            WorkspaceHandle::for_local_path_test("web", tmp.path().to_path_buf()),
        );

        let model = extract_route_model(&workspaces);

        let patch = model
            .backend_routes
            .iter()
            .find(|r| r.method == "PATCH" && r.path == "/api/orders/{id}")
            .expect("openapi patch route");
        assert!(patch.params.iter().any(|p| p == "id"));
        assert!(patch.body_fields.iter().any(|f| f == "status"));
        assert!(patch.auth_checks.iter().any(|auth| auth == "bearerAuth"));
        assert!(model.api_client_calls.iter().any(|call| call.path == "/api/admin/debug"));
        assert!(model
            .api_client_calls
            .iter()
            .any(|call| { call.path == "/graphql" && call.method == "POST" }));
        let form = model.forms.iter().find(|f| f.action == "/api/session").expect("form");
        assert_eq!(form.method, "POST");
        assert!(form.fields.iter().any(|f| f == "email"));
        assert!(form.csrf_markers.iter().any(|f| f == "csrf_token"));
    }
}

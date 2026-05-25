use std::collections::{BTreeMap, BTreeSet};
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

#[derive(Debug, Clone)]
struct SourceFile {
    rel: String,
    src: String,
    route_source: bool,
    openapi: bool,
}

#[derive(Debug, Default)]
struct SemanticIndex {
    service_names: BTreeSet<String>,
    model_names: BTreeSet<String>,
}

#[derive(Debug, Default)]
struct SemanticHints {
    query_params: Vec<String>,
    request_fields: Vec<String>,
    response_hints: Vec<String>,
    service_calls: Vec<String>,
    model_names: Vec<String>,
    resource_names: Vec<String>,
    tenant_fields: Vec<String>,
    owner_fields: Vec<String>,
    side_effects: Vec<String>,
}

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
    let mut files = Vec::new();

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
        files.push(SourceFile {
            rel,
            src,
            route_source: is_route_source_file(path),
            openapi: is_openapi_candidate_file(path),
        });
    }

    let index = build_semantic_index(&files);
    for file in &files {
        if file.route_source {
            extract_backend_routes(repo, &file.rel, &file.src, &index, &mut backend);
            extract_frontend_routes(repo, &file.rel, &file.src, &mut frontend);
            extract_api_client_calls(repo, &file.rel, &file.src, &mut clients);
            extract_forms(repo, &file.rel, &file.src, &mut forms);
            extract_js_bundle_endpoints(repo, &file.rel, &file.src, &mut clients);
        }
        if file.openapi {
            extract_openapi_routes(repo, &file.rel, &file.src, &mut backend, &mut model.notes);
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

fn build_semantic_index(files: &[SourceFile]) -> SemanticIndex {
    let mut index = SemanticIndex::default();
    let service_re = Regex::new(
        r#"\b(?:class|function|const|let|var)\s+([A-Za-z_][A-Za-z0-9_]*(?:Service|Repository|Repo|Client|Gateway|Manager))\b"#,
    )
    .expect("service symbol regex");
    let model_re = Regex::new(
        r#"\b(?:class|interface|type|struct|model|Schema::create)\s+([A-Z][A-Za-z0-9_]*(?:Model|Entity|Schema|Record|Dto|DTO))\b"#,
    )
    .expect("model symbol regex");
    let python_model_re =
        Regex::new(r#"\bclass\s+([A-Z][A-Za-z0-9_]*)\s*\([^)]*(?:BaseModel|Model|SQLModel)"#)
            .expect("python model regex");
    for file in files.iter().filter(|f| f.route_source) {
        for cap in service_re.captures_iter(&file.src) {
            index.service_names.insert(cap[1].to_string());
        }
        for cap in model_re.captures_iter(&file.src) {
            if !is_service_like_symbol(&cap[1]) {
                index.model_names.insert(cap[1].to_string());
            }
        }
        for cap in python_model_re.captures_iter(&file.src) {
            if !is_service_like_symbol(&cap[1]) {
                index.model_names.insert(cap[1].to_string());
            }
        }
    }
    index
}

fn is_service_like_symbol(symbol: &str) -> bool {
    ["Service", "Repository", "Repo", "Client", "Gateway", "Manager", "Controller"]
        .iter()
        .any(|suffix| symbol.ends_with(suffix))
}

fn extract_backend_routes(
    repo: &str,
    rel: &str,
    src: &str,
    index: &SemanticIndex,
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
    let nest_controller =
        Regex::new(r#"@Controller\s*\(\s*["']([^"']*)["']\s*\)"#).expect("nest controller regex");
    let nest_method = Regex::new(
        r#"@(Get|Post|Put|Patch|Delete|Head|Options)\s*\(\s*["']?([^"')\n]*)["']?\s*\)"#,
    )
    .expect("nest method regex");
    let rails_route = Regex::new(r#"\b(get|post|put|patch|delete|match)\s+["']([^"']+)["'][^\n]*"#)
        .expect("rails route regex");
    let rails_resources =
        Regex::new(r#"\bresources\s+:([A-Za-z_][A-Za-z0-9_]*)"#).expect("rails resources regex");
    let laravel_route = Regex::new(
        r#"Route::(get|post|put|patch|delete|match|any)\s*\(\s*["']([^"']+)["']([^;]*)"#,
    )
    .expect("laravel route regex");

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
            None,
            "rust-worker",
            index,
            &lines,
            out,
        );
    }
    for cap in rails_route.captures_iter(src) {
        let Some(m) = cap.get(0) else {
            continue;
        };
        let idx = line_number_at(src, m.start()).saturating_sub(1) as usize;
        let methods = if cap[1].eq_ignore_ascii_case("match") {
            vec!["GET".to_string(), "POST".to_string()]
        } else {
            vec![cap[1].to_ascii_uppercase()]
        };
        for method in methods {
            push_backend_route(
                repo,
                rel,
                idx.min(lines.len().saturating_sub(1)),
                &method,
                &cap[2],
                rails_handler(m.as_str()),
                "rails",
                index,
                &lines,
                out,
            );
        }
    }
    for cap in rails_resources.captures_iter(src) {
        let Some(m) = cap.get(0) else {
            continue;
        };
        let idx = line_number_at(src, m.start()).saturating_sub(1) as usize;
        let resource = &cap[1];
        for (method, suffix, handler) in [
            ("GET", "", "index"),
            ("POST", "", "create"),
            ("GET", "/:id", "show"),
            ("PATCH", "/:id", "update"),
            ("DELETE", "/:id", "destroy"),
        ] {
            push_backend_route(
                repo,
                rel,
                idx.min(lines.len().saturating_sub(1)),
                method,
                &format!("/{resource}{suffix}"),
                Some(handler.to_string()),
                "rails",
                index,
                &lines,
                out,
            );
        }
    }
    for cap in laravel_route.captures_iter(src) {
        let Some(m) = cap.get(0) else {
            continue;
        };
        let idx = line_number_at(src, m.start()).saturating_sub(1) as usize;
        let methods = match cap[1].to_ascii_lowercase().as_str() {
            "match" | "any" => vec!["GET".to_string(), "POST".to_string()],
            other => vec![other.to_ascii_uppercase()],
        };
        let handler = laravel_handler(cap.get(3).map(|m| m.as_str()).unwrap_or(""));
        for method in methods {
            push_backend_route(
                repo,
                rel,
                idx.min(lines.len().saturating_sub(1)),
                &method,
                &cap[2],
                handler.clone(),
                "laravel",
                index,
                &lines,
                out,
            );
        }
    }
    let mut controller_prefix = String::new();
    for (idx, line) in lines.iter().enumerate() {
        if let Some(cap) = nest_controller.captures(line) {
            controller_prefix = normalise_route_path(&cap[1]);
        }
        if let Some(cap) = nest_method.captures(line) {
            let method = nest_method_name_to_http(&cap[1]);
            let path = join_route_paths(&controller_prefix, &cap[2]);
            push_backend_route(
                repo,
                rel,
                idx,
                &method,
                &path,
                next_handler_name(&lines, idx),
                "nest",
                index,
                &lines,
                out,
            );
        }
        for cap in express.captures_iter(line) {
            push_backend_route(
                repo, rel, idx, &cap[1], &cap[2], None, "express", index, &lines, out,
            );
        }
        for cap in decorator.captures_iter(line) {
            push_backend_route(
                repo,
                rel,
                idx,
                &cap[1],
                &cap[2],
                next_handler_name(&lines, idx),
                "python",
                index,
                &lines,
                out,
            );
        }
        for cap in route_decorator.captures_iter(line) {
            let methods =
                methods_from_route_decorator(cap.get(2).map(|m| m.as_str()).unwrap_or(""));
            for method in methods {
                push_backend_route(
                    repo,
                    rel,
                    idx,
                    &method,
                    &cap[1],
                    next_handler_name(&lines, idx),
                    "python",
                    index,
                    &lines,
                    out,
                );
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
    handler_name: Option<String>,
    framework: &str,
    index: &SemanticIndex,
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
    let semantic = semantic_hints(&path, &method, &window, index);
    let mut body = body_fields(&window);
    merge_strings(&mut body, semantic.request_fields.clone());
    let mut side_effects = semantic.side_effects;
    if !matches!(method.as_str(), "GET" | "HEAD" | "OPTIONS") && side_effects.is_empty() {
        side_effects.push("writes_resource".to_string());
    }
    merge_backend_route(
        out,
        key,
        RouteModelEndpoint {
            method: method.clone(),
            path: path.clone(),
            framework: framework.to_string(),
            repo: Some(repo.to_string()),
            handler_file: Some(rel.to_string()),
            handler_name,
            line: Some((idx + 1) as i64),
            params: route_params(&path),
            query_params: semantic.query_params,
            middleware: middleware_markers(&window),
            auth_checks: auth_markers(&window),
            role_checks: role_markers(&window),
            body_fields: body.clone(),
            request_fields: body,
            response_hints: semantic.response_hints,
            service_calls: semantic.service_calls,
            model_names: semantic.model_names,
            resource_names: semantic.resource_names,
            tenant_fields: semantic.tenant_fields,
            owner_fields: semantic.owner_fields,
            side_effects,
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
            merge_strings(&mut existing.query_params, next.query_params);
            merge_strings(&mut existing.middleware, next.middleware);
            merge_strings(&mut existing.auth_checks, next.auth_checks);
            merge_strings(&mut existing.role_checks, next.role_checks);
            merge_strings(&mut existing.body_fields, next.body_fields);
            merge_strings(&mut existing.request_fields, next.request_fields);
            merge_strings(&mut existing.response_hints, next.response_hints);
            merge_strings(&mut existing.service_calls, next.service_calls);
            merge_strings(&mut existing.model_names, next.model_names);
            merge_strings(&mut existing.resource_names, next.resource_names);
            merge_strings(&mut existing.tenant_fields, next.tenant_fields);
            merge_strings(&mut existing.owner_fields, next.owner_fields);
            merge_strings(&mut existing.side_effects, next.side_effects);
            existing.state_changing |= next.state_changing;
            existing.confidence = existing.confidence.max(next.confidence);
            existing.evidence.append(&mut next.evidence);
            if existing.framework.is_empty() {
                existing.framework = next.framework;
            }
            if existing.handler_name.is_none() {
                existing.handler_name = next.handler_name;
            }
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
                    framework: "openapi".to_string(),
                    repo: Some(repo.to_string()),
                    handler_file: Some(rel.to_string()),
                    handler_name: operation
                        .get("operationId")
                        .and_then(|v| v.as_str())
                        .map(str::to_string),
                    line: Some(line),
                    params,
                    query_params: openapi_query_parameters(operation),
                    middleware: vec!["openapi".to_string()],
                    auth_checks,
                    role_checks: Vec::new(),
                    body_fields: body_fields.clone(),
                    request_fields: body_fields,
                    response_hints: openapi_response_hints(operation),
                    service_calls: Vec::new(),
                    model_names: openapi_schema_refs(operation),
                    resource_names: route_objects(&path),
                    tenant_fields: Vec::new(),
                    owner_fields: Vec::new(),
                    side_effects: side_effects(&method, &path, ""),
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

fn openapi_query_parameters(value: &serde_json::Value) -> Vec<String> {
    let mut out = Vec::new();
    for param in value.get("parameters").and_then(|v| v.as_array()).into_iter().flatten() {
        if param.get("in").and_then(|v| v.as_str()) == Some("query") {
            if let Some(name) = param.get("name").and_then(|v| v.as_str()) {
                out.push(name.to_string());
            }
        }
    }
    sorted_unique(out)
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

fn openapi_response_hints(value: &serde_json::Value) -> Vec<String> {
    let mut out = Vec::new();
    if let Some(responses) = value.get("responses").and_then(|v| v.as_object()) {
        for (status, response) in responses {
            out.push(format!("status:{status}"));
            collect_schema_refs(response, &mut out);
        }
    }
    sorted_unique(out)
}

fn openapi_schema_refs(value: &serde_json::Value) -> Vec<String> {
    let mut out = Vec::new();
    collect_schema_refs(value, &mut out);
    sorted_unique(out)
}

fn collect_schema_refs(value: &serde_json::Value, out: &mut Vec<String>) {
    match value {
        serde_json::Value::Object(map) => {
            for (key, value) in map {
                if key == "$ref" {
                    if let Some(raw) = value.as_str().and_then(|s| s.rsplit('/').next()) {
                        out.push(raw.to_string());
                    }
                } else {
                    collect_schema_refs(value, out);
                }
            }
        }
        serde_json::Value::Array(items) => {
            for item in items {
                collect_schema_refs(item, out);
            }
        }
        _ => {}
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

fn nest_method_name_to_http(raw: &str) -> String {
    match raw.to_ascii_lowercase().as_str() {
        "get" => "GET",
        "post" => "POST",
        "put" => "PUT",
        "patch" => "PATCH",
        "delete" => "DELETE",
        "head" => "HEAD",
        "options" => "OPTIONS",
        _ => "GET",
    }
    .to_string()
}

fn join_route_paths(prefix: &str, child: &str) -> String {
    let prefix = normalise_route_path(prefix);
    let child = child.trim().trim_matches('/');
    if child.is_empty() {
        return prefix;
    }
    if prefix == "/" {
        format!("/{child}")
    } else {
        format!("{}/{}", prefix.trim_end_matches('/'), child)
    }
}

fn next_handler_name(lines: &[&str], idx: usize) -> Option<String> {
    let re =
        Regex::new(r#"\b(?:async\s+)?(?:function\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*(?:\([^)]*\)|=)"#)
            .expect("handler regex");
    for line in lines.iter().skip(idx + 1).take(5) {
        let trimmed = line.trim();
        if trimmed.starts_with('@') {
            continue;
        }
        if let Some(cap) = re.captures(trimmed) {
            return Some(cap[1].to_string());
        }
    }
    None
}

fn laravel_handler(raw: &str) -> Option<String> {
    let array_re = Regex::new(r#"\[([A-Za-z_][A-Za-z0-9_:]*)::class\s*,\s*["']([^"']+)["']"#)
        .expect("laravel array handler regex");
    let string_re = Regex::new(r#"["']([A-Za-z_][A-Za-z0-9_\\]+@[A-Za-z_][A-Za-z0-9_]*)["']"#)
        .expect("laravel string handler regex");
    array_re
        .captures(raw)
        .map(|cap| format!("{}.{}", &cap[1], &cap[2]))
        .or_else(|| string_re.captures(raw).map(|cap| cap[1].replace('@', ".")))
}

fn rails_handler(raw: &str) -> Option<String> {
    let re = Regex::new(r#"to:\s*["']([^"']+)["']"#).expect("rails handler regex");
    re.captures(raw).map(|cap| cap[1].replace('#', "."))
}

fn semantic_hints(path: &str, method: &str, window: &str, index: &SemanticIndex) -> SemanticHints {
    let mut hints =
        SemanticHints { resource_names: route_objects(path), ..SemanticHints::default() };
    hints.query_params = query_fields(window);
    hints.request_fields = request_fields(window);
    hints.response_hints = response_hints(window);
    hints.tenant_fields =
        field_markers(window, &["tenant", "tenant_id", "org_id", "organization_id", "account_id"]);
    hints.owner_fields =
        field_markers(window, &["owner", "owner_id", "user_id", "created_by", "account_id"]);
    hints.service_calls = called_symbols(window, &index.service_names);
    hints.model_names = called_symbols(window, &index.model_names);
    merge_strings(
        &mut hints.model_names,
        models_matching_resources(&hints.resource_names, &index.model_names),
    );
    merge_strings(&mut hints.resource_names, resource_names_from_symbols(&hints.model_names));
    hints.side_effects = side_effects(method, path, window);
    hints
}

fn query_fields(window: &str) -> Vec<String> {
    let mut out = capture_group(window, r#"\b(?:req|request)\.query\.([A-Za-z_][A-Za-z0-9_]*)"#);
    out.extend(capture_group(
        window,
        r#"\b(?:params|query_params|request\.args)\s*\[\s*["']([A-Za-z_][A-Za-z0-9_]*)["']"#,
    ));
    sorted_unique(out)
}

fn request_fields(window: &str) -> Vec<String> {
    let mut out = body_fields(window);
    out.extend(capture_group(
        window,
        r#"\b(?:request\.json|request\.data|data|payload|body)\.([A-Za-z_][A-Za-z0-9_]*)"#,
    ));
    out.extend(capture_group(
        window,
        r#"\b(?:request\.json|request\.data|data|payload)\s*\[\s*["']([A-Za-z_][A-Za-z0-9_]*)["']"#,
    ));
    sorted_unique(out)
}

fn response_hints(window: &str) -> Vec<String> {
    let mut out = capture_group(
        window,
        r#"\b(?:res\.json|jsonify|render|serialize)\s*\(\s*([A-Za-z_][A-Za-z0-9_]*)"#,
    );
    out.extend(capture_group(window, r#"\breturn\s+([A-Za-z_][A-Za-z0-9_]*)"#));
    sorted_unique(out)
}

fn field_markers(window: &str, names: &[&str]) -> Vec<String> {
    let lower = window.to_ascii_lowercase();
    let mut out = Vec::new();
    for name in names {
        if lower.contains(name) {
            out.push((*name).to_string());
        }
    }
    sorted_unique(out)
}

fn called_symbols(window: &str, symbols: &BTreeSet<String>) -> Vec<String> {
    let mut out = Vec::new();
    for symbol in symbols {
        if window.contains(symbol) {
            out.push(symbol.clone());
        }
    }
    sorted_unique(out)
}

fn resource_names_from_symbols(symbols: &[String]) -> Vec<String> {
    sorted_unique(symbols.iter().map(|s| {
        s.trim_end_matches("Model")
            .trim_end_matches("Entity")
            .trim_end_matches("Schema")
            .trim_end_matches("Record")
            .to_ascii_lowercase()
    }))
}

fn models_matching_resources(resources: &[String], models: &BTreeSet<String>) -> Vec<String> {
    let mut out = Vec::new();
    for model in models {
        let lower = model.to_ascii_lowercase();
        for resource in resources {
            if lower.starts_with(resource) || lower.starts_with(&format!("{resource}s")) {
                out.push(model.clone());
            }
        }
    }
    sorted_unique(out)
}

fn side_effects(method: &str, path: &str, window: &str) -> Vec<String> {
    let lower = format!("{} {}", path.to_ascii_lowercase(), window.to_ascii_lowercase());
    let mut out = Vec::new();
    for (needle, effect) in [
        ("delete", "delete_resource"),
        ("destroy", "delete_resource"),
        ("create", "create_resource"),
        ("insert", "create_resource"),
        ("update", "update_resource"),
        ("save", "update_resource"),
        ("transfer", "moves_value"),
        ("payment", "moves_value"),
        ("refund", "moves_value"),
        ("email", "sends_message"),
        ("notify", "sends_message"),
        ("upload", "stores_file"),
        ("export", "exports_data"),
        ("download", "exports_data"),
    ] {
        if lower.contains(needle) {
            out.push(effect.to_string());
        }
    }
    if method == "DELETE" {
        out.push("delete_resource".to_string());
    }
    sorted_unique(out)
}

fn capture_group(raw: &str, pattern: &str) -> Vec<String> {
    let re = Regex::new(pattern).expect("semantic capture regex");
    re.captures_iter(raw).map(|cap| cap[1].to_string()).collect()
}

fn sorted_unique<I>(items: I) -> Vec<String>
where
    I: IntoIterator<Item = String>,
{
    let mut out: Vec<String> = items.into_iter().filter(|s| !s.trim().is_empty()).collect();
    out.sort();
    out.dedup();
    out
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

fn route_objects(path: &str) -> Vec<String> {
    let stop = [
        "api", "v1", "v2", "admin", "auth", "login", "logout", "me", "search", "new", "edit",
        "health", "debug", "metrics",
    ];
    let mut out = Vec::new();
    for segment in path.split('/') {
        let clean = segment
            .trim_matches(|c: char| !c.is_ascii_alphanumeric() && c != '_' && c != '-')
            .trim_start_matches(':')
            .trim_matches(|c| c == '{' || c == '}');
        if clean.is_empty()
            || clean.chars().all(|c| c.is_ascii_digit())
            || stop.iter().any(|s| clean.eq_ignore_ascii_case(s))
        {
            continue;
        }
        out.push(clean.trim_end_matches('s').to_ascii_lowercase());
    }
    sorted_unique(out)
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
        let resources = if route.resource_names.is_empty() {
            String::new()
        } else {
            format!(" resources:{}", route.resource_names.join(","))
        };
        let effects = if route.side_effects.is_empty() {
            String::new()
        } else {
            format!(" effects:{}", route.side_effects.join(","))
        };
        lines.push(format!(
            "{} {} {}{}{}{} file:{}:{}",
            route.method,
            route.path,
            auth,
            roles,
            resources,
            effects,
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

    #[test]
    fn extracts_nest_routes_with_semantic_hints() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::write(
            tmp.path().join("users.controller.ts"),
            r#"
@Controller("api/users")
export class UsersController {
  constructor(private readonly usersService: UsersService) {}

  @Patch(":id")
  async updateUser(@Param("id") id: string, @Body() body: UpdateUserDto, @Req() req) {
    const tenantId = req.user.tenant_id;
    const user = await this.usersService.update(id, body.email, tenantId);
    return { user };
  }
}
"#,
        )
        .unwrap();
        std::fs::write(
            tmp.path().join("users.service.ts"),
            r#"
export class UsersService {
  async update(id: string, email: string, tenantId: string): Promise<UserEntity> {
    return UserEntity.save({ id, email, tenant_id: tenantId });
  }
}
export class UserEntity {}
"#,
        )
        .unwrap();
        let mut workspaces = BTreeMap::new();
        workspaces.insert(
            "api".to_string(),
            WorkspaceHandle::for_local_path_test("api", tmp.path().to_path_buf()),
        );

        let model = extract_route_model(&workspaces);
        let route = model
            .backend_routes
            .iter()
            .find(|r| r.method == "PATCH" && r.path == "/api/users/:id")
            .expect("nest route");
        assert_eq!(route.framework, "nest");
        assert_eq!(route.handler_name.as_deref(), Some("updateUser"));
        assert!(route.params.iter().any(|p| p == "id"));
        assert!(route.tenant_fields.iter().any(|f| f == "tenant_id"));
        assert!(route.service_calls.iter().any(|s| s == "UsersService"));
        assert!(route.model_names.iter().any(|m| m == "UserEntity"));
        assert!(route.side_effects.iter().any(|s| s == "update_resource"));
    }

    #[test]
    fn extracts_rails_and_laravel_route_declarations() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::write(
            tmp.path().join("routes.rb"),
            r#"
Rails.application.routes.draw do
  resources :projects
  post "/admin/reports/export", to: "reports#export"
end
"#,
        )
        .unwrap();
        std::fs::write(
            tmp.path().join("web.php"),
            r#"
Route::get('/orders/{id}', [OrderController::class, 'show']);
Route::post('/orders/{id}/refund', [OrderController::class, 'refund'])->middleware('auth');
"#,
        )
        .unwrap();
        let mut workspaces = BTreeMap::new();
        workspaces.insert(
            "api".to_string(),
            WorkspaceHandle::for_local_path_test("api", tmp.path().to_path_buf()),
        );

        let model = extract_route_model(&workspaces);
        assert!(model
            .backend_routes
            .iter()
            .any(|r| r.framework == "rails" && r.method == "GET" && r.path == "/projects/:id"));
        let export = model
            .backend_routes
            .iter()
            .find(|r| r.framework == "rails" && r.path == "/admin/reports/export")
            .expect("rails export route");
        assert_eq!(export.handler_name.as_deref(), Some("reports.export"));
        assert!(export.side_effects.iter().any(|s| s == "exports_data"));
        let refund = model
            .backend_routes
            .iter()
            .find(|r| r.framework == "laravel" && r.path == "/orders/{id}/refund")
            .expect("laravel refund route");
        assert_eq!(refund.handler_name.as_deref(), Some("OrderController.refund"));
        assert!(refund.params.iter().any(|p| p == "id"));
        assert!(refund.side_effects.iter().any(|s| s == "moves_value"));
    }

    #[test]
    fn infers_services_and_models_across_files() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::write(
            tmp.path().join("billing.routes.js"),
            r#"
router.post("/api/invoices/:id/pay", requireAuth, async (req, res) => {
  const result = await BillingService.charge(req.params.id, req.body.amount, req.user.owner_id);
  res.json({ invoice: result });
});
"#,
        )
        .unwrap();
        std::fs::write(
            tmp.path().join("billing.service.js"),
            r#"
class BillingService {}
class InvoiceModel {}
"#,
        )
        .unwrap();
        let mut workspaces = BTreeMap::new();
        workspaces.insert(
            "api".to_string(),
            WorkspaceHandle::for_local_path_test("api", tmp.path().to_path_buf()),
        );

        let model = extract_route_model(&workspaces);
        let route = model
            .backend_routes
            .iter()
            .find(|r| r.path == "/api/invoices/:id/pay")
            .expect("billing route");
        assert!(route.service_calls.iter().any(|s| s == "BillingService"));
        assert!(route.model_names.iter().any(|m| m == "InvoiceModel"));
        assert!(route.resource_names.iter().any(|r| r == "invoice"));
        assert!(route.owner_fields.iter().any(|f| f == "owner_id"));
        assert!(route.request_fields.iter().any(|f| f == "amount"));
    }
}

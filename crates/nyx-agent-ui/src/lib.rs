//! Embedded single-page UI for the nyx-agent daemon.
//!
//! The `dist/` directory is populated by `build.rs`:
//! * release builds run the Vite pipeline in `<repo>/frontend/` and
//!   copy the output here;
//! * other profiles drop a tiny stub `index.html` so the agent's `/`
//!   route still returns something usable.
//!
//! Consumers wire [`spa_handler`] as the Axum fallback so any path
//! outside `/api/v1/...` resolves to either the matching asset or the
//! SPA's `index.html` (for client-side routing).

use axum::{
    body::Body,
    extract::State,
    http::{header, StatusCode, Uri},
    response::{IntoResponse, Response},
};
use rust_embed::RustEmbed;

#[derive(RustEmbed)]
#[folder = "dist/"]
pub struct UiAssets;

/// Bootstrap context passed into the SPA at request time. Currently
/// carries the bearer token the API middleware expects on every
/// non-`/setup` request. The fallback handler rewrites `index.html` to
/// embed it before sending the response; the SPA reads it from
/// `window.__NYX_BOOTSTRAP__`.
#[derive(Clone, Default)]
pub struct UiBootstrap {
    pub auth_token: Option<String>,
}

/// Resolve the given URI path against the embedded asset tree.
/// Returns `None` if no asset (including `index.html`) is available
/// for that path.
pub fn resolve(path: &str) -> Option<UiResponse> {
    resolve_with(path, &UiBootstrap::default())
}

/// `resolve` with bootstrap context. When the resolved asset is
/// `index.html` and `bootstrap.auth_token` is set, the response body
/// has a `<script>` tag injected at the start of `<head>` so the SPA
/// has the token before any API call fires.
pub fn resolve_with(path: &str, bootstrap: &UiBootstrap) -> Option<UiResponse> {
    let clean = path.trim_start_matches('/');
    let candidate = if clean.is_empty() { "index.html" } else { clean };
    if let Some(file) = UiAssets::get(candidate) {
        return Some(UiResponse::from_embedded(candidate, file, bootstrap));
    }
    // SPA fallback: unknown path with no extension → return index.html
    // so client-side routing can render the requested view.
    if !candidate.contains('.') {
        if let Some(file) = UiAssets::get("index.html") {
            return Some(UiResponse::from_embedded("index.html", file, bootstrap));
        }
    }
    None
}

pub struct UiResponse {
    body: Vec<u8>,
    content_type: String,
}

impl UiResponse {
    fn from_embedded(
        path: &str,
        file: rust_embed::EmbeddedFile,
        bootstrap: &UiBootstrap,
    ) -> Self {
        let mime = mime_guess::from_path(path).first_or_octet_stream();
        let body = if path == "index.html" {
            inject_bootstrap(&file.data, bootstrap)
        } else {
            file.data.into_owned()
        };
        Self { body, content_type: mime.essence_str().to_string() }
    }
}

fn inject_bootstrap(html: &[u8], bootstrap: &UiBootstrap) -> Vec<u8> {
    let Ok(text) = std::str::from_utf8(html) else {
        return html.to_vec();
    };
    let payload = format!(
        "<script>window.__NYX_BOOTSTRAP__={};</script>",
        serde_payload(bootstrap)
    );
    // Inject right after the opening <head>. Falls back to prepending
    // if no <head> tag is present.
    if let Some(pos) = text.find("<head>") {
        let mut out = String::with_capacity(text.len() + payload.len());
        out.push_str(&text[..pos + "<head>".len()]);
        out.push_str(&payload);
        out.push_str(&text[pos + "<head>".len()..]);
        out.into_bytes()
    } else {
        let mut out = payload.into_bytes();
        out.extend_from_slice(html);
        out
    }
}

fn serde_payload(bootstrap: &UiBootstrap) -> String {
    // Tiny hand-rolled JSON to avoid adding a serde dependency to this
    // crate just for one field. The token is hex, so escaping is moot.
    match &bootstrap.auth_token {
        Some(token) => format!("{{\"authToken\":\"{}\"}}", token.replace('"', "\\\"")),
        None => "{}".to_string(),
    }
}

impl IntoResponse for UiResponse {
    fn into_response(self) -> Response {
        Response::builder()
            .status(StatusCode::OK)
            .header(header::CONTENT_TYPE, self.content_type)
            .body(Body::from(self.body))
            .expect("build static response")
    }
}

/// Axum-compatible fallback handler. Pass to `Router::fallback`.
///
/// Paths under `/api/` are never served from the embedded SPA: if a
/// matching `/api/v1/...` route exists the router resolves it before
/// the fallback fires, and a miss (typo, wrong version prefix) should
/// surface as a real 404 instead of being swallowed by the SPA
/// index.html.
pub async fn spa_handler(uri: Uri) -> Response {
    spa_handler_with(uri, &UiBootstrap::default()).await
}

pub async fn spa_handler_with(uri: Uri, bootstrap: &UiBootstrap) -> Response {
    let path = uri.path();
    if path.starts_with("/api/") || path == "/api" {
        return (StatusCode::NOT_FOUND, "not found").into_response();
    }
    match resolve_with(path, bootstrap) {
        Some(resp) => resp.into_response(),
        None => (StatusCode::NOT_FOUND, "not found").into_response(),
    }
}

/// Stateful Axum handler bound to a clonable [`UiBootstrap`]. Used as
/// the daemon's fallback so every served `index.html` carries the live
/// auth token.
pub async fn spa_handler_stateful(
    State(bootstrap): State<std::sync::Arc<UiBootstrap>>,
    uri: Uri,
) -> Response {
    spa_handler_with(uri, &bootstrap).await
}

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
    http::{header, StatusCode, Uri},
    response::{IntoResponse, Response},
};
use rust_embed::RustEmbed;

#[derive(RustEmbed)]
#[folder = "dist/"]
pub struct UiAssets;

/// Resolve the given URI path against the embedded asset tree.
/// Returns `None` if no asset (including `index.html`) is available
/// for that path.
pub fn resolve(path: &str) -> Option<UiResponse> {
    let clean = path.trim_start_matches('/');
    let candidate = if clean.is_empty() { "index.html" } else { clean };
    if let Some(file) = UiAssets::get(candidate) {
        return Some(UiResponse::from_embedded(candidate, file));
    }
    // SPA fallback: unknown path with no extension → return index.html
    // so client-side routing can render the requested view.
    if !candidate.contains('.') {
        if let Some(file) = UiAssets::get("index.html") {
            return Some(UiResponse::from_embedded("index.html", file));
        }
    }
    None
}

pub struct UiResponse {
    body: Vec<u8>,
    content_type: String,
}

impl UiResponse {
    fn from_embedded(path: &str, file: rust_embed::EmbeddedFile) -> Self {
        let mime = mime_guess::from_path(path).first_or_octet_stream();
        Self { body: file.data.into_owned(), content_type: mime.essence_str().to_string() }
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
    let path = uri.path();
    if path.starts_with("/api/") || path == "/api" {
        return (StatusCode::NOT_FOUND, "not found").into_response();
    }
    match resolve(path) {
        Some(resp) => resp.into_response(),
        None => (StatusCode::NOT_FOUND, "not found").into_response(),
    }
}

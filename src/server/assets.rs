use axum::body::Body;
use axum::http::{header, StatusCode};
use axum::response::Response;
use rust_embed::RustEmbed;

#[derive(RustEmbed)]
#[folder = "assets/"]
pub struct Assets;

fn clean_path(path: &str) -> String {
    let trimmed = if path.is_empty() || path == "/" {
        "index.html"
    } else {
        path.trim_start_matches('/')
    };
    trimmed.to_string()
}

fn build(bytes: Vec<u8>, name: &str) -> Response {
    let mime = mime_guess::from_path(name).first_or_octet_stream();
    Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, mime.as_ref())
        .header(header::CACHE_CONTROL, "no-store, no-cache, must-revalidate")
        .body(Body::from(bytes))
        .unwrap()
}

fn not_found() -> Response {
    Response::builder()
        .status(StatusCode::NOT_FOUND)
        .body(Body::from("not found"))
        .unwrap()
}

fn is_route(path: &str) -> bool {
    let last = path.rsplit('/').next().unwrap_or("");
    !last.contains('.')
}

#[cfg(debug_assertions)]
fn load(name: &str) -> Option<Vec<u8>> {
    let base = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("assets");
    std::fs::read(base.join(name)).ok()
}

#[cfg(not(debug_assertions))]
fn load(name: &str) -> Option<Vec<u8>> {
    Assets::get(name).map(|f| f.data.into_owned())
}

pub fn serve(path: &str) -> Response {
    let clean = clean_path(path);
    if let Some(bytes) = load(&clean) {
        return build(bytes, &clean);
    }
    if is_route(&clean) {
        if let Some(bytes) = load("index.html") {
            return build(bytes, "index.html");
        }
    }
    not_found()
}

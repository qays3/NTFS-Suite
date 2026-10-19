use std::sync::Arc;

use axum::extract::State;
use axum::http::{Request, StatusCode};
use axum::middleware::Next;
use axum::response::Response;

use crate::server::state::AppState;

pub async fn guard(
    State(state): State<Arc<AppState>>,
    request: Request<axum::body::Body>,
    next: Next,
) -> Result<Response, StatusCode> {
    let path = request.uri().path().to_string();
    let headers = request.headers();

    match headers.get("host").and_then(|h| h.to_str().ok()) {
        Some(host) if host_allowed(host, state.port) => {}
        _ => return Err(StatusCode::FORBIDDEN),
    }

    if path.starts_with("/api/") {
        if let Some(origin) = headers.get("origin").and_then(|h| h.to_str().ok()) {
            if !origin_allowed(origin, state.port) {
                return Err(StatusCode::FORBIDDEN);
            }
        }
    }

    Ok(next.run(request).await)
}

fn host_allowed(host: &str, port: u16) -> bool {
    let expected_ip = format!("127.0.0.1:{}", port);
    let expected_local = format!("localhost:{}", port);
    host == expected_ip || host == expected_local
}

fn origin_allowed(origin: &str, port: u16) -> bool {
    let a = format!("http://127.0.0.1:{}", port);
    let b = format!("http://localhost:{}", port);
    origin == a || origin == b
}

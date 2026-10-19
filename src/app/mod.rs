pub mod browser;

use std::sync::Arc;

use tokio::net::TcpListener;

use crate::server::build_router;
use crate::server::state::AppState;
use crate::settings::{self, Settings};

pub async fn run() -> std::io::Result<()> {
    let paths = settings::resolve_paths();
    let loaded = settings::load(&paths.settings_path);
    let current = match loaded {
        Some(s) => s,
        None => Settings::defaults(paths.default_cases_dir.display().to_string()),
    };

    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let port = listener.local_addr()?.port();

    let state = Arc::new(AppState::new(port, paths, current));
    let app = build_router(state);

    let url = format!("http://127.0.0.1:{}/", port);
    println!("NTFS Suite listening on {}", url);
    browser::open(&url);

    axum::serve(listener, app).await
}

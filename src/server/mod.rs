pub mod assets;
pub mod jobs;
pub mod security;
pub mod state;

use std::sync::Arc;

use axum::extract::State;
use axum::http::Request;
use axum::response::Response;
use axum::routing::{get, post};
use axum::Router;

use crate::api;
use state::AppState;

pub fn build_router(state: Arc<AppState>) -> Router {
    Router::new()
        .route("/api/bootstrap", get(api::bootstrap))
        .route("/api/setup", post(api::save_setup))
        .route("/api/cases", get(api::list_cases).post(api::create_case))
        .route("/api/cases/open", post(api::open_case))
        .route("/api/cases/delete", post(api::delete_case))
        .route("/api/case", get(api::case_state))
        .route("/api/case/audit", get(api::audit_log))
        .route("/api/case/timezone", post(api::set_timezone))
        .route("/api/evidence", post(api::add_evidence))
        .route("/api/evidence/delete", post(api::delete_evidence))
        .route("/api/evidence/parse", post(api::parse_evidence))
        .route("/api/evidence/stats", post(api::evidence_stats))
        .route("/api/jobs/status", post(api::job_status))
        .route("/api/jobs/cancel", post(api::job_cancel))
        .route("/api/records", post(api::records))
        .route("/api/records/export", get(api::export::export_records))
        .route("/api/export/bodyfile", get(api::export::export_bodyfile))
        .route("/api/export/timeline", get(api::export::export_timeline))
        .route("/api/export/ioc", get(api::report::ioc))
        .route("/api/report", get(api::report::report))
        .route("/api/findings", post(api::findings))
        .route("/api/findings/grouped", post(api::findings_grouped))
        .route("/api/findings/status", post(api::finding_status))
        .route("/api/findings/status/group", post(api::finding_status_group))
        .route("/api/detect", post(api::detect))
        .route("/api/rules", get(api::rules::list))
        .route("/api/rules/preview", post(api::rules::preview))
        .route("/api/rules/save", post(api::rules::save))
        .route("/api/rules/delete", post(api::rules::delete_rule))
        .route("/api/rules/enable", post(api::rules::enable))
        .route("/api/iocs", get(api::iocs::list))
        .route("/api/iocs/import", post(api::iocs::import))
        .route("/api/iocs/clear", post(api::iocs::clear))
        .route("/api/charts/dashboard", post(api::charts::dashboard))
        .route("/api/graph/roots", post(api::graph::roots))
        .route("/api/graph/neighbors", post(api::graph::neighbors))
        .route("/api/graph/anatomy", post(api::graph::anatomy))
        .route("/api/graph/ownership", post(api::graph::ownership))
        .route("/api/usn", post(api::usn::list))
        .route("/api/collect/volumes", get(api::collect::volumes))
        .route("/api/collect/run", post(api::collect::run))
        .route("/api/secure/lookup", post(api::secure::lookup))
        .route("/api/timeline/events", post(api::timeline::events))
        .route("/api/timeline/bodyfile", post(api::timeline::bodyfile))
        .route("/api/timeline/bodyfile/default", post(api::timeline::bodyfile_default))
        .route("/api/browse", post(api::browse_files))
        .route("/api/pick", post(api::pick_file))
        .route(
            "/api/upload",
            post(api::upload_file).layer(axum::extract::DefaultBodyLimit::disable()),
        )
        .fallback(static_handler)
        .layer(axum::middleware::from_fn_with_state(state.clone(), security::guard))
        .with_state(state)
}

async fn static_handler(State(_state): State<Arc<AppState>>, request: Request<axum::body::Body>) -> Response {
    let path = request.uri().path().to_string();
    assets::serve(&path)
}

pub mod browse;
pub mod charts;
pub mod collect;
pub mod correlate;
pub mod export;
pub mod graph;
pub mod iocs;
pub mod pick;
pub mod report;
pub mod rules;
pub mod secure;
pub mod timeline;
pub mod usn;

use std::path::{Path, PathBuf};
use std::sync::Arc;

use axum::extract::State;
use axum::http::StatusCode;
use axum::Json;
use serde::{Deserialize, Serialize};

use browse::{BrowseRequest, BrowseResponse};

use crate::server::state::{AppState, OpenCase, APP_NAME, APP_VERSION};
use crate::settings::{store, Settings};
use crate::util::hash::sha256_file;
use crate::vault::{audit, case_store, evidence_store, finding_store, record_store, Vault};

#[derive(Serialize)]
pub struct Bootstrap {
    pub app_name: String,
    pub version: String,
    pub setup_complete: bool,
    pub settings: Settings,
    pub default_cases_dir: String,
    pub plugins: Vec<String>,
}

pub async fn bootstrap(State(state): State<Arc<AppState>>) -> Json<Bootstrap> {
    let inner = state.inner.lock().unwrap();
    Json(Bootstrap {
        app_name: APP_NAME.to_string(),
        version: APP_VERSION.to_string(),
        setup_complete: inner.settings.setup_complete,
        settings: inner.settings.clone(),
        default_cases_dir: state.paths.default_cases_dir.display().to_string(),
        plugins: state.registry.ids().iter().map(|s| s.to_string()).collect(),
    })
}

#[derive(Deserialize)]
pub struct SetupRequest {
    pub storage_mode: String,
    pub cases_dir: String,
    pub analyst: String,
    pub organization: String,
    pub default_timezone: String,
    pub downgrade_cloud_sync: bool,
    pub encrypt_new_vaults: bool,
    pub auto_shutdown_seconds: u64,
    pub theme: String,
}

pub async fn save_setup(
    State(state): State<Arc<AppState>>,
    Json(req): Json<SetupRequest>,
) -> Result<Json<Settings>, StatusCode> {
    let cases_dir = PathBuf::from(&req.cases_dir);
    if !store::is_writable(&cases_dir) {
        return Err(StatusCode::BAD_REQUEST);
    }
    let settings = Settings {
        setup_complete: true,
        storage_mode: req.storage_mode,
        cases_dir: req.cases_dir,
        analyst: req.analyst,
        organization: req.organization,
        default_timezone: req.default_timezone,
        downgrade_cloud_sync: req.downgrade_cloud_sync,
        encrypt_new_vaults: req.encrypt_new_vaults,
        auto_shutdown_seconds: req.auto_shutdown_seconds,
        theme: req.theme,
    };
    store::save(&state.paths.settings_path, &settings).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let mut inner = state.inner.lock().unwrap();
    inner.settings = settings.clone();
    Ok(Json(settings))
}

#[derive(Serialize)]
pub struct CaseSummary {
    pub file: String,
    pub name: String,
    pub number: String,
}

pub async fn list_cases(State(state): State<Arc<AppState>>) -> Json<Vec<CaseSummary>> {
    let dir = {
        let inner = state.inner.lock().unwrap();
        PathBuf::from(inner.settings.cases_dir.clone())
    };
    let mut out = Vec::new();
    if let Ok(entries) = std::fs::read_dir(&dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) == Some("vault") {
                let info = Vault::open(&path).ok().and_then(|v| case_store::get(&v.conn).ok());
                let name = info
                    .as_ref()
                    .map(|c| c.name.clone())
                    .unwrap_or_else(|| path.file_stem().unwrap_or_default().to_string_lossy().to_string());
                let number = info.as_ref().map(|c| c.number.clone()).unwrap_or_default();
                out.push(CaseSummary { file: path.display().to_string(), name, number });
            }
        }
    }
    Json(out)
}

#[derive(Deserialize)]
pub struct CreateCaseRequest {
    pub name: String,
    pub number: String,
    pub analyst: String,
    pub notes: String,
}

#[derive(Serialize)]
pub struct CaseState {
    pub name: String,
    pub number: String,
    pub analyst: String,
    pub display_timezone: String,
    pub created_utc: String,
    pub file: String,
    pub evidence: Vec<evidence_store::Evidence>,
}

pub async fn create_case(
    State(state): State<Arc<AppState>>,
    Json(req): Json<CreateCaseRequest>,
) -> Result<Json<CaseState>, StatusCode> {
    let dir = {
        let inner = state.inner.lock().unwrap();
        PathBuf::from(inner.settings.cases_dir.clone())
    };
    std::fs::create_dir_all(&dir).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let file = dir.join(format!("{}.vault", safe_file_name(&req.name)));
    let vault = Vault::create(&file, &req.name, &req.number, &req.analyst, &req.notes)
        .map_err(|_| StatusCode::CONFLICT)?;
    set_open_case(&state, file.clone(), vault);
    current_case_state(&state)
}

#[derive(Deserialize)]
pub struct OpenCaseRequest {
    pub file: String,
}

pub async fn open_case(
    State(state): State<Arc<AppState>>,
    Json(req): Json<OpenCaseRequest>,
) -> Result<Json<CaseState>, StatusCode> {
    let path = PathBuf::from(&req.file);
    let vault = Vault::open(&path).map_err(|_| StatusCode::NOT_FOUND)?;
    set_open_case(&state, path, vault);
    current_case_state(&state)
}

pub async fn case_state(State(state): State<Arc<AppState>>) -> Result<Json<CaseState>, StatusCode> {
    current_case_state(&state)
}

pub async fn audit_log(
    State(state): State<Arc<AppState>>,
) -> Result<Json<Vec<audit::AuditEntry>>, StatusCode> {
    let inner = state.inner.lock().unwrap();
    let case = inner.open_case.as_ref().ok_or(StatusCode::BAD_REQUEST)?;
    let entries = audit::list(&case.vault.conn).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(Json(entries))
}

#[derive(Deserialize)]
pub struct DeleteCaseRequest {
    pub file: String,
}

#[derive(Serialize)]
pub struct DeleteCaseResponse {
    pub deleted: bool,
}

pub async fn delete_case(
    State(state): State<Arc<AppState>>,
    Json(req): Json<DeleteCaseRequest>,
) -> Result<Json<DeleteCaseResponse>, StatusCode> {
    let path = PathBuf::from(&req.file);
    if path.extension().and_then(|e| e.to_str()) != Some("vault") {
        return Err(StatusCode::BAD_REQUEST);
    }
    {
        let mut inner = state.inner.lock().unwrap();
        let is_open = inner.open_case.as_ref().map(|c| c.path == path).unwrap_or(false);
        if is_open {
            inner.open_case = None;
        }
    }
    let mut removed = false;
    for suffix in ["", "-wal", "-shm"] {
        let p = PathBuf::from(format!("{}{}", path.display(), suffix));
        if p.exists() && std::fs::remove_file(&p).is_ok() {
            removed = true;
        }
    }
    if removed {
        Ok(Json(DeleteCaseResponse { deleted: true }))
    } else {
        Err(StatusCode::NOT_FOUND)
    }
}

#[derive(Deserialize)]
pub struct AddEvidenceRequest {
    pub path: String,
}

#[derive(Serialize)]
pub struct AddEvidenceResponse {
    pub evidence_id: i64,
    pub plugin: String,
    pub size: i64,
    pub sha256: String,
}

pub async fn add_evidence(
    State(state): State<Arc<AppState>>,
    Json(req): Json<AddEvidenceRequest>,
) -> Result<Json<AddEvidenceResponse>, (StatusCode, String)> {
    let path = PathBuf::from(&req.path);
    if !path.is_file() {
        return Err((StatusCode::BAD_REQUEST, String::from("The path is not a file.")));
    }
    let plugin = state.registry.identify_path(&path).ok_or((
        StatusCode::UNSUPPORTED_MEDIA_TYPE,
        String::from(
            "This file is not a recognized artifact. Only the $MFT is supported right now. $UsnJrnl ($J), $LogFile and $I30 come in later versions.",
        ),
    ))?;
    let size = std::fs::metadata(&path).map(|m| m.len() as i64).unwrap_or(0);
    let sha = sha256_file(&path)
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, String::from("Could not hash the file.")))?;
    let name = path.file_name().unwrap_or_default().to_string_lossy().to_string();

    let inner = state.inner.lock().unwrap();
    let case = inner
        .open_case
        .as_ref()
        .ok_or((StatusCode::BAD_REQUEST, String::from("No case is open.")))?;
    if evidence_store::count_by_plugin(&case.vault.conn, plugin).unwrap_or(0) > 0 {
        let existing = evidence_store::list(&case.vault.conn)
            .unwrap_or_default()
            .into_iter()
            .find(|e| e.plugin == plugin)
            .map(|e| e.name)
            .unwrap_or_default();
        return Err((
            StatusCode::CONFLICT,
            format!(
                "This case already has a {} ({}). Remove it first to add another {}.",
                plugin_label(plugin),
                existing,
                plugin_label(plugin)
            ),
        ));
    }
    let id = evidence_store::add(&case.vault.conn, &name, &req.path, size, &sha, plugin)
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, String::from("Could not store the evidence.")))?;
    audit::record(&case.vault.conn, "analyst", "evidence_added", &name).ok();
    Ok(Json(AddEvidenceResponse { evidence_id: id, plugin: plugin.to_string(), size, sha256: sha }))
}

fn plugin_label(plugin: &str) -> String {
    match plugin {
        "mft" => String::from("$MFT"),
        "usnjrnl" => String::from("$UsnJrnl $J"),
        "secure" => String::from("$Secure"),
        "logfile" => String::from("$LogFile"),
        "i30" => String::from("$I30"),
        other => other.to_string(),
    }
}

#[derive(Deserialize)]
pub struct EvidenceIdRequest {
    pub evidence_id: i64,
}

pub async fn delete_evidence(
    State(state): State<Arc<AppState>>,
    Json(req): Json<EvidenceIdRequest>,
) -> Result<Json<OkResponse>, (StatusCode, String)> {
    let inner = state.inner.lock().unwrap();
    let case = inner
        .open_case
        .as_ref()
        .ok_or((StatusCode::BAD_REQUEST, String::from("No case is open.")))?;
    let removed = evidence_store::get(&case.vault.conn, req.evidence_id).ok().flatten();
    evidence_store::remove(&case.vault.conn, req.evidence_id)
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, String::from("Could not remove the evidence.")))?;
    let label = removed.map(|e| e.name).unwrap_or_default();
    audit::record(&case.vault.conn, "analyst", "evidence_removed", &label).ok();
    Ok(Json(OkResponse { ok: true }))
}

#[derive(Deserialize)]
pub struct ParseRequest {
    pub evidence_id: i64,
    pub path: String,
    pub plugin: String,
}

#[derive(Serialize)]
pub struct JobStarted {
    pub job_id: u64,
}

pub async fn parse_evidence(
    State(state): State<Arc<AppState>>,
    Json(req): Json<ParseRequest>,
) -> Result<Json<JobStarted>, StatusCode> {
    let case_path = state.open_case_path().ok_or(StatusCode::BAD_REQUEST)?;
    if state.registry.by_id(&req.plugin).is_none() {
        return Err(StatusCode::BAD_REQUEST);
    }
    let size = std::fs::metadata(&req.path).map(|m| m.len()).unwrap_or(0);
    let estimate = if size > 0 { size / 1024 } else { 0 };
    let job = state.jobs.create(req.evidence_id, estimate);
    let job_id = job.id;

    let state2 = state.clone();
    let path = req.path.clone();
    let plugin_id = req.plugin.clone();
    let evidence_id = req.evidence_id;
    let ctx = job.ctx.clone();

    tokio::task::spawn_blocking(move || {
        let outcome = run_ingest(&state2, &case_path, &path, &plugin_id, evidence_id, &ctx);
        state2.jobs.finish(job_id, outcome);
    });

    Ok(Json(JobStarted { job_id }))
}

fn run_ingest(
    state: &Arc<AppState>,
    case_path: &Path,
    file_path: &str,
    plugin_id: &str,
    evidence_id: i64,
    ctx: &Arc<crate::plugins::artifact_plugin::IngestCtx>,
) -> crate::server::jobs::Outcome {
    use crate::server::jobs::Outcome;
    let mut vault = match Vault::open(case_path) {
        Ok(v) => v,
        Err(e) => return Outcome::Error(e.to_string()),
    };
    let plugin = match state.registry.by_id(plugin_id) {
        Some(p) => p,
        None => return Outcome::Error(String::from("unknown plugin")),
    };
    match plugin.ingest(Path::new(file_path), &mut vault, evidence_id, ctx) {
        Ok(stats) => {
            if stats.cancelled {
                Outcome::Cancelled(stats)
            } else {
                let _ = crate::vault::evidence_store::mark_parsed(&vault.conn, evidence_id);
                ctx.set_phase("Detecting");
                let downgrade = state.inner.lock().unwrap().settings.downgrade_cloud_sync;
                let mut options = crate::detection::DetectionOptions::default();
                options.downgrade_cloud = downgrade;
                if let Ok(summary) = crate::detection::run(&mut vault.conn, evidence_id, &options) {
                    let _ = crate::vault::audit::record(
                        &vault.conn,
                        "system",
                        "detection_run",
                        &format!("{} findings on evidence {}", summary.findings, evidence_id),
                    );
                }
                Outcome::Done(stats)
            }
        }
        Err(e) => Outcome::Error(e.to_string()),
    }
}

#[derive(Deserialize)]
pub struct JobQuery {
    pub job_id: u64,
}

pub async fn job_status(
    State(state): State<Arc<AppState>>,
    Json(req): Json<JobQuery>,
) -> Result<Json<crate::server::jobs::JobView>, StatusCode> {
    let job = state.jobs.get(req.job_id).ok_or(StatusCode::NOT_FOUND)?;
    Ok(Json(job.view()))
}

pub async fn job_cancel(
    State(state): State<Arc<AppState>>,
    Json(req): Json<JobQuery>,
) -> Result<Json<crate::server::jobs::JobView>, StatusCode> {
    let job = state.jobs.get(req.job_id).ok_or(StatusCode::NOT_FOUND)?;
    job.ctx.request_cancel();
    Ok(Json(job.view()))
}

#[derive(Deserialize)]
pub struct RecordsQuery {
    pub evidence_id: i64,
    pub offset: i64,
    pub limit: i64,
    #[serde(default)]
    pub search: String,
    #[serde(default)]
    pub deleted_only: bool,
    #[serde(default)]
    pub ads_only: bool,
    #[serde(default)]
    pub dir_only: bool,
    #[serde(default)]
    pub orphan_only: bool,
    #[serde(default)]
    pub si_lt_fn_only: bool,
    #[serde(default)]
    pub fn_lt_si_only: bool,
    #[serde(default)]
    pub after: String,
    #[serde(default)]
    pub before: String,
}

#[derive(Serialize)]
pub struct RecordRow {
    #[serde(flatten)]
    pub record: record_store::StoredRecord,
    pub sources: Vec<String>,
    pub correlated: bool,
}

#[derive(Serialize)]
pub struct RecordsPage {
    pub total: i64,
    pub rows: Vec<RecordRow>,
}

pub async fn records(
    State(state): State<Arc<AppState>>,
    Json(req): Json<RecordsQuery>,
) -> Result<Json<RecordsPage>, StatusCode> {
    let inner = state.inner.lock().unwrap();
    let case = inner.open_case.as_ref().ok_or(StatusCode::BAD_REQUEST)?;
    let limit = req.limit.clamp(1, 1000);
    let filter = record_store::RecordFilter {
        search: req.search.clone(),
        deleted_only: req.deleted_only,
        ads_only: req.ads_only,
        dir_only: req.dir_only,
        orphan_only: req.orphan_only,
        si_lt_fn_only: req.si_lt_fn_only,
        fn_lt_si_only: req.fn_lt_si_only,
        after: req.after.clone(),
        before: req.before.clone(),
    };
    let total = record_store::count_filtered(&case.vault.conn, req.evidence_id, &filter)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let rows = record_store::page_filtered(&case.vault.conn, req.evidence_id, &filter, req.offset, limit)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let secure = correlate::secure_ids(&case.vault.conn);
    let entries: Vec<i64> = rows.iter().map(|r| r.entry).collect();
    let usn = correlate::usn_entries(&case.vault.conn, &entries);
    let rows = rows
        .into_iter()
        .map(|r| {
            let sources = correlate::sources_for(r.entry, r.security_id, &usn, &secure);
            let correlated = sources.len() >= 2;
            RecordRow { record: r, sources, correlated }
        })
        .collect();
    Ok(Json(RecordsPage { total, rows }))
}

#[derive(Deserialize)]
pub struct FindingsQuery {
    pub evidence_id: i64,
    pub offset: i64,
    pub limit: i64,
    #[serde(default)]
    pub severity: String,
    #[serde(default)]
    pub status: String,
    #[serde(default)]
    pub rule_id: String,
    #[serde(default)]
    pub search: String,
}

#[derive(Serialize)]
pub struct FindingRow {
    #[serde(flatten)]
    pub finding: finding_store::Finding,
    pub sources: Vec<String>,
    pub correlated: bool,
}

#[derive(Serialize)]
pub struct FindingsPage {
    pub total: i64,
    pub rows: Vec<FindingRow>,
    pub stats: finding_store::FindingStats,
    pub ranked: Vec<finding_store::RankedFile>,
}

pub async fn findings(
    State(state): State<Arc<AppState>>,
    Json(req): Json<FindingsQuery>,
) -> Result<Json<FindingsPage>, StatusCode> {
    let inner = state.inner.lock().unwrap();
    let case = inner.open_case.as_ref().ok_or(StatusCode::BAD_REQUEST)?;
    let conn = &case.vault.conn;
    let limit = req.limit.clamp(1, 1000);
    let filter = finding_store::FindingFilter {
        severity: req.severity.clone(),
        status: req.status.clone(),
        rule_id: req.rule_id.clone(),
        search: req.search.clone(),
    };
    let total = finding_store::count(conn, req.evidence_id, &filter)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let rows = finding_store::list(conn, req.evidence_id, &filter, req.offset, limit)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let stats = finding_store::stats_filtered(conn, req.evidence_id, &filter)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let ranked = finding_store::ranked_files(conn, req.evidence_id, 50)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let entries: Vec<i64> = rows.iter().map(|r| r.entry).collect();
    let usn = correlate::usn_entries(conn, &entries);
    let rows = rows
        .into_iter()
        .map(|f| {
            let mut sources = vec![String::from("$MFT")];
            if usn.contains(&f.entry) {
                sources.push(String::from("$UsnJrnl"));
            }
            if f.rule_id == "MFT-OWN-01" {
                sources.push(String::from("$Secure"));
            }
            let correlated = sources.len() >= 2;
            FindingRow { finding: f, sources, correlated }
        })
        .collect();
    Ok(Json(FindingsPage { total, rows, stats, ranked }))
}

#[derive(Serialize)]
pub struct OkResponse {
    pub ok: bool,
}

#[derive(Serialize)]
pub struct FindingGroupsPage {
    pub total: i64,
    pub groups: Vec<finding_store::FindingGroup>,
    pub stats: finding_store::GroupTally,
}

pub async fn findings_grouped(
    State(state): State<Arc<AppState>>,
    Json(req): Json<FindingsQuery>,
) -> Result<Json<FindingGroupsPage>, StatusCode> {
    let inner = state.inner.lock().unwrap();
    let case = inner.open_case.as_ref().ok_or(StatusCode::BAD_REQUEST)?;
    let conn = &case.vault.conn;
    let limit = req.limit.clamp(1, 1000);
    let filter = finding_store::FindingFilter {
        severity: req.severity.clone(),
        status: req.status.clone(),
        rule_id: req.rule_id.clone(),
        search: req.search.clone(),
    };
    let (tally, groups) = finding_store::grouped(conn, req.evidence_id, &filter, req.offset, limit)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(Json(FindingGroupsPage { total: tally.folders, groups, stats: tally }))
}

#[derive(Deserialize)]
pub struct FindingStatusRequest {
    pub id: i64,
    pub status: String,
    #[serde(default)]
    pub notes: String,
}

pub async fn finding_status(
    State(state): State<Arc<AppState>>,
    Json(req): Json<FindingStatusRequest>,
) -> Result<Json<OkResponse>, StatusCode> {
    let allowed = ["new", "confirmed", "false_positive"];
    if !allowed.contains(&req.status.as_str()) {
        return Err(StatusCode::BAD_REQUEST);
    }
    let inner = state.inner.lock().unwrap();
    let case = inner.open_case.as_ref().ok_or(StatusCode::BAD_REQUEST)?;
    let analyst = inner.settings.analyst.clone();
    finding_store::set_status(&case.vault.conn, req.id, &req.status, &req.notes)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let _ = crate::vault::audit::record(
        &case.vault.conn,
        &analyst,
        "finding_status_changed",
        &format!("finding {} set to {}", req.id, req.status),
    );
    Ok(Json(OkResponse { ok: true }))
}

#[derive(Deserialize)]
pub struct FindingStatusGroupRequest {
    pub evidence_id: i64,
    pub rule_id: String,
    pub status: String,
}

#[derive(Serialize)]
pub struct FindingStatusGroupResponse {
    pub updated: usize,
}

pub async fn finding_status_group(
    State(state): State<Arc<AppState>>,
    Json(req): Json<FindingStatusGroupRequest>,
) -> Result<Json<FindingStatusGroupResponse>, StatusCode> {
    let allowed = ["new", "confirmed", "false_positive"];
    if !allowed.contains(&req.status.as_str()) {
        return Err(StatusCode::BAD_REQUEST);
    }
    let inner = state.inner.lock().unwrap();
    let case = inner.open_case.as_ref().ok_or(StatusCode::BAD_REQUEST)?;
    let analyst = inner.settings.analyst.clone();
    let updated = finding_store::set_status_by_rule(&case.vault.conn, req.evidence_id, &req.rule_id, &req.status)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let _ = crate::vault::audit::record(
        &case.vault.conn,
        &analyst,
        "finding_status_changed",
        &format!("{} findings of rule {} set to {}", updated, req.rule_id, req.status),
    );
    Ok(Json(FindingStatusGroupResponse { updated }))
}

#[derive(Deserialize)]
pub struct DetectRequest {
    pub evidence_id: i64,
}

pub async fn detect(
    State(state): State<Arc<AppState>>,
    Json(req): Json<DetectRequest>,
) -> Result<Json<crate::detection::DetectionSummary>, StatusCode> {
    let case_path = state.open_case_path().ok_or(StatusCode::BAD_REQUEST)?;
    let downgrade = state.inner.lock().unwrap().settings.downgrade_cloud_sync;
    let evidence_id = req.evidence_id;
    let summary = tokio::task::spawn_blocking(move || {
        let mut vault = Vault::open(&case_path).map_err(|e| e.to_string())?;
        let mut options = crate::detection::DetectionOptions::default();
        options.downgrade_cloud = downgrade;
        let summary = crate::detection::run(&mut vault.conn, evidence_id, &options)
            .map_err(|e| e.to_string())?;
        let _ = crate::vault::audit::record(
            &vault.conn,
            "system",
            "detection_run",
            &format!("{} findings on evidence {}", summary.findings, evidence_id),
        );
        Ok::<crate::detection::DetectionSummary, String>(summary)
    })
    .await
    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(Json(summary))
}

#[derive(Deserialize)]
pub struct TimezoneRequest {
    pub timezone: String,
}

pub async fn set_timezone(
    State(state): State<Arc<AppState>>,
    Json(req): Json<TimezoneRequest>,
) -> Result<Json<CaseState>, StatusCode> {
    {
        let inner = state.inner.lock().unwrap();
        let case = inner.open_case.as_ref().ok_or(StatusCode::BAD_REQUEST)?;
        case_store::set_timezone(&case.vault.conn, &req.timezone)
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    }
    current_case_state(&state)
}

pub async fn browse_files(Json(req): Json<BrowseRequest>) -> Json<BrowseResponse> {
    Json(browse::browse(&req))
}

pub async fn pick_file(Json(req): Json<pick::PickRequest>) -> Json<pick::PickResponse> {
    let outcome = tokio::task::spawn_blocking(move || pick::pick(&req)).await;
    match outcome {
        Ok(res) => Json(res),
        Err(_) => Json(pick::PickResponse { path: None, supported: false }),
    }
}

#[derive(Serialize)]
pub struct UploadResponse {
    pub path: String,
}

pub async fn upload_file(
    State(state): State<Arc<AppState>>,
    headers: axum::http::HeaderMap,
    body: axum::body::Body,
) -> Result<Json<UploadResponse>, StatusCode> {
    use futures_util::StreamExt;
    use tokio::io::AsyncWriteExt;

    let raw_name = headers
        .get("x-filename")
        .and_then(|h| h.to_str().ok())
        .unwrap_or("dropped.bin");
    let name = sanitize_upload_name(raw_name);
    let dir = state.paths.base_dir.join("uploads");
    tokio::fs::create_dir_all(&dir)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let target = dir.join(&name);
    let mut file = tokio::fs::File::create(&target)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let mut stream = body.into_data_stream();
    while let Some(chunk) = stream.next().await {
        let bytes = chunk.map_err(|_| StatusCode::BAD_REQUEST)?;
        file.write_all(&bytes)
            .await
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    }
    file.flush().await.map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(Json(UploadResponse { path: target.display().to_string() }))
}

fn sanitize_upload_name(name: &str) -> String {
    let base = name.rsplit(['/', '\\']).next().unwrap_or(name);
    let cleaned: String = base
        .chars()
        .map(|c| if c.is_alphanumeric() || c == '.' || c == '-' || c == '_' || c == '$' { c } else { '_' })
        .collect();
    if cleaned.is_empty() {
        String::from("dropped.bin")
    } else {
        cleaned
    }
}

#[derive(Deserialize)]
pub struct StatsRequest {
    pub evidence_id: i64,
}

pub async fn evidence_stats(
    State(state): State<Arc<AppState>>,
    Json(req): Json<StatsRequest>,
) -> Result<Json<record_store::RecordStats>, StatusCode> {
    let inner = state.inner.lock().unwrap();
    let case = inner.open_case.as_ref().ok_or(StatusCode::BAD_REQUEST)?;
    let stats = record_store::stats(&case.vault.conn, req.evidence_id)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(Json(stats))
}

fn set_open_case(state: &Arc<AppState>, path: PathBuf, vault: Vault) {
    let mut inner = state.inner.lock().unwrap();
    inner.open_case = Some(OpenCase { path, vault });
}

fn current_case_state(state: &Arc<AppState>) -> Result<Json<CaseState>, StatusCode> {
    let inner = state.inner.lock().unwrap();
    let case = inner.open_case.as_ref().ok_or(StatusCode::BAD_REQUEST)?;
    let info = case_store::get(&case.vault.conn).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let evidence = evidence_store::list(&case.vault.conn).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(Json(CaseState {
        name: info.name,
        number: info.number,
        analyst: info.analyst,
        display_timezone: info.display_timezone,
        created_utc: info.created_utc,
        file: case.path.display().to_string(),
        evidence,
    }))
}

fn safe_file_name(name: &str) -> String {
    let mut out: String = name
        .chars()
        .map(|c| if c.is_alphanumeric() || c == '-' || c == '_' { c } else { '_' })
        .collect();
    if out.is_empty() {
        out.push_str("case");
    }
    out
}

pub fn is_file_path(path: &str) -> bool {
    Path::new(path).is_file()
}

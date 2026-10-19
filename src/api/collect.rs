//! Collect API: enumerate volumes and pull NTFS metafiles off a live volume,
//! optionally straight into a parsed case vault.

use std::io::BufWriter;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use axum::extract::State;
use axum::http::StatusCode;
use axum::Json;
use serde::{Deserialize, Serialize};

use crate::collect::{self, volume, Target};
use crate::server::state::AppState;
use crate::vault::{audit, evidence_store, Vault};

use super::{sha256_file, set_open_case};

/// GET /api/collect/volumes
pub async fn volumes() -> Json<VolumesReply> {
    let list = tokio::task::spawn_blocking(volume::list_volumes)
        .await
        .unwrap_or_default();
    let supported = cfg!(windows);
    Json(VolumesReply { supported, volumes: list })
}

#[derive(Serialize)]
pub struct VolumesReply {
    pub supported: bool,
    pub volumes: Vec<volume::VolumeInfo>,
}

#[derive(Deserialize)]
pub struct CollectRequest {
    pub volume: String,
    #[serde(default)]
    pub targets: Vec<String>,
    #[serde(default)]
    pub out_dir: Option<String>,
    #[serde(default)]
    pub into_case: Option<IntoCase>,
}

#[derive(Deserialize, Clone)]
pub struct IntoCase {
    pub name: String,
    #[serde(default)]
    pub number: String,
    #[serde(default)]
    pub analyst: String,
    #[serde(default)]
    pub notes: String,
}

#[derive(Serialize)]
pub struct CollectItem {
    pub target: String,
    pub label: String,
    pub ok: bool,
    pub bytes: u64,
    pub path: Option<String>,
    pub parsed: bool,
    pub error: Option<String>,
}

#[derive(Serialize)]
pub struct CollectReply {
    pub volume: String,
    pub out_dir: Option<String>,
    pub case_file: Option<String>,
    pub items: Vec<CollectItem>,
}

/// POST /api/collect/run
pub async fn run(
    State(state): State<Arc<AppState>>,
    Json(req): Json<CollectRequest>,
) -> Result<Json<CollectReply>, (StatusCode, String)> {
    if !cfg!(windows) {
        return Err((
            StatusCode::NOT_IMPLEMENTED,
            String::from(
                "Live collection reads a raw volume, which only works on Windows run as Administrator. On this machine, add the artifacts as files instead.",
            ),
        ));
    }
    if req.out_dir.is_none() && req.into_case.is_none() {
        return Err((
            StatusCode::BAD_REQUEST,
            String::from("Choose where to store the artifacts: a folder, a new case, or both."),
        ));
    }

    // Resolve the target list.
    let targets: Vec<Target> = if req.targets.is_empty() {
        Target::all().to_vec()
    } else {
        let mut t = Vec::new();
        for id in &req.targets {
            match Target::from_id(id) {
                Some(x) => t.push(x),
                None => {
                    return Err((StatusCode::BAD_REQUEST, format!("Unknown target '{id}'.")))
                }
            }
        }
        t
    };

    let state2 = state.clone();
    let result = tokio::task::spawn_blocking(move || collect_blocking(&state2, &req, &targets))
        .await
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, String::from("Collection task failed.")))?;

    result.map(Json)
}

fn collect_blocking(
    state: &Arc<AppState>,
    req: &CollectRequest,
    targets: &[Target],
) -> Result<CollectReply, (StatusCode, String)> {
    // Decide the folder that raw streams are written to.
    let cases_dir = {
        let inner = state.inner.lock().unwrap();
        PathBuf::from(inner.settings.cases_dir.clone())
    };

    // If collecting into a case, create the vault up front.
    let mut case_file: Option<PathBuf> = None;
    let out_dir: PathBuf = if let Some(spec) = &req.into_case {
        std::fs::create_dir_all(&cases_dir)
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Could not create cases folder: {e}")))?;
        let file = cases_dir.join(format!("{}.vault", super::safe_file_name(&spec.name)));
        let vault = Vault::create(&file, &spec.name, &spec.number, &spec.analyst, &spec.notes)
            .map_err(|_| (StatusCode::CONFLICT, String::from("A case with that name already exists.")))?;
        // we only needed it created; reopen later per ingest
        drop(vault);
        case_file = Some(file.clone());
        // raw streams live beside the vault unless the user also picked a folder
        match &req.out_dir {
            Some(d) => PathBuf::from(d),
            None => {
                let d = cases_dir.join(format!("{}_artifacts", super::safe_file_name(&spec.name)));
                std::fs::create_dir_all(&d).map_err(|e| {
                    (StatusCode::INTERNAL_SERVER_ERROR, format!("Could not create artifacts folder: {e}"))
                })?;
                d
            }
        }
    } else {
        let d = PathBuf::from(req.out_dir.as_ref().unwrap());
        std::fs::create_dir_all(&d)
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Could not create folder: {e}")))?;
        d
    };

    // Open the volume once.
    let mut collector = volume::open_volume(&req.volume).map_err(|e| {
        (
            StatusCode::FORBIDDEN,
            format!(
                "Could not open volume {}: {e}. Live collection needs to run as Administrator.",
                req.volume
            ),
        )
    })?;

    let mut items = Vec::new();
    for target in targets {
        let dest = out_dir.join(target.out_name());
        let item = match extract_one(&mut collector, *target, &dest) {
            Ok(bytes) => CollectItem {
                target: target.id().to_string(),
                label: label_for(*target),
                ok: true,
                bytes,
                path: Some(dest.display().to_string()),
                parsed: false,
                error: None,
            },
            Err(e) => CollectItem {
                target: target.id().to_string(),
                label: label_for(*target),
                ok: false,
                bytes: 0,
                path: None,
                parsed: false,
                error: Some(e.to_string()),
            },
        };
        items.push(item);
    }

    // If collecting into a case, add + parse each successfully written stream.
    if let Some(ref file) = case_file {
        for item in items.iter_mut() {
            if !item.ok {
                continue;
            }
            let path = match &item.path {
                Some(p) => p.clone(),
                None => continue,
            };
            match ingest_into_case(state, file, &path, &item.target) {
                Ok(()) => item.parsed = true,
                Err(e) => {
                    item.error = Some(format!("collected, but parsing failed: {e}"));
                }
            }
        }
        // Open the freshly built case so the user lands in it ready to use.
        if let Ok(vault) = Vault::open(file) {
            let _ = audit::record(&vault.conn, "analyst", "case_collected", &req.volume);
            set_open_case(state, file.clone(), vault);
        }
    }

    Ok(CollectReply {
        volume: req.volume.clone(),
        out_dir: Some(out_dir.display().to_string()),
        case_file: case_file.map(|f| f.display().to_string()),
        items,
    })
}

/// Extract a single target stream to `dest`.
fn extract_one<R: collect::BlockReader>(
    collector: &mut collect::Collector<R>,
    target: Target,
    dest: &Path,
) -> Result<u64, collect::CollectError> {
    let file = std::fs::File::create(dest)?;
    let mut sink = BufWriter::new(file);
    let bytes = match target {
        Target::Mft => collector.extract_mft(&mut sink)?,
        Target::Secure => collector.extract_secure(&mut sink)?,
        Target::UsnJrnl => collector.extract_usnjrnl(&mut sink)?,
    };
    use std::io::Write;
    sink.flush()?;
    Ok(bytes)
}

/// Add a collected stream as evidence in the case and run its plugin + detection.
fn ingest_into_case(
    state: &Arc<AppState>,
    case_path: &Path,
    file_path: &str,
    plugin_id: &str,
) -> Result<(), String> {
    let path = PathBuf::from(file_path);
    let size = std::fs::metadata(&path).map(|m| m.len() as i64).unwrap_or(0);
    let sha = sha256_file(&path).map_err(|_| String::from("hashing failed"))?;
    let name = path.file_name().unwrap_or_default().to_string_lossy().to_string();

    let evidence_id = {
        let vault = Vault::open(case_path).map_err(|e| e.to_string())?;
        if evidence_store::count_by_plugin(&vault.conn, plugin_id).unwrap_or(0) > 0 {
            return Err(format!("the case already has a {plugin_id} artifact"));
        }
        let id = evidence_store::add(&vault.conn, &name, file_path, size, &sha, plugin_id)
            .map_err(|e| e.to_string())?;
        audit::record(&vault.conn, "analyst", "evidence_added", &name).ok();
        id
    };

    let ctx = Arc::new(crate::plugins::artifact_plugin::IngestCtx::new(0));
    match super::run_ingest(state, case_path, file_path, plugin_id, evidence_id, &ctx) {
        crate::server::jobs::Outcome::Done(_) => Ok(()),
        crate::server::jobs::Outcome::Cancelled(_) => Err(String::from("cancelled")),
        crate::server::jobs::Outcome::Error(e) => Err(e),
        crate::server::jobs::Outcome::Running => Ok(()),
    }
}

fn label_for(target: Target) -> String {
    match target {
        Target::Mft => "$MFT".to_string(),
        Target::UsnJrnl => "$UsnJrnl $J".to_string(),
        Target::Secure => "$Secure $SDS".to_string(),
    }
}

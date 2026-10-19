use std::sync::Arc;

use axum::extract::State;
use axum::http::StatusCode;
use axum::Json;
use serde::{Deserialize, Serialize};

use crate::detection::is_zeroed;
use crate::server::state::AppState;
use crate::vault::{finding_store, record_store};
use rusqlite::Connection;

#[derive(Deserialize)]
pub struct EventsQuery {
    pub evidence_id: i64,
    pub entries: Vec<i64>,
}

#[derive(Serialize)]
pub struct Ev {
    pub label: String,
    pub full: String,
    pub time: String,
}

#[derive(Serialize)]
pub struct Lane {
    pub entry: i64,
    pub name: String,
    pub path: String,
    pub deleted: bool,
    pub findings: Vec<String>,
    pub events: Vec<Ev>,
}

pub async fn events(
    State(state): State<Arc<AppState>>,
    Json(req): Json<EventsQuery>,
) -> Result<Json<Vec<Lane>>, StatusCode> {
    let inner = state.inner.lock().unwrap();
    let case = inner.open_case.as_ref().ok_or(StatusCode::BAD_REQUEST)?;
    let conn = &case.vault.conn;
    let mut lanes = Vec::new();
    for entry in req.entries.iter().take(16) {
        if let Some(rec) = record_store::get(conn, req.evidence_id, *entry).ok().flatten() {
            lanes.push(lane_for(conn, req.evidence_id, &rec));
        }
    }
    Ok(Json(lanes))
}

fn lane_for(conn: &Connection, eid: i64, rec: &record_store::StoredRecord) -> Lane {
    let mut events = Vec::new();
    let mut add = |label: &str, full: &str, time: &str| {
        if !is_zeroed(time) {
            events.push(Ev {
                label: label.to_string(),
                full: full.to_string(),
                time: time.to_string(),
            });
        }
    };
    add("B", "Standard Information created", &rec.si_created);
    add("M", "Standard Information modified", &rec.si_modified);
    add("C", "Standard Information MFT changed", &rec.si_mft_modified);
    add("A", "Standard Information accessed", &rec.si_accessed);
    add("FN", "File Name created", &rec.fn_created);
    events.sort_by(|a, b| a.time.cmp(&b.time));
    let findings = finding_store::rules_for_entry(conn, eid, rec.entry)
        .unwrap_or_default()
        .into_iter()
        .map(|r| r.title)
        .collect();
    Lane {
        entry: rec.entry,
        name: rec.name.clone(),
        path: rec.path.clone(),
        deleted: !rec.in_use,
        findings,
        events,
    }
}

#[derive(Deserialize)]
pub struct BodyfileQuery {
    pub path: String,
    #[serde(default)]
    pub search: String,
}

#[derive(Serialize)]
pub struct BodyfileResult {
    pub returned: usize,
    pub lines: usize,
    pub truncated: bool,
    pub lanes: Vec<Lane>,
}

const BODY_LANE_CAP: usize = 5000;

pub async fn bodyfile(
    Json(req): Json<BodyfileQuery>,
) -> Result<Json<BodyfileResult>, (StatusCode, String)> {
    let path = std::path::PathBuf::from(&req.path);
    if !path.is_file() {
        return Err((StatusCode::BAD_REQUEST, String::from("The path is not a file.")));
    }
    let search = req.search.to_lowercase();
    tokio::task::spawn_blocking(move || parse_bodyfile(&path, &search))
        .await
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, String::from("Could not read the bodyfile.")))?
        .map(Json)
}

#[derive(Deserialize)]
pub struct BodyfileDefaultQuery {
    pub evidence_id: i64,
    #[serde(default)]
    pub search: String,
}

pub async fn bodyfile_default(
    State(state): State<Arc<AppState>>,
    Json(req): Json<BodyfileDefaultQuery>,
) -> Result<Json<BodyfileResult>, StatusCode> {
    let inner = state.inner.lock().unwrap();
    let case = inner.open_case.as_ref().ok_or(StatusCode::BAD_REQUEST)?;
    let conn = &case.vault.conn;
    let filter = record_store::RecordFilter {
        search: req.search.clone(),
        ..Default::default()
    };
    let total = record_store::count_filtered(conn, req.evidence_id, &filter).unwrap_or(0);
    let rows = record_store::page_filtered(conn, req.evidence_id, &filter, 0, BODY_LANE_CAP as i64)
        .unwrap_or_default();
    let truncated = total as usize > rows.len();
    let mut lanes = Vec::with_capacity(rows.len());
    for r in &rows {
        let mut events = Vec::new();
        for (label, full, time) in [
            ("B", "Created", &r.si_created),
            ("M", "Modified", &r.si_modified),
            ("C", "MFT changed", &r.si_mft_modified),
            ("A", "Accessed", &r.si_accessed),
            ("FN", "File Name created", &r.fn_created),
        ] {
            if !is_zeroed(time) {
                events.push(Ev {
                    label: label.to_string(),
                    full: full.to_string(),
                    time: time.clone(),
                });
            }
        }
        events.sort_by(|a, b| a.time.cmp(&b.time));
        lanes.push(Lane {
            entry: r.entry,
            name: r.name.clone(),
            path: r.path.clone(),
            deleted: !r.in_use,
            findings: Vec::new(),
            events,
        });
    }
    Ok(Json(BodyfileResult {
        returned: lanes.len(),
        lines: total as usize,
        truncated,
        lanes,
    }))
}

fn parse_bodyfile(path: &std::path::Path, search: &str) -> Result<BodyfileResult, (StatusCode, String)> {
    use std::io::BufRead;
    let file = std::fs::File::open(path)
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, String::from("Could not open the file.")))?;
    let reader = std::io::BufReader::new(file);
    let mut index: std::collections::HashMap<String, usize> = std::collections::HashMap::new();
    let mut lanes: Vec<Lane> = Vec::new();
    let mut lines = 0usize;
    let mut truncated = false;
    for raw in reader.lines() {
        let line = match raw {
            Ok(l) => l,
            Err(_) => break,
        };
        if line.trim().is_empty() {
            continue;
        }
        let fields: Vec<&str> = line.split('|').collect();
        if fields.len() < 11 {
            continue;
        }
        lines += 1;
        let raw_name = fields[1];
        let is_fn = raw_name.ends_with("($FILE_NAME)");
        let deleted = raw_name.contains("(deleted");
        let clean = clean_name(raw_name);
        if !search.is_empty() && !clean.to_lowercase().contains(search) {
            continue;
        }
        let inode = fields[2].parse::<i64>().unwrap_or(0);
        let atime = fields[7].parse::<i64>().unwrap_or(0);
        let mtime = fields[8].parse::<i64>().unwrap_or(0);
        let ctime = fields[9].parse::<i64>().unwrap_or(0);
        let crtime = fields[10].parse::<i64>().unwrap_or(0);
        let idx = match index.get(&clean) {
            Some(i) => *i,
            None => {
                if lanes.len() >= BODY_LANE_CAP {
                    truncated = true;
                    continue;
                }
                lanes.push(Lane {
                    entry: inode,
                    name: file_label(&clean),
                    path: clean.clone(),
                    deleted,
                    findings: Vec::new(),
                    events: Vec::new(),
                });
                index.insert(clean.clone(), lanes.len() - 1);
                lanes.len() - 1
            }
        };
        let lane = &mut lanes[idx];
        if deleted {
            lane.deleted = true;
        }
        if is_fn {
            push_event(lane, "FN", "File Name created", crtime);
        } else {
            push_event(lane, "B", "Created", crtime);
            push_event(lane, "M", "Modified", mtime);
            push_event(lane, "C", "MFT changed", ctime);
            push_event(lane, "A", "Accessed", atime);
        }
    }
    for lane in lanes.iter_mut() {
        lane.events.sort_by(|a, b| a.time.cmp(&b.time));
    }
    Ok(BodyfileResult {
        returned: lanes.len(),
        lines,
        truncated,
        lanes,
    })
}

fn push_event(lane: &mut Lane, label: &str, full: &str, secs: i64) {
    if secs == 0 {
        return;
    }
    if lane.events.iter().any(|e| e.label == label) {
        return;
    }
    lane.events.push(Ev {
        label: label.to_string(),
        full: full.to_string(),
        time: epoch_to_iso(secs),
    });
}

fn clean_name(raw: &str) -> String {
    let mut s = raw.to_string();
    loop {
        let before = s.len();
        for suffix in [" ($FILE_NAME)", " (deleted-realloc)", " (deleted)"] {
            if s.ends_with(suffix) {
                let keep = s.len() - suffix.len();
                s.truncate(keep);
            }
        }
        if s.len() == before {
            break;
        }
    }
    s.trim().to_string()
}

fn file_label(path: &str) -> String {
    let base = path.rsplit(['/', '\\']).next().unwrap_or(path);
    if base.is_empty() {
        path.to_string()
    } else {
        base.to_string()
    }
}

fn civil_from_days(z: i64) -> (i64, i64, i64) {
    let z = z + 719468;
    let era = (if z >= 0 { z } else { z - 146096 }) / 146097;
    let doe = z - era * 146097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    (if m <= 2 { y + 1 } else { y }, m, d)
}

fn epoch_to_iso(secs: i64) -> String {
    let days = secs.div_euclid(86400);
    let rem = secs.rem_euclid(86400);
    let (y, m, d) = civil_from_days(days);
    let h = rem / 3600;
    let mi = (rem % 3600) / 60;
    let s = rem % 60;
    format!("{:04}-{:02}-{:02}T{:02}:{:02}:{:02}.0000000Z", y, m, d, h, mi, s)
}

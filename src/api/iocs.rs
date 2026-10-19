use std::sync::Arc;

use axum::extract::State;
use axum::http::StatusCode;
use axum::Json;
use serde::{Deserialize, Serialize};

use crate::server::state::AppState;
use crate::vault::ioc_store::{self, Ioc};
use crate::vault::audit;

#[derive(Serialize)]
pub struct IocListResponse {
    pub count: i64,
    pub entries: Vec<Ioc>,
}

pub async fn list(State(state): State<Arc<AppState>>) -> Result<Json<IocListResponse>, StatusCode> {
    let inner = state.inner.lock().unwrap();
    let case = inner.open_case.as_ref().ok_or(StatusCode::BAD_REQUEST)?;
    let conn = &case.vault.conn;
    let count = ioc_store::count(conn).unwrap_or(0);
    let mut stmt = conn
        .prepare("SELECT name, path, size, hash FROM iocs LIMIT 200")
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let rows = stmt
        .query_map([], |row| {
            Ok(Ioc {
                name: row.get(0)?,
                path: row.get(1)?,
                size: row.get(2)?,
                hash: row.get(3)?,
            })
        })
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let entries = rows.flatten().collect();
    Ok(Json(IocListResponse { count, entries }))
}

#[derive(Deserialize)]
pub struct ImportRequest {
    pub text: String,
    #[serde(default)]
    pub format: String,
}

#[derive(Serialize)]
pub struct ImportResult {
    pub count: usize,
}

pub async fn import(
    State(state): State<Arc<AppState>>,
    Json(req): Json<ImportRequest>,
) -> Result<Json<ImportResult>, (StatusCode, String)> {
    let entries = if req.format == "json" {
        serde_json::from_str::<Vec<Ioc>>(&req.text)
            .map_err(|_| (StatusCode::BAD_REQUEST, String::from("The JSON must be an array of name, path, size and hash objects.")))?
    } else {
        parse_csv(&req.text)
    };
    if entries.is_empty() {
        return Err((StatusCode::BAD_REQUEST, String::from("No usable rows were found. Give a header row with name, path, size or hash.")));
    }
    let mut inner = state.inner.lock().unwrap();
    let case = inner.open_case.as_mut().ok_or((StatusCode::BAD_REQUEST, String::from("No case is open.")))?;
    let count = ioc_store::replace_all(&mut case.vault.conn, &entries)
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, String::from("Could not store the IOC list.")))?;
    audit::record(&case.vault.conn, "analyst", "ioc_list_imported", &format!("{} entries", count)).ok();
    Ok(Json(ImportResult { count }))
}

pub async fn clear(State(state): State<Arc<AppState>>) -> Result<Json<ImportResult>, StatusCode> {
    let inner = state.inner.lock().unwrap();
    let case = inner.open_case.as_ref().ok_or(StatusCode::BAD_REQUEST)?;
    ioc_store::clear(&case.vault.conn).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(Json(ImportResult { count: 0 }))
}

fn parse_csv(text: &str) -> Vec<Ioc> {
    let mut lines = text.lines().filter(|l| !l.trim().is_empty());
    let header = match lines.next() {
        Some(h) => h,
        None => return Vec::new(),
    };
    let cols: Vec<String> = header.split(',').map(|s| s.trim().to_ascii_lowercase()).collect();
    let find = |key: &str| cols.iter().position(|c| c == key);
    let ni = find("name");
    let pi = find("path");
    let si = find("size");
    let hi = find("hash");
    if ni.is_none() && pi.is_none() && si.is_none() && hi.is_none() {
        return Vec::new();
    }
    let mut out = Vec::new();
    for line in lines {
        let fields: Vec<&str> = line.split(',').map(|s| s.trim()).collect();
        let get = |i: Option<usize>| i.and_then(|idx| fields.get(idx)).map(|s| s.to_string()).unwrap_or_default();
        let size = si
            .and_then(|idx| fields.get(idx))
            .and_then(|s| s.trim().parse::<i64>().ok())
            .unwrap_or(0);
        let ioc = Ioc {
            name: get(ni),
            path: get(pi),
            size,
            hash: get(hi),
        };
        if !ioc.name.is_empty() || !ioc.path.is_empty() || ioc.size > 0 || !ioc.hash.is_empty() {
            out.push(ioc);
        }
    }
    out
}

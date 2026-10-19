use std::path::Path;
use std::sync::Arc;

use axum::body::{Body, Bytes};
use axum::extract::{Query, State};
use axum::http::{header, StatusCode};
use axum::response::Response;
use serde::Deserialize;
use tokio_stream::wrappers::ReceiverStream;

use crate::server::state::AppState;
use crate::vault::record_store::{self, RecordFilter, StoredRecord};
use crate::vault::Vault;

#[derive(Deserialize)]
pub struct ExportParams {
    pub evidence_id: i64,
    #[serde(default)]
    pub format: String,
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

pub async fn export_records(
    State(state): State<Arc<AppState>>,
    Query(params): Query<ExportParams>,
) -> Result<Response, StatusCode> {
    let case_path = state.open_case_path().ok_or(StatusCode::BAD_REQUEST)?;
    let as_json = params.format == "json";
    let filter = RecordFilter {
        search: params.search.clone(),
        deleted_only: params.deleted_only,
        ads_only: params.ads_only,
        dir_only: params.dir_only,
        orphan_only: params.orphan_only,
        si_lt_fn_only: params.si_lt_fn_only,
        fn_lt_si_only: params.fn_lt_si_only,
        after: params.after.clone(),
        before: params.before.clone(),
    };
    let evidence_id = params.evidence_id;

    let (tx, rx) = tokio::sync::mpsc::channel::<Result<Bytes, std::io::Error>>(32);

    tokio::task::spawn_blocking(move || {
        stream_rows(&case_path, evidence_id, &filter, as_json, &tx);
    });

    let stream = ReceiverStream::new(rx);
    let (content_type, filename) = if as_json {
        ("application/json", "records.json")
    } else {
        ("text/csv", "records.csv")
    };
    Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, content_type)
        .header(
            header::CONTENT_DISPOSITION,
            format!("attachment; filename=\"{}\"", filename),
        )
        .header(header::CACHE_CONTROL, "no-store")
        .body(Body::from_stream(stream))
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)
}

fn stream_rows(
    case_path: &Path,
    evidence_id: i64,
    filter: &RecordFilter,
    as_json: bool,
    tx: &tokio::sync::mpsc::Sender<Result<Bytes, std::io::Error>>,
) {
    let vault = match Vault::open(case_path) {
        Ok(v) => v,
        Err(_) => {
            let _ = tx.blocking_send(Ok(Bytes::from_static(b"")));
            return;
        }
    };
    let mut buffer = String::with_capacity(1 << 16);
    let mut first = true;
    if as_json {
        buffer.push('[');
    } else {
        buffer.push_str(CSV_HEADER);
        buffer.push('\n');
    }
    let result = record_store::for_each_filtered(&vault.conn, evidence_id, filter, |r| {
        if as_json {
            if !first {
                buffer.push(',');
            }
            buffer.push_str(&json_row(r));
        } else {
            buffer.push_str(&csv_row(r));
            buffer.push('\n');
        }
        first = false;
        if buffer.len() >= (1 << 16) {
            let chunk = std::mem::take(&mut buffer);
            let _ = tx.blocking_send(Ok(Bytes::from(chunk)));
        }
    });
    if result.is_err() {
        return;
    }
    if as_json {
        buffer.push(']');
    }
    if !buffer.is_empty() {
        let _ = tx.blocking_send(Ok(Bytes::from(buffer)));
    }
}

const CSV_HEADER: &str = "entry,sequence,in_use,is_directory,has_ads,orphan,parent_entry,si_created,si_modified,si_mft_modified,si_accessed,fn_created,name,path";

fn csv_row(r: &StoredRecord) -> String {
    format!(
        "{},{},{},{},{},{},{},{},{},{},{},{},{},{}",
        r.entry,
        r.sequence,
        r.in_use as u8,
        r.is_directory as u8,
        r.has_ads as u8,
        r.orphan as u8,
        r.parent_entry,
        r.si_created,
        r.si_modified,
        r.si_mft_modified,
        r.si_accessed,
        r.fn_created,
        csv_field(&r.name),
        csv_field(&r.path),
    )
}

fn csv_field(value: &str) -> String {
    if value.contains(',') || value.contains('"') || value.contains('\n') {
        format!("\"{}\"", value.replace('"', "\"\""))
    } else {
        value.to_string()
    }
}

fn json_row(r: &StoredRecord) -> String {
    serde_json::to_string(r).unwrap_or_else(|_| String::from("{}"))
}

#[derive(Deserialize)]
pub struct SimpleExport {
    pub evidence_id: i64,
}

fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = (if y >= 0 { y } else { y - 399 }) / 400;
    let yoe = y - era * 400;
    let mp = if m > 2 { m - 3 } else { m + 9 };
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146097 + doe - 719468
}

fn iso_to_epoch(s: &str) -> i64 {
    if s.len() < 19 || s.starts_with("1601-01-01") {
        return 0;
    }
    let p = |a: usize, b: usize, def: i64| s[a..b].parse::<i64>().unwrap_or(def);
    let y = p(0, 4, 1970);
    let mo = p(5, 7, 1);
    let d = p(8, 10, 1);
    let h = p(11, 13, 0);
    let mi = p(14, 16, 0);
    let se = p(17, 19, 0);
    days_from_civil(y, mo, d) * 86400 + h * 3600 + mi * 60 + se
}

pub async fn export_bodyfile(
    State(state): State<Arc<AppState>>,
    Query(params): Query<SimpleExport>,
) -> Result<Response, StatusCode> {
    let case_path = state.open_case_path().ok_or(StatusCode::BAD_REQUEST)?;
    let evidence_id = params.evidence_id;
    let (tx, rx) = tokio::sync::mpsc::channel::<Result<Bytes, std::io::Error>>(32);
    tokio::task::spawn_blocking(move || {
        let vault = match Vault::open(&case_path) {
            Ok(v) => v,
            Err(_) => return,
        };
        let mut buf = String::with_capacity(1 << 16);
        let _ = record_store::for_each_filtered(&vault.conn, evidence_id, &RecordFilter::default(), |r| {
            let deleted = if r.in_use { "" } else { " (deleted)" };
            let si_line = format!(
                "0|{}{}|{}|0|0|0|0|{}|{}|{}|{}\n",
                r.path, deleted, r.entry,
                iso_to_epoch(&r.si_accessed), iso_to_epoch(&r.si_modified),
                iso_to_epoch(&r.si_mft_modified), iso_to_epoch(&r.si_created),
            );
            buf.push_str(&si_line);
            let fn_t = iso_to_epoch(&r.fn_created);
            let fn_line = format!(
                "0|{} ($FILE_NAME){}|{}|0|0|0|0|{}|{}|{}|{}\n",
                r.path, deleted, r.entry, fn_t, fn_t, fn_t, fn_t,
            );
            buf.push_str(&fn_line);
            if buf.len() >= (1 << 16) {
                let chunk = std::mem::take(&mut buf);
                let _ = tx.blocking_send(Ok(Bytes::from(chunk)));
            }
        });
        if !buf.is_empty() {
            let _ = tx.blocking_send(Ok(Bytes::from(buf)));
        }
    });
    stream_response(rx, "text/plain", "bodyfile.txt")
}

pub async fn export_timeline(
    State(state): State<Arc<AppState>>,
    Query(params): Query<SimpleExport>,
) -> Result<Response, StatusCode> {
    let case_path = state.open_case_path().ok_or(StatusCode::BAD_REQUEST)?;
    let evidence_id = params.evidence_id;
    let (tx, rx) = tokio::sync::mpsc::channel::<Result<Bytes, std::io::Error>>(32);
    tokio::task::spawn_blocking(move || {
        let vault = match Vault::open(&case_path) {
            Ok(v) => v,
            Err(_) => return,
        };
        let mut buf = String::with_capacity(1 << 16);
        buf.push_str("Date,MACB,Source,Entry,Deleted,Path\n");
        let _ = record_store::for_each_filtered(&vault.conn, evidence_id, &RecordFilter::default(), |r| {
            let mut rows: Vec<(&str, &str)> = vec![
                (r.si_created.as_str(), "B"),
                (r.si_modified.as_str(), "M"),
                (r.si_mft_modified.as_str(), "C"),
                (r.si_accessed.as_str(), "A"),
            ];
            rows.retain(|(t, _)| !t.starts_with("1601-01-01"));
            let mut grouped: std::collections::BTreeMap<String, String> = std::collections::BTreeMap::new();
            for (t, letter) in rows {
                grouped.entry(t.to_string()).or_default().push_str(letter);
            }
            for (time, macb) in grouped {
                buf.push_str(&format!(
                    "{},{},SI,{},{},{}\n",
                    time, macb, r.entry, if r.in_use { "" } else { "deleted" }, csv_field(&r.path)
                ));
            }
            if !r.fn_created.starts_with("1601-01-01") {
                buf.push_str(&format!(
                    "{},B,FN,{},{},{}\n",
                    r.fn_created, r.entry, if r.in_use { "" } else { "deleted" }, csv_field(&r.path)
                ));
            }
            if buf.len() >= (1 << 16) {
                let chunk = std::mem::take(&mut buf);
                let _ = tx.blocking_send(Ok(Bytes::from(chunk)));
            }
        });
        if !buf.is_empty() {
            let _ = tx.blocking_send(Ok(Bytes::from(buf)));
        }
    });
    stream_response(rx, "text/csv", "timeline.csv")
}

fn stream_response(
    rx: tokio::sync::mpsc::Receiver<Result<Bytes, std::io::Error>>,
    content_type: &str,
    filename: &str,
) -> Result<Response, StatusCode> {
    let stream = ReceiverStream::new(rx);
    Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, content_type)
        .header(
            header::CONTENT_DISPOSITION,
            format!("attachment; filename=\"{}\"", filename),
        )
        .header(header::CACHE_CONTROL, "no-store")
        .body(Body::from_stream(stream))
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)
}

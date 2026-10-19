use std::sync::Arc;

use axum::extract::State;
use axum::http::StatusCode;
use axum::Json;
use rusqlite::Connection;
use serde::{Deserialize, Serialize};

use crate::server::state::AppState;
use crate::usn;
use crate::vault::usn_store::{self, UsnFilter};

#[derive(Deserialize)]
pub struct UsnQuery {
    pub evidence_id: i64,
    pub offset: i64,
    pub limit: i64,
    #[serde(default)]
    pub search: String,
    #[serde(default)]
    pub summary: String,
    #[serde(default)]
    pub after: String,
    #[serde(default)]
    pub before: String,
}

#[derive(Serialize)]
pub struct UsnRow {
    pub usn: i64,
    pub timestamp: String,
    pub entry: i64,
    pub sequence: i64,
    pub parent_entry: i64,
    pub reason: i64,
    pub summary: String,
    pub reason_text: String,
    pub source_info: i64,
    pub security_id: i64,
    pub file_attributes: i64,
    pub name: String,
    pub flag: String,
    pub sources: Vec<String>,
    pub correlated: bool,
}

fn mft_entries(conn: &Connection, entries: &[i64]) -> std::collections::HashSet<i64> {
    let mut set = std::collections::HashSet::new();
    if entries.is_empty() {
        return set;
    }
    let list = entries.iter().map(|e| e.to_string()).collect::<Vec<_>>().join(",");
    let sql = format!("SELECT DISTINCT entry FROM records WHERE entry IN ({})", list);
    if let Ok(mut stmt) = conn.prepare(&sql) {
        if let Ok(rows) = stmt.query_map([], |r| r.get::<_, i64>(0)) {
            for r in rows.flatten() {
                set.insert(r);
            }
        }
    }
    set
}

fn is_executable(name: &str) -> bool {
    let n = name.to_lowercase();
    [".exe", ".dll", ".sys", ".scr", ".bat", ".ps1", ".vbs", ".cmd", ".com"]
        .iter()
        .any(|e| n.ends_with(e))
}

fn created_then_deleted(conn: &Connection, evidence_id: i64) -> std::collections::HashSet<i64> {
    let mut set = std::collections::HashSet::new();
    let sql = "SELECT entry FROM usn_events WHERE evidence_id = ?1 AND summary = 'create'
               INTERSECT
               SELECT entry FROM usn_events WHERE evidence_id = ?1 AND summary = 'delete'";
    if let Ok(mut stmt) = conn.prepare(sql) {
        if let Ok(rows) = stmt.query_map([evidence_id], |r| r.get::<_, i64>(0)) {
            for r in rows.flatten() {
                set.insert(r);
            }
        }
    }
    set
}

#[derive(Serialize)]
pub struct SummaryBucket {
    pub summary: String,
    pub count: i64,
}

#[derive(Serialize)]
pub struct UsnReply {
    pub total: i64,
    pub rows: Vec<UsnRow>,
    pub summary_counts: Vec<SummaryBucket>,
}

pub async fn list(
    State(state): State<Arc<AppState>>,
    Json(req): Json<UsnQuery>,
) -> Result<Json<UsnReply>, StatusCode> {
    let inner = state.inner.lock().unwrap();
    let case = inner.open_case.as_ref().ok_or(StatusCode::BAD_REQUEST)?;
    let conn = &case.vault.conn;
    let limit = req.limit.clamp(1, 1000);
    let filter = UsnFilter {
        search: req.search.clone(),
        summary: req.summary.clone(),
        after: req.after.clone(),
        before: req.before.clone(),
    };
    let total = usn_store::count(conn, req.evidence_id, &filter)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let events = usn_store::page(conn, req.evidence_id, &filter, req.offset, limit)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    // Entries that were both created and deleted in the journal: a dropped file
    // that was then removed, a classic staging / anti-forensics pattern.
    let churned = created_then_deleted(conn, req.evidence_id);
    let page_entries: Vec<i64> = events.iter().map(|e| e.entry).collect();
    let in_mft = mft_entries(conn, &page_entries);

    let rows = events
        .into_iter()
        .map(|e| {
            let flag = if churned.contains(&e.entry) && is_executable(&e.name) {
                "executable created then deleted".to_string()
            } else if e.summary == "rename" && is_executable(&e.name) {
                "renamed to an executable".to_string()
            } else {
                String::new()
            };
            let mut sources = vec!["$UsnJrnl".to_string()];
            if in_mft.contains(&e.entry) {
                sources.push("$MFT".to_string());
            }
            let correlated = sources.len() >= 2;
            UsnRow {
                sources,
                correlated,
                reason_text: usn::reason_labels(e.reason as u32).join(", "),
                usn: e.usn,
                timestamp: e.timestamp,
                entry: e.entry,
                sequence: e.sequence,
                parent_entry: e.parent_entry,
                reason: e.reason,
                summary: e.summary,
                source_info: e.source_info,
                security_id: e.security_id,
                file_attributes: e.file_attributes,
                name: e.name,
                flag,
            }
        })
        .collect();
    let summary_counts = usn_store::summary_counts(conn, req.evidence_id)
        .unwrap_or_default()
        .into_iter()
        .map(|(summary, count)| SummaryBucket { summary, count })
        .collect();
    Ok(Json(UsnReply { total, rows, summary_counts }))
}

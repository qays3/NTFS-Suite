use std::collections::HashMap;
use std::sync::Arc;

use axum::extract::State;
use axum::http::StatusCode;
use axum::Json;
use serde::{Deserialize, Serialize};

use crate::detection::rule_catalog;
use crate::detection::rule_engine::{self, Rule};
use crate::server::state::AppState;
use crate::vault::record_store::{self, RecordFilter};
use crate::vault::{audit, rule_store};

#[derive(Serialize)]
pub struct RuleItem {
    pub id: String,
    pub title: String,
    pub severity: String,
    pub mitre: String,
    pub source: String,
    pub condition: String,
    pub needs: String,
    pub ships_in: String,
    pub kind: String,
    pub custom: bool,
    pub enabled: bool,
    pub count: i64,
}

#[derive(Serialize)]
pub struct RuleList {
    pub rules: Vec<RuleItem>,
}

fn counts(conn: &rusqlite::Connection) -> HashMap<String, i64> {
    let mut map = HashMap::new();
    if let Ok(mut stmt) = conn.prepare("SELECT rule_id, COUNT(*) FROM findings GROUP BY rule_id") {
        if let Ok(rows) = stmt.query_map([], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?))
        }) {
            for row in rows.flatten() {
                map.insert(row.0, row.1);
            }
        }
    }
    map
}

pub async fn list(State(state): State<Arc<AppState>>) -> Result<Json<RuleList>, StatusCode> {
    let inner = state.inner.lock().unwrap();
    let case = inner.open_case.as_ref().ok_or(StatusCode::BAD_REQUEST)?;
    let conn = &case.vault.conn;
    let enabled = rule_store::enabled_map(conn).unwrap_or_default();
    let count_map = counts(conn);
    let mut rules = Vec::new();
    for c in rule_catalog::builtin() {
        let count = count_map.get(&c.id).copied().unwrap_or(0);
        rules.push(RuleItem {
            enabled: *enabled.get(&c.id).unwrap_or(&true),
            custom: false,
            count,
            id: c.id,
            title: c.title,
            severity: c.severity,
            mitre: c.mitre,
            source: c.source,
            condition: c.condition,
            needs: c.needs,
            ships_in: c.ships_in,
            kind: c.kind,
        });
    }
    for rule in rule_store::list_custom(conn).unwrap_or_default() {
        let count = count_map.get(&rule.id).copied().unwrap_or(0);
        let condition = serde_json::to_string_pretty(&rule.condition).unwrap_or_default();
        rules.push(RuleItem {
            enabled: *enabled.get(&rule.id).unwrap_or(&true),
            custom: true,
            count,
            id: rule.id,
            title: rule.title,
            severity: rule.severity,
            mitre: rule.mitre,
            source: String::from("$MFT"),
            condition,
            needs: String::from("$MFT"),
            ships_in: String::from("custom"),
            kind: String::from("declarative"),
        });
    }
    Ok(Json(RuleList { rules }))
}

#[derive(Deserialize)]
pub struct PreviewRequest {
    pub evidence_id: i64,
    pub rule: Rule,
}

#[derive(Serialize)]
pub struct PreviewSample {
    pub entry: i64,
    pub name: String,
    pub path: String,
}

#[derive(Serialize)]
pub struct PreviewResult {
    pub count: i64,
    pub scanned: i64,
    pub truncated: bool,
    pub sample: Vec<PreviewSample>,
}

const PREVIEW_SCAN_CAP: i64 = 300_000;
const PREVIEW_PAGE: i64 = 5_000;

pub async fn preview(
    State(state): State<Arc<AppState>>,
    Json(req): Json<PreviewRequest>,
) -> Result<Json<PreviewResult>, StatusCode> {
    let inner = state.inner.lock().unwrap();
    let case = inner.open_case.as_ref().ok_or(StatusCode::BAD_REQUEST)?;
    let conn = &case.vault.conn;
    let filter = RecordFilter::default();
    let mut count = 0i64;
    let mut scanned = 0i64;
    let mut sample = Vec::new();
    let mut offset = 0i64;
    let mut truncated = false;
    loop {
        let rows = record_store::page_filtered(conn, req.evidence_id, &filter, offset, PREVIEW_PAGE)
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
        if rows.is_empty() {
            break;
        }
        for record in &rows {
            scanned += 1;
            if rule_engine::eval(&req.rule.condition, record) {
                count += 1;
                if sample.len() < 25 {
                    sample.push(PreviewSample {
                        entry: record.entry,
                        name: record.name.clone(),
                        path: record.path.clone(),
                    });
                }
            }
        }
        offset += PREVIEW_PAGE;
        if offset >= PREVIEW_SCAN_CAP {
            truncated = true;
            break;
        }
    }
    Ok(Json(PreviewResult { count, scanned, truncated, sample }))
}

#[derive(Serialize)]
pub struct SaveResult {
    pub id: String,
}

pub async fn save(
    State(state): State<Arc<AppState>>,
    Json(mut rule): Json<Rule>,
) -> Result<Json<SaveResult>, (StatusCode, String)> {
    if !matches!(rule.severity.as_str(), "high" | "medium" | "low") {
        return Err((StatusCode::BAD_REQUEST, String::from("Severity must be high, medium or low.")));
    }
    if rule.title.trim().is_empty() {
        return Err((StatusCode::BAD_REQUEST, String::from("A rule needs a title.")));
    }
    let inner = state.inner.lock().unwrap();
    let case = inner.open_case.as_ref().ok_or((StatusCode::BAD_REQUEST, String::from("No case is open.")))?;
    let conn = &case.vault.conn;
    if rule.id.trim().is_empty() {
        rule.id = rule_store::next_custom_id(conn)
            .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, String::from("Could not assign a rule id.")))?;
    }
    rule_store::upsert(conn, &rule)
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, String::from("Could not save the rule.")))?;
    audit::record(conn, "analyst", "rule_saved", &rule.id).ok();
    Ok(Json(SaveResult { id: rule.id }))
}

#[derive(Deserialize)]
pub struct RuleIdRequest {
    pub id: String,
}

pub async fn delete_rule(
    State(state): State<Arc<AppState>>,
    Json(req): Json<RuleIdRequest>,
) -> Result<Json<OkResult>, StatusCode> {
    let inner = state.inner.lock().unwrap();
    let case = inner.open_case.as_ref().ok_or(StatusCode::BAD_REQUEST)?;
    let conn = &case.vault.conn;
    rule_store::delete(conn, &req.id).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    audit::record(conn, "analyst", "rule_deleted", &req.id).ok();
    Ok(Json(OkResult { ok: true }))
}

#[derive(Deserialize)]
pub struct EnableRequest {
    pub rule_id: String,
    pub enabled: bool,
}

#[derive(Serialize)]
pub struct OkResult {
    pub ok: bool,
}

pub async fn enable(
    State(state): State<Arc<AppState>>,
    Json(req): Json<EnableRequest>,
) -> Result<Json<OkResult>, StatusCode> {
    let inner = state.inner.lock().unwrap();
    let case = inner.open_case.as_ref().ok_or(StatusCode::BAD_REQUEST)?;
    let conn = &case.vault.conn;
    rule_store::set_enabled(conn, &req.rule_id, req.enabled).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(Json(OkResult { ok: true }))
}

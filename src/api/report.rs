use std::sync::Arc;

use axum::body::Body;
use axum::extract::{Query, State};
use axum::http::{header, StatusCode};
use axum::response::Response;
use axum::Json;
use serde::{Deserialize, Serialize};

use crate::server::state::AppState;
use crate::vault::{case_store, evidence_store, finding_store, record_store};

const NOT_RUN: &[&str] = &[
    "Record number order versus creation time",
    "Executable content inside an alternate data stream",
    "Zone.Identifier download source and Mark of the Web",
    "Allocated versus real size anomalies",
    "Broken fixup and BAAD records",
];

#[derive(Deserialize)]
pub struct ReportQuery {
    pub evidence_id: i64,
    #[serde(default)]
    pub format: String,
}

#[derive(Serialize)]
pub struct ReportData {
    pub case: case_store::CaseInfo,
    pub evidence: Vec<evidence_store::Evidence>,
    pub record_stats: record_store::RecordStats,
    pub finding_stats: finding_store::FindingStats,
    pub rules: Vec<finding_store::RuleCount>,
    pub ranked: Vec<finding_store::RankedFile>,
    pub not_run: Vec<String>,
    pub generated_utc: String,
}

fn gather(conn: &rusqlite::Connection, eid: i64) -> Result<ReportData, StatusCode> {
    let case = case_store::get(conn).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let evidence = evidence_store::list(conn).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let record_stats = record_store::stats(conn, eid).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let finding_stats = finding_store::stats(conn, eid).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let rules = finding_store::by_rule(conn, eid).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let ranked = finding_store::ranked_files(conn, eid, 50).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(ReportData {
        case,
        evidence,
        record_stats,
        finding_stats,
        rules,
        ranked,
        not_run: NOT_RUN.iter().map(|s| s.to_string()).collect(),
        generated_utc: crate::util::clock::now_iso8601(),
    })
}

pub async fn report(
    State(state): State<Arc<AppState>>,
    Query(params): Query<ReportQuery>,
) -> Result<Response, StatusCode> {
    let inner = state.inner.lock().unwrap();
    let case = inner.open_case.as_ref().ok_or(StatusCode::BAD_REQUEST)?;
    let data = gather(&case.vault.conn, params.evidence_id)?;
    if params.format == "json" {
        let body = serde_json::to_string_pretty(&data).unwrap_or_default();
        return Response::builder()
            .status(StatusCode::OK)
            .header(header::CONTENT_TYPE, "application/json")
            .header(header::CONTENT_DISPOSITION, "attachment; filename=\"report.json\"")
            .header(header::CACHE_CONTROL, "no-store")
            .body(Body::from(body))
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR);
    }
    let html = render_html(&data);
    Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "text/html; charset=utf-8")
        .header(header::CONTENT_DISPOSITION, "inline; filename=\"report.html\"")
        .header(header::CACHE_CONTROL, "no-store")
        .body(Body::from(html))
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)
}

fn esc(s: &str) -> String {
    s.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;")
}

fn render_html(d: &ReportData) -> String {
    let mut h = String::with_capacity(1 << 14);
    h.push_str("<!doctype html><html><head><meta charset=\"utf-8\"><title>NTFS Suite report ");
    h.push_str(&esc(&d.case.name));
    h.push_str("</title><style>");
    h.push_str("body{font-family:Segoe UI,Arial,sans-serif;color:#1b1b1b;background:#fff;margin:40px;line-height:1.5}");
    h.push_str("h1{font-size:22px;margin:0 0 4px}h2{font-size:15px;margin:28px 0 8px;border-bottom:1px solid #ccc;padding-bottom:4px}");
    h.push_str("table{border-collapse:collapse;width:100%;margin:8px 0;font-size:12px}th,td{border:1px solid #ddd;padding:5px 8px;text-align:left}th{background:#f4f4f4}");
    h.push_str(".mut{color:#666;font-size:12px}.hi{color:#b01034;font-weight:bold}.med{color:#8a6410}.mono{font-family:Consolas,monospace;font-size:11px}");
    h.push_str("</style></head><body>");

    h.push_str(&format!("<h1>NTFS Suite findings report</h1><div class=\"mut\">Case {} &middot; number {} &middot; analyst {} &middot; generated {} UTC</div>",
        esc(&d.case.name), esc(&d.case.number), esc(&d.case.analyst), esc(&d.generated_utc)));
    h.push_str(&format!("<div class=\"mut\">Times stored in UTC. Display time zone for this case: {}.</div>", esc(&d.case.display_timezone)));

    h.push_str("<h2>Summary</h2><table><tr><th>Records</th><th>Deleted</th><th>Alternate streams</th><th>Orphans</th><th>High</th><th>Medium</th><th>Low</th><th>Flagged files</th></tr>");
    h.push_str(&format!("<tr><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td class=\"hi\">{}</td><td class=\"med\">{}</td><td>{}</td><td>{}</td></tr></table>",
        d.record_stats.records, d.record_stats.deleted, d.record_stats.with_ads, d.record_stats.orphans,
        d.finding_stats.high, d.finding_stats.medium, d.finding_stats.low, d.finding_stats.flagged_files));

    h.push_str("<h2>Evidence</h2><table><tr><th>Name</th><th>Path</th><th>Size</th><th>SHA256</th><th>Plugin</th></tr>");
    for e in &d.evidence {
        h.push_str(&format!("<tr><td>{}</td><td class=\"mono\">{}</td><td>{}</td><td class=\"mono\">{}</td><td>{}</td></tr>",
            esc(&e.name), esc(&e.source_path), e.size, esc(&e.sha256), esc(&e.plugin)));
    }
    h.push_str("</table>");

    h.push_str("<h2>Findings by rule</h2><table><tr><th>Rule</th><th>Title</th><th>Severity</th><th>MITRE</th><th>Count</th></tr>");
    for r in &d.rules {
        h.push_str(&format!("<tr><td class=\"mono\">{}</td><td>{}</td><td>{}</td><td class=\"mono\">{}</td><td>{}</td></tr>",
            esc(&r.rule_id), esc(&r.title), esc(&r.severity), esc(&r.mitre), r.count));
    }
    h.push_str("</table>");

    h.push_str("<h2>Top ranked files</h2><table><tr><th>Score</th><th>Severity</th><th>Findings</th><th>File</th><th>Path</th></tr>");
    for f in &d.ranked {
        h.push_str(&format!("<tr><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td class=\"mono\">{}</td></tr>",
            f.total_score, esc(&f.top_severity), f.finding_count, esc(&f.name), esc(&f.path)));
    }
    h.push_str("</table>");

    h.push_str("<h2>Checks not run from the $MFT alone</h2><ul>");
    for c in &d.not_run {
        h.push_str(&format!("<li>{}</li>", esc(c)));
    }
    h.push_str("</ul></body></html>");
    h
}

#[derive(Deserialize)]
pub struct IocQuery {
    pub evidence_id: i64,
}

#[derive(Serialize)]
pub struct Ioc {
    pub entry: i64,
    pub name: String,
    pub path: String,
    pub score: i64,
    pub severity: String,
}

pub async fn ioc(
    State(state): State<Arc<AppState>>,
    Query(params): Query<IocQuery>,
) -> Result<Response, StatusCode> {
    let inner = state.inner.lock().unwrap();
    let case = inner.open_case.as_ref().ok_or(StatusCode::BAD_REQUEST)?;
    let ranked = finding_store::ranked_files(&case.vault.conn, params.evidence_id, 1000)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let items: Vec<Ioc> = ranked
        .into_iter()
        .map(|r| Ioc {
            entry: r.entry,
            name: r.name,
            path: r.path,
            score: r.total_score,
            severity: r.top_severity,
        })
        .collect();
    let body = serde_json::to_string_pretty(&items).unwrap_or_default();
    Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "application/json")
        .header(header::CONTENT_DISPOSITION, "attachment; filename=\"ioc.json\"")
        .header(header::CACHE_CONTROL, "no-store")
        .body(Body::from(body))
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)
}

pub async fn report_json(
    State(state): State<Arc<AppState>>,
    Json(params): Json<ReportQuery>,
) -> Result<Json<ReportData>, StatusCode> {
    let inner = state.inner.lock().unwrap();
    let case = inner.open_case.as_ref().ok_or(StatusCode::BAD_REQUEST)?;
    let data = gather(&case.vault.conn, params.evidence_id)?;
    Ok(Json(data))
}

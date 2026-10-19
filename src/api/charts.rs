use std::collections::HashMap;
use std::sync::Arc;

use axum::extract::State;
use axum::http::StatusCode;
use axum::Json;
use rusqlite::Connection;
use serde::{Deserialize, Serialize};

use crate::server::state::AppState;

#[derive(Deserialize)]
pub struct DashboardQuery {
    pub evidence_id: i64,
    #[serde(default)]
    pub from: String,
    #[serde(default)]
    pub to: String,
}

#[derive(Serialize, Default)]
pub struct Totals {
    pub records: i64,
    pub deleted: i64,
    pub ads: i64,
    pub orphans: i64,
    pub high: i64,
    pub medium: i64,
    pub low: i64,
}

#[derive(Serialize)]
pub struct DayCount {
    pub day: String,
    pub count: i64,
}

#[derive(Serialize)]
pub struct HeatCell {
    pub dow: i64,
    pub hour: i64,
    pub count: i64,
}

#[derive(Serialize)]
pub struct NameCount {
    pub name: String,
    pub count: i64,
}

#[derive(Serialize)]
pub struct SiFnPoint {
    pub si: String,
    pub fnc: String,
    pub stomp: bool,
}

#[derive(Serialize)]
pub struct RecordPoint {
    pub entry: i64,
    pub si: String,
}

#[derive(Serialize)]
pub struct Dashboard {
    pub totals: Totals,
    pub density: Vec<DayCount>,
    pub subsecond: Vec<i64>,
    pub heatmap: Vec<HeatCell>,
    pub extensions: Vec<NameCount>,
    pub si_fn: Vec<SiFnPoint>,
    pub record_scatter: Vec<RecordPoint>,
    pub rules: Vec<NameCount>,
}

struct Sampler<T> {
    items: Vec<T>,
    seen: u64,
    stride: u64,
    cap: usize,
}

impl<T> Sampler<T> {
    fn new(cap: usize) -> Self {
        Sampler {
            items: Vec::new(),
            seen: 0,
            stride: 1,
            cap,
        }
    }

    fn push(&mut self, make: impl FnOnce() -> T) {
        self.seen += 1;
        if self.seen % self.stride != 0 {
            return;
        }
        self.items.push(make());
        if self.items.len() > self.cap {
            let mut keep = Vec::with_capacity(self.cap);
            for (i, item) in std::mem::take(&mut self.items).into_iter().enumerate() {
                if i % 2 == 0 {
                    keep.push(item);
                }
            }
            self.items = keep;
            self.stride *= 2;
        }
    }
}

fn safe_date(value: &str) -> Option<String> {
    if value.is_empty() {
        return None;
    }
    if value.len() <= 10 && value.chars().all(|c| c.is_ascii_digit() || c == '-') {
        Some(value.to_string())
    } else {
        None
    }
}

pub fn where_clause(from: &Option<String>, to: &Option<String>) -> String {
    let mut clause = String::from("evidence_id = ?1 AND si_created NOT LIKE '1601-%'");
    if let Some(f) = from {
        clause.push_str(&format!(" AND substr(si_created,1,10) >= '{}'", f));
    }
    if let Some(t) = to {
        clause.push_str(&format!(" AND substr(si_created,1,10) <= '{}'", t));
    }
    clause
}

fn weekday(day: &str) -> i64 {
    let bytes = day.as_bytes();
    if day.len() < 10 {
        return 0;
    }
    let num = |a: usize, b: usize| -> i64 {
        day[a..b].parse::<i64>().unwrap_or(0)
    };
    let _ = bytes;
    let mut y = num(0, 4);
    let m = num(5, 7);
    let d = num(8, 10);
    let table = [0, 3, 2, 5, 0, 3, 5, 1, 4, 6, 2, 4];
    if m < 3 {
        y -= 1;
    }
    let idx = ((m - 1).rem_euclid(12)) as usize;
    (y + y / 4 - y / 100 + y / 400 + table[idx] + d).rem_euclid(7)
}

pub async fn dashboard(
    State(state): State<Arc<AppState>>,
    Json(req): Json<DashboardQuery>,
) -> Result<Json<Dashboard>, StatusCode> {
    let inner = state.inner.lock().unwrap();
    let case = inner.open_case.as_ref().ok_or(StatusCode::BAD_REQUEST)?;
    let conn = &case.vault.conn;
    let eid = req.evidence_id;
    let from = safe_date(&req.from);
    let to = safe_date(&req.to);
    let wc = where_clause(&from, &to);
    let result = build(conn, eid, &wc).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(Json(result))
}

pub fn build(conn: &Connection, eid: i64, wc: &str) -> Result<Dashboard, rusqlite::Error> {
    let sql = format!(
        "SELECT entry, in_use, is_directory, has_ads, orphan, si_created, fn_created, name
         FROM records WHERE {}",
        wc
    );
    let mut stmt = conn.prepare(&sql)?;
    let mut rows = stmt.query([eid])?;

    let mut totals = Totals::default();
    let mut density: HashMap<String, i64> = HashMap::new();
    let mut subsecond = vec![0i64; 10];
    let mut heat: HashMap<(i64, i64), i64> = HashMap::new();
    let mut ext: HashMap<String, i64> = HashMap::new();
    let mut stomped: Sampler<SiFnPoint> = Sampler::new(1500);
    let mut normal: Sampler<SiFnPoint> = Sampler::new(1500);
    let mut scatter: Sampler<RecordPoint> = Sampler::new(4000);

    while let Some(row) = rows.next()? {
        let entry: i64 = row.get(0)?;
        let in_use: i64 = row.get(1)?;
        let is_dir: i64 = row.get(2)?;
        let has_ads: i64 = row.get(3)?;
        let orphan: i64 = row.get(4)?;
        let si: String = row.get(5)?;
        let fnc: String = row.get(6)?;
        let name: String = row.get(7)?;

        totals.records += 1;
        if in_use == 0 {
            totals.deleted += 1;
        }
        if has_ads != 0 {
            totals.ads += 1;
        }
        if orphan != 0 {
            totals.orphans += 1;
        }

        if si.len() >= 19 {
            let day = si[0..10].to_string();
            *density.entry(day.clone()).or_insert(0) += 1;
            let hour: i64 = si[11..13].parse().unwrap_or(0);
            let dow = weekday(&day);
            *heat.entry((dow, hour)).or_insert(0) += 1;
        }
        if let Some(b) = si.as_bytes().get(20) {
            if b.is_ascii_digit() {
                subsecond[(b - b'0') as usize] += 1;
            }
        }

        if is_dir == 0 {
            if let Some(i) = name.rfind('.') {
                if i > 0 && i + 1 < name.len() {
                    let e = name[i + 1..].to_ascii_lowercase();
                    if e.len() <= 8 {
                        *ext.entry(e).or_insert(0) += 1;
                    }
                }
            }
        }

        let fn_zero = fnc.starts_with("1601");
        if !fn_zero && si < fnc {
            stomped.push(|| SiFnPoint { si: si.clone(), fnc: fnc.clone(), stomp: true });
        } else if !fn_zero {
            normal.push(|| SiFnPoint { si: si.clone(), fnc: fnc.clone(), stomp: false });
        }
        scatter.push(|| RecordPoint { entry, si: si.clone() });
    }

    let (high, medium, low) = conn.query_row(
        "SELECT SUM(CASE WHEN severity='high' THEN 1 ELSE 0 END),
                SUM(CASE WHEN severity='medium' THEN 1 ELSE 0 END),
                SUM(CASE WHEN severity='low' THEN 1 ELSE 0 END)
         FROM findings WHERE evidence_id = ?1",
        [eid],
        |row| {
            Ok((
                row.get::<_, Option<i64>>(0)?.unwrap_or(0),
                row.get::<_, Option<i64>>(1)?.unwrap_or(0),
                row.get::<_, Option<i64>>(2)?.unwrap_or(0),
            ))
        },
    )?;
    totals.high = high;
    totals.medium = medium;
    totals.low = low;

    let mut density_vec: Vec<DayCount> = density
        .into_iter()
        .map(|(day, count)| DayCount { day, count })
        .collect();
    density_vec.sort_by(|a, b| a.day.cmp(&b.day));

    let heatmap: Vec<HeatCell> = heat
        .into_iter()
        .map(|((dow, hour), count)| HeatCell { dow, hour, count })
        .collect();

    let mut extensions: Vec<NameCount> = ext
        .into_iter()
        .map(|(name, count)| NameCount { name, count })
        .collect();
    extensions.sort_by(|a, b| b.count.cmp(&a.count));
    extensions.truncate(15);

    let mut si_fn = stomped.items;
    si_fn.extend(normal.items);

    let rules = rules(conn, eid)?;

    Ok(Dashboard {
        totals,
        density: density_vec,
        subsecond,
        heatmap,
        extensions,
        si_fn,
        record_scatter: scatter.items,
        rules,
    })
}

fn rules(conn: &Connection, eid: i64) -> Result<Vec<NameCount>, rusqlite::Error> {
    let mut stmt = conn.prepare(
        "SELECT rule_id, COUNT(*) c FROM findings WHERE evidence_id = ?1 GROUP BY rule_id ORDER BY c DESC",
    )?;
    let rows = stmt.query_map([eid], |row| {
        Ok(NameCount {
            name: row.get(0)?,
            count: row.get(1)?,
        })
    })?;
    let mut out = Vec::new();
    for r in rows {
        out.push(r?);
    }
    Ok(out)
}

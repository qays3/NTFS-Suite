use rusqlite::Connection;

use crate::vault::error::VaultError;

#[derive(Debug, Clone, serde::Serialize)]
pub struct Finding {
    pub id: i64,
    pub rule_id: String,
    pub title: String,
    pub severity: String,
    pub score: i64,
    pub mitre: String,
    pub entry: i64,
    pub path: String,
    pub name: String,
    pub reason: String,
    pub status: String,
    pub notes: String,
    pub created_utc: String,
}

#[derive(Debug, Clone)]
pub struct NewFinding {
    pub rule_id: String,
    pub title: String,
    pub severity: String,
    pub score: i64,
    pub mitre: String,
    pub entry: i64,
    pub path: String,
    pub name: String,
    pub reason: String,
}

#[derive(Debug, Clone, Default)]
pub struct FindingFilter {
    pub severity: String,
    pub status: String,
    pub rule_id: String,
    pub search: String,
}

#[derive(Debug, Clone, Default, serde::Serialize)]
pub struct FindingStats {
    pub total: i64,
    pub high: i64,
    pub medium: i64,
    pub low: i64,
    pub flagged_files: i64,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct FindingGroup {
    pub rule_id: String,
    pub title: String,
    pub severity: String,
    pub mitre: String,
    pub folder: String,
    pub reason: String,
    pub count: i64,
    pub entry: i64,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct RankedFile {
    pub entry: i64,
    pub path: String,
    pub name: String,
    pub total_score: i64,
    pub finding_count: i64,
    pub top_severity: String,
}

pub fn clear(conn: &Connection, evidence_id: i64) -> Result<(), VaultError> {
    conn.execute("DELETE FROM findings WHERE evidence_id = ?1", [evidence_id])?;
    Ok(())
}

pub fn insert_many(
    conn: &mut Connection,
    evidence_id: i64,
    created_utc: &str,
    findings: &[NewFinding],
) -> Result<usize, VaultError> {
    let tx = conn.transaction()?;
    {
        let mut stmt = tx.prepare(
            "INSERT INTO findings
             (evidence_id, rule_id, title, severity, score, mitre, entry, path, reason, status, notes, created_utc)
             VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,'new','',?10)",
        )?;
        for f in findings {
            stmt.execute(rusqlite::params![
                evidence_id,
                f.rule_id,
                f.title,
                f.severity,
                f.score,
                f.mitre,
                f.entry,
                f.path,
                f.reason,
                created_utc,
            ])?;
        }
    }
    tx.commit()?;
    Ok(findings.len())
}

fn where_clause(filter: &FindingFilter) -> (String, Vec<String>) {
    let mut clauses = vec![String::from("f.evidence_id = ?1")];
    let mut params: Vec<String> = Vec::new();
    if !filter.severity.is_empty() {
        clauses.push(format!("f.severity = ?{}", params.len() + 2));
        params.push(filter.severity.clone());
    }
    if !filter.status.is_empty() {
        clauses.push(format!("f.status = ?{}", params.len() + 2));
        params.push(filter.status.clone());
    }
    if !filter.rule_id.is_empty() {
        clauses.push(format!("f.rule_id = ?{}", params.len() + 2));
        params.push(filter.rule_id.clone());
    }
    if !filter.search.is_empty() {
        clauses.push(format!(
            "(f.path LIKE ?{0} OR r.name LIKE ?{0})",
            params.len() + 2
        ));
        params.push(format!("%{}%", filter.search));
    }
    (clauses.join(" AND "), params)
}

pub fn list(
    conn: &Connection,
    evidence_id: i64,
    filter: &FindingFilter,
    offset: i64,
    limit: i64,
) -> Result<Vec<Finding>, VaultError> {
    let (clause, extra) = where_clause(filter);
    let sql = format!(
        "SELECT f.id, f.rule_id, f.title, f.severity, f.score, f.mitre, f.entry, f.path,
                COALESCE(r.name, ''), f.reason, f.status, f.notes, f.created_utc
         FROM findings f
         LEFT JOIN records r ON r.evidence_id = f.evidence_id AND r.entry = f.entry
         WHERE {}
         ORDER BY CASE f.severity WHEN 'high' THEN 0 WHEN 'medium' THEN 1 ELSE 2 END,
                  f.score DESC, f.id ASC
         LIMIT ?{} OFFSET ?{}",
        clause,
        extra.len() + 2,
        extra.len() + 3
    );
    let mut stmt = conn.prepare(&sql)?;
    let mut bind: Vec<&dyn rusqlite::ToSql> = vec![&evidence_id];
    for e in extra.iter() {
        bind.push(e);
    }
    bind.push(&limit);
    bind.push(&offset);
    let rows = stmt.query_map(bind.as_slice(), map_finding)?;
    let mut out = Vec::new();
    for r in rows {
        out.push(r?);
    }
    Ok(out)
}

pub fn count(
    conn: &Connection,
    evidence_id: i64,
    filter: &FindingFilter,
) -> Result<i64, VaultError> {
    let (clause, extra) = where_clause(filter);
    let sql = format!(
        "SELECT COUNT(*) FROM findings f
         LEFT JOIN records r ON r.evidence_id = f.evidence_id AND r.entry = f.entry
         WHERE {}",
        clause
    );
    let mut stmt = conn.prepare(&sql)?;
    let mut bind: Vec<&dyn rusqlite::ToSql> = vec![&evidence_id];
    for e in extra.iter() {
        bind.push(e);
    }
    let n: i64 = stmt.query_row(bind.as_slice(), |row| row.get(0))?;
    Ok(n)
}

fn folder_of(path: &str) -> String {
    match path.rfind('\\') {
        Some(0) => String::from("\\"),
        Some(i) => path[..i].to_string(),
        None => path.to_string(),
    }
}

fn severity_rank(severity: &str) -> i64 {
    match severity {
        "high" => 0,
        "medium" => 1,
        _ => 2,
    }
}

#[derive(Debug, Clone, Default, serde::Serialize)]
pub struct GroupTally {
    pub folders: i64,
    pub high: i64,
    pub medium: i64,
    pub low: i64,
}

pub fn grouped(
    conn: &Connection,
    evidence_id: i64,
    filter: &FindingFilter,
    offset: i64,
    limit: i64,
) -> Result<(GroupTally, Vec<FindingGroup>), VaultError> {
    let (clause, extra) = where_clause(filter);
    let sql = format!(
        "SELECT f.rule_id, f.title, f.severity, f.mitre, f.entry, f.path, f.reason
         FROM findings f
         LEFT JOIN records r ON r.evidence_id = f.evidence_id AND r.entry = f.entry
         WHERE {}",
        clause
    );
    let mut stmt = conn.prepare(&sql)?;
    let mut bind: Vec<&dyn rusqlite::ToSql> = vec![&evidence_id];
    for e in extra.iter() {
        bind.push(e);
    }
    let mut rows = stmt.query(bind.as_slice())?;
    let mut map: std::collections::HashMap<(String, String), FindingGroup> = std::collections::HashMap::new();
    while let Some(row) = rows.next()? {
        let rule_id: String = row.get(0)?;
        let title: String = row.get(1)?;
        let severity: String = row.get(2)?;
        let mitre: String = row.get(3)?;
        let entry: i64 = row.get(4)?;
        let path: String = row.get(5)?;
        let reason: String = row.get(6)?;
        let folder = folder_of(&path);
        let key = (rule_id.clone(), folder.clone());
        let group = map.entry(key).or_insert(FindingGroup {
            rule_id,
            title,
            severity,
            mitre,
            folder,
            reason,
            count: 0,
            entry,
        });
        group.count += 1;
        if entry < group.entry {
            group.entry = entry;
        }
    }
    let mut groups: Vec<FindingGroup> = map.into_values().collect();
    groups.sort_by(|a, b| {
        severity_rank(&a.severity)
            .cmp(&severity_rank(&b.severity))
            .then(b.count.cmp(&a.count))
            .then(a.folder.cmp(&b.folder))
    });
    let mut tally = GroupTally {
        folders: groups.len() as i64,
        ..Default::default()
    };
    for g in groups.iter() {
        match g.severity.as_str() {
            "high" => tally.high += 1,
            "medium" => tally.medium += 1,
            _ => tally.low += 1,
        }
    }
    let start = offset.max(0) as usize;
    let end = (start + limit.max(0) as usize).min(groups.len());
    let page = if start < groups.len() {
        groups[start..end].to_vec()
    } else {
        Vec::new()
    };
    Ok((tally, page))
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct RuleCount {
    pub rule_id: String,
    pub title: String,
    pub severity: String,
    pub mitre: String,
    pub count: i64,
}

pub fn by_rule(conn: &Connection, evidence_id: i64) -> Result<Vec<RuleCount>, VaultError> {
    let mut stmt = conn.prepare(
        "SELECT rule_id, title, severity, mitre, COUNT(*) c
         FROM findings WHERE evidence_id = ?1
         GROUP BY rule_id
         ORDER BY CASE severity WHEN 'high' THEN 0 WHEN 'medium' THEN 1 ELSE 2 END, c DESC",
    )?;
    let rows = stmt.query_map([evidence_id], |row| {
        Ok(RuleCount {
            rule_id: row.get(0)?,
            title: row.get(1)?,
            severity: row.get(2)?,
            mitre: row.get(3)?,
            count: row.get(4)?,
        })
    })?;
    let mut out = Vec::new();
    for r in rows {
        out.push(r?);
    }
    Ok(out)
}

pub fn ranked_files(
    conn: &Connection,
    evidence_id: i64,
    limit: i64,
) -> Result<Vec<RankedFile>, VaultError> {
    let mut stmt = conn.prepare(
        "SELECT f.entry, f.path, COALESCE(r.name, ''), SUM(f.score), COUNT(*),
                MIN(CASE f.severity WHEN 'high' THEN 0 WHEN 'medium' THEN 1 ELSE 2 END)
         FROM findings f
         LEFT JOIN records r ON r.evidence_id = f.evidence_id AND r.entry = f.entry
         WHERE f.evidence_id = ?1
         GROUP BY f.entry, f.path
         ORDER BY SUM(f.score) DESC, COUNT(*) DESC
         LIMIT ?2",
    )?;
    let rows = stmt.query_map(rusqlite::params![evidence_id, limit], |row| {
        let sev: i64 = row.get(5)?;
        Ok(RankedFile {
            entry: row.get(0)?,
            path: row.get(1)?,
            name: row.get(2)?,
            total_score: row.get(3)?,
            finding_count: row.get(4)?,
            top_severity: severity_label(sev),
        })
    })?;
    let mut out = Vec::new();
    for r in rows {
        out.push(r?);
    }
    Ok(out)
}

pub fn stats_filtered(
    conn: &Connection,
    evidence_id: i64,
    filter: &FindingFilter,
) -> Result<FindingStats, VaultError> {
    let (clause, extra) = where_clause(filter);
    let sql = format!(
        "SELECT COUNT(*),
                SUM(CASE WHEN f.severity = 'high' THEN 1 ELSE 0 END),
                SUM(CASE WHEN f.severity = 'medium' THEN 1 ELSE 0 END),
                SUM(CASE WHEN f.severity = 'low' THEN 1 ELSE 0 END),
                COUNT(DISTINCT f.entry)
         FROM findings f
         LEFT JOIN records r ON r.evidence_id = f.evidence_id AND r.entry = f.entry
         WHERE {}",
        clause
    );
    let mut stmt = conn.prepare(&sql)?;
    let mut bind: Vec<&dyn rusqlite::ToSql> = vec![&evidence_id];
    for e in extra.iter() {
        bind.push(e);
    }
    stmt.query_row(bind.as_slice(), |row| {
        Ok(FindingStats {
            total: row.get(0)?,
            high: row.get::<_, Option<i64>>(1)?.unwrap_or(0),
            medium: row.get::<_, Option<i64>>(2)?.unwrap_or(0),
            low: row.get::<_, Option<i64>>(3)?.unwrap_or(0),
            flagged_files: row.get(4)?,
        })
    })
    .map_err(VaultError::from)
}

pub fn stats(conn: &Connection, evidence_id: i64) -> Result<FindingStats, VaultError> {
    let (total, high, medium, low) = conn.query_row(
        "SELECT COUNT(*),
                SUM(CASE WHEN severity = 'high' THEN 1 ELSE 0 END),
                SUM(CASE WHEN severity = 'medium' THEN 1 ELSE 0 END),
                SUM(CASE WHEN severity = 'low' THEN 1 ELSE 0 END)
         FROM findings WHERE evidence_id = ?1",
        [evidence_id],
        |row| {
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, Option<i64>>(1)?.unwrap_or(0),
                row.get::<_, Option<i64>>(2)?.unwrap_or(0),
                row.get::<_, Option<i64>>(3)?.unwrap_or(0),
            ))
        },
    )?;
    let flagged_files: i64 = conn.query_row(
        "SELECT COUNT(DISTINCT entry) FROM findings WHERE evidence_id = ?1",
        [evidence_id],
        |row| row.get(0),
    )?;
    Ok(FindingStats {
        total,
        high,
        medium,
        low,
        flagged_files,
    })
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct RuleHitRow {
    pub rule_id: String,
    pub title: String,
    pub severity: String,
}

pub fn rules_for_entry(
    conn: &Connection,
    evidence_id: i64,
    entry: i64,
) -> Result<Vec<RuleHitRow>, VaultError> {
    let mut stmt = conn.prepare(
        "SELECT DISTINCT rule_id, title, severity FROM findings WHERE evidence_id = ?1 AND entry = ?2",
    )?;
    let rows = stmt.query_map(rusqlite::params![evidence_id, entry], |row| {
        Ok(RuleHitRow {
            rule_id: row.get(0)?,
            title: row.get(1)?,
            severity: row.get(2)?,
        })
    })?;
    let mut out = Vec::new();
    for r in rows {
        out.push(r?);
    }
    Ok(out)
}

pub fn set_status(
    conn: &Connection,
    id: i64,
    status: &str,
    notes: &str,
) -> Result<(), VaultError> {
    conn.execute(
        "UPDATE findings SET status = ?2, notes = ?3 WHERE id = ?1",
        rusqlite::params![id, status, notes],
    )?;
    Ok(())
}

pub fn set_status_by_rule(
    conn: &Connection,
    evidence_id: i64,
    rule_id: &str,
    status: &str,
) -> Result<usize, VaultError> {
    let count = conn.execute(
        "UPDATE findings SET status = ?3 WHERE evidence_id = ?1 AND rule_id = ?2",
        rusqlite::params![evidence_id, rule_id, status],
    )?;
    Ok(count)
}

fn severity_label(rank: i64) -> String {
    match rank {
        0 => String::from("high"),
        1 => String::from("medium"),
        _ => String::from("low"),
    }
}

fn map_finding(row: &rusqlite::Row) -> rusqlite::Result<Finding> {
    Ok(Finding {
        id: row.get(0)?,
        rule_id: row.get(1)?,
        title: row.get(2)?,
        severity: row.get(3)?,
        score: row.get(4)?,
        mitre: row.get(5)?,
        entry: row.get(6)?,
        path: row.get(7)?,
        name: row.get(8)?,
        reason: row.get(9)?,
        status: row.get(10)?,
        notes: row.get(11)?,
        created_utc: row.get(12)?,
    })
}

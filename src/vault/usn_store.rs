use rusqlite::Connection;

use crate::vault::error::VaultError;

#[derive(Debug, Clone, Default, serde::Serialize)]
pub struct UsnEvent {
    pub usn: i64,
    pub timestamp: String,
    pub entry: i64,
    pub sequence: i64,
    pub parent_entry: i64,
    pub reason: i64,
    pub summary: String,
    pub source_info: i64,
    pub security_id: i64,
    pub file_attributes: i64,
    pub name: String,
}

pub fn ensure(conn: &Connection) -> Result<(), VaultError> {
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS usn_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            evidence_id INTEGER NOT NULL,
            usn INTEGER NOT NULL,
            timestamp TEXT NOT NULL,
            entry INTEGER NOT NULL,
            sequence INTEGER NOT NULL,
            parent_entry INTEGER NOT NULL,
            reason INTEGER NOT NULL,
            summary TEXT NOT NULL,
            source_info INTEGER NOT NULL,
            security_id INTEGER NOT NULL,
            file_attributes INTEGER NOT NULL,
            name TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_usn_evidence ON usn_events(evidence_id, usn);
        CREATE INDEX IF NOT EXISTS idx_usn_name ON usn_events(evidence_id, name);
        CREATE INDEX IF NOT EXISTS idx_usn_entry ON usn_events(evidence_id, entry);
        CREATE INDEX IF NOT EXISTS idx_usn_summary ON usn_events(evidence_id, summary);",
    )?;
    Ok(())
}

pub fn insert_many(
    conn: &mut Connection,
    evidence_id: i64,
    rows: &[UsnEvent],
) -> Result<usize, VaultError> {
    let tx = conn.transaction()?;
    {
        let mut stmt = tx.prepare(
            "INSERT INTO usn_events
             (evidence_id, usn, timestamp, entry, sequence, parent_entry, reason, summary,
              source_info, security_id, file_attributes, name)
             VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12)",
        )?;
        for r in rows {
            stmt.execute(rusqlite::params![
                evidence_id,
                r.usn,
                r.timestamp,
                r.entry,
                r.sequence,
                r.parent_entry,
                r.reason,
                r.summary,
                r.source_info,
                r.security_id,
                r.file_attributes,
                r.name,
            ])?;
        }
    }
    tx.commit()?;
    Ok(rows.len())
}

#[derive(Debug, Clone, Default)]
pub struct UsnFilter {
    pub search: String,
    pub summary: String,
    pub after: String,
    pub before: String,
}

fn where_clause(filter: &UsnFilter) -> (String, Vec<String>) {
    let mut clauses = vec![String::from("evidence_id = ?1")];
    let mut params: Vec<String> = Vec::new();
    if !filter.search.is_empty() {
        let i = 2 + params.len();
        clauses.push(format!("name LIKE ?{i}"));
        params.push(format!("%{}%", filter.search));
    }
    if !filter.summary.is_empty() {
        let i = 2 + params.len();
        clauses.push(format!("summary = ?{i}"));
        params.push(filter.summary.clone());
    }
    if !filter.after.is_empty() {
        let i = 2 + params.len();
        clauses.push(format!("timestamp >= ?{i}"));
        params.push(format!("{}T00:00:00.0000000Z", filter.after));
    }
    if !filter.before.is_empty() {
        let i = 2 + params.len();
        clauses.push(format!("timestamp <= ?{i}"));
        params.push(format!("{}T23:59:59.9999999Z", filter.before));
    }
    (clauses.join(" AND "), params)
}

pub fn count(conn: &Connection, evidence_id: i64, filter: &UsnFilter) -> Result<i64, VaultError> {
    let (clause, extra) = where_clause(filter);
    let sql = format!("SELECT COUNT(*) FROM usn_events WHERE {}", clause);
    let mut stmt = conn.prepare(&sql)?;
    let mut bind: Vec<&dyn rusqlite::ToSql> = vec![&evidence_id];
    for e in extra.iter() {
        bind.push(e);
    }
    let n: i64 = stmt.query_row(bind.as_slice(), |row| row.get(0))?;
    Ok(n)
}

fn map_event(row: &rusqlite::Row) -> rusqlite::Result<UsnEvent> {
    Ok(UsnEvent {
        usn: row.get(0)?,
        timestamp: row.get(1)?,
        entry: row.get(2)?,
        sequence: row.get(3)?,
        parent_entry: row.get(4)?,
        reason: row.get(5)?,
        summary: row.get(6)?,
        source_info: row.get(7)?,
        security_id: row.get(8)?,
        file_attributes: row.get(9)?,
        name: row.get(10)?,
    })
}

pub fn page(
    conn: &Connection,
    evidence_id: i64,
    filter: &UsnFilter,
    offset: i64,
    limit: i64,
) -> Result<Vec<UsnEvent>, VaultError> {
    let (clause, extra) = where_clause(filter);
    let sql = format!(
        "SELECT usn, timestamp, entry, sequence, parent_entry, reason, summary,
                source_info, security_id, file_attributes, name
         FROM usn_events WHERE {} ORDER BY usn DESC LIMIT ?{} OFFSET ?{}",
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
    let rows = stmt.query_map(bind.as_slice(), map_event)?;
    let mut out = Vec::new();
    for r in rows {
        out.push(r?);
    }
    Ok(out)
}

pub fn summary_counts(conn: &Connection, evidence_id: i64) -> Result<Vec<(String, i64)>, VaultError> {
    let mut stmt = conn.prepare(
        "SELECT summary, COUNT(*) c FROM usn_events WHERE evidence_id = ?1 GROUP BY summary ORDER BY c DESC",
    )?;
    let rows = stmt.query_map([evidence_id], |r| Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)?)))?;
    let mut out = Vec::new();
    for r in rows {
        out.push(r?);
    }
    Ok(out)
}

pub fn count_all(conn: &Connection, evidence_id: i64) -> Result<i64, VaultError> {
    count(conn, evidence_id, &UsnFilter::default())
}

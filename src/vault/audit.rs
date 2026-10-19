use rusqlite::Connection;

use crate::util::clock::now_iso8601;
use crate::vault::error::VaultError;

#[derive(Debug, Clone, serde::Serialize)]
pub struct AuditEntry {
    pub time_utc: String,
    pub actor: String,
    pub action: String,
    pub detail: String,
}

pub fn record(conn: &Connection, actor: &str, action: &str, detail: &str) -> Result<(), VaultError> {
    conn.execute(
        "INSERT INTO audit (time_utc, actor, action, detail) VALUES (?1, ?2, ?3, ?4)",
        rusqlite::params![now_iso8601(), actor, action, detail],
    )?;
    Ok(())
}

pub fn list(conn: &Connection) -> Result<Vec<AuditEntry>, VaultError> {
    let mut stmt = conn.prepare(
        "SELECT time_utc, actor, action, detail FROM audit ORDER BY id ASC",
    )?;
    let rows = stmt.query_map([], |row| {
        Ok(AuditEntry {
            time_utc: row.get(0)?,
            actor: row.get(1)?,
            action: row.get(2)?,
            detail: row.get(3)?,
        })
    })?;
    let mut out = Vec::new();
    for r in rows {
        out.push(r?);
    }
    Ok(out)
}

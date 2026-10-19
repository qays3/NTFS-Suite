use rusqlite::Connection;

use crate::util::clock::now_iso8601;
use crate::vault::error::VaultError;

#[derive(Debug, Clone, serde::Serialize)]
pub struct Evidence {
    pub id: i64,
    pub name: String,
    pub source_path: String,
    pub size: i64,
    pub sha256: String,
    pub plugin: String,
    pub status: String,
    pub added_utc: String,
    pub parsed_utc: Option<String>,
}

pub fn add(
    conn: &Connection,
    name: &str,
    source_path: &str,
    size: i64,
    sha256: &str,
    plugin: &str,
) -> Result<i64, VaultError> {
    conn.execute(
        "INSERT INTO evidence (name, source_path, size, sha256, plugin, status, added_utc)
         VALUES (?1, ?2, ?3, ?4, ?5, 'added', ?6)",
        rusqlite::params![name, source_path, size, sha256, plugin, now_iso8601()],
    )?;
    Ok(conn.last_insert_rowid())
}

pub fn mark_parsed(conn: &Connection, id: i64) -> Result<(), VaultError> {
    conn.execute(
        "UPDATE evidence SET status = 'parsed', parsed_utc = ?1 WHERE id = ?2",
        rusqlite::params![now_iso8601(), id],
    )?;
    Ok(())
}

pub fn count_by_plugin(conn: &Connection, plugin: &str) -> Result<i64, VaultError> {
    conn.query_row(
        "SELECT COUNT(*) FROM evidence WHERE plugin = ?1",
        [plugin],
        |row| row.get(0),
    )
    .map_err(VaultError::from)
}

pub fn get(conn: &Connection, id: i64) -> Result<Option<Evidence>, VaultError> {
    let mut stmt = conn.prepare(
        "SELECT id, name, source_path, size, sha256, plugin, status, added_utc, parsed_utc
         FROM evidence WHERE id = ?1",
    )?;
    let mut rows = stmt.query([id])?;
    if let Some(row) = rows.next()? {
        Ok(Some(Evidence {
            id: row.get(0)?,
            name: row.get(1)?,
            source_path: row.get(2)?,
            size: row.get(3)?,
            sha256: row.get(4)?,
            plugin: row.get(5)?,
            status: row.get(6)?,
            added_utc: row.get(7)?,
            parsed_utc: row.get(8)?,
        }))
    } else {
        Ok(None)
    }
}

pub fn remove(conn: &Connection, id: i64) -> Result<(), VaultError> {
    conn.execute_batch(&format!(
        "BEGIN; DELETE FROM records WHERE evidence_id = {id}; DELETE FROM events WHERE evidence_id = {id}; DELETE FROM findings WHERE evidence_id = {id}; DELETE FROM evidence WHERE id = {id}; COMMIT;"
    ))?;
    Ok(())
}

pub fn list(conn: &Connection) -> Result<Vec<Evidence>, VaultError> {
    let mut stmt = conn.prepare(
        "SELECT id, name, source_path, size, sha256, plugin, status, added_utc, parsed_utc
         FROM evidence ORDER BY id ASC",
    )?;
    let rows = stmt.query_map([], |row| {
        Ok(Evidence {
            id: row.get(0)?,
            name: row.get(1)?,
            source_path: row.get(2)?,
            size: row.get(3)?,
            sha256: row.get(4)?,
            plugin: row.get(5)?,
            status: row.get(6)?,
            added_utc: row.get(7)?,
            parsed_utc: row.get(8)?,
        })
    })?;
    let mut out = Vec::new();
    for r in rows {
        out.push(r?);
    }
    Ok(out)
}

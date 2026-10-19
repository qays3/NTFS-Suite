use rusqlite::Connection;

use crate::vault::error::VaultError;

#[derive(Debug, Clone, Default, serde::Serialize)]
pub struct SecurityDescriptor {
    pub security_id: i64,
    pub owner_sid: String,
    pub owner_name: String,
    pub group_sid: String,
    pub group_name: String,
    pub control: i64,
    pub ace_count: i64,
    pub allow_count: i64,
    pub deny_count: i64,
}

pub fn ensure(conn: &Connection) -> Result<(), VaultError> {
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS security_descriptors (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            evidence_id INTEGER NOT NULL,
            security_id INTEGER NOT NULL,
            owner_sid TEXT NOT NULL,
            owner_name TEXT NOT NULL,
            group_sid TEXT NOT NULL,
            group_name TEXT NOT NULL,
            control INTEGER NOT NULL,
            ace_count INTEGER NOT NULL,
            allow_count INTEGER NOT NULL,
            deny_count INTEGER NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_secdesc_evidence ON security_descriptors(evidence_id);
        CREATE INDEX IF NOT EXISTS idx_secdesc_secid ON security_descriptors(security_id);",
    )?;
    Ok(())
}

pub fn insert_many(
    conn: &mut Connection,
    evidence_id: i64,
    rows: &[SecurityDescriptor],
) -> Result<usize, VaultError> {
    let tx = conn.transaction()?;
    {
        let mut stmt = tx.prepare(
            "INSERT INTO security_descriptors
             (evidence_id, security_id, owner_sid, owner_name, group_sid, group_name,
              control, ace_count, allow_count, deny_count)
             VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10)",
        )?;
        for r in rows {
            stmt.execute(rusqlite::params![
                evidence_id,
                r.security_id,
                r.owner_sid,
                r.owner_name,
                r.group_sid,
                r.group_name,
                r.control,
                r.ace_count,
                r.allow_count,
                r.deny_count,
            ])?;
        }
    }
    tx.commit()?;
    Ok(rows.len())
}

pub fn count(conn: &Connection) -> Result<i64, VaultError> {
    let n: i64 = conn
        .query_row("SELECT COUNT(*) FROM security_descriptors", [], |r| r.get(0))
        .unwrap_or(0);
    Ok(n)
}

fn map_row(row: &rusqlite::Row) -> rusqlite::Result<SecurityDescriptor> {
    Ok(SecurityDescriptor {
        security_id: row.get(0)?,
        owner_sid: row.get(1)?,
        owner_name: row.get(2)?,
        group_sid: row.get(3)?,
        group_name: row.get(4)?,
        control: row.get(5)?,
        ace_count: row.get(6)?,
        allow_count: row.get(7)?,
        deny_count: row.get(8)?,
    })
}

// Every descriptor in the case, newest evidence last. Used to resolve the
// security ids stored on $MFT records.
pub fn all(conn: &Connection) -> Result<Vec<SecurityDescriptor>, VaultError> {
    let mut stmt = conn.prepare(
        "SELECT security_id, owner_sid, owner_name, group_sid, group_name,
                control, ace_count, allow_count, deny_count
         FROM security_descriptors ORDER BY security_id",
    )?;
    let rows = stmt.query_map([], map_row)?;
    let mut out = Vec::new();
    for r in rows {
        out.push(r?);
    }
    Ok(out)
}

pub fn get(conn: &Connection, security_id: i64) -> Result<Option<SecurityDescriptor>, VaultError> {
    let mut stmt = conn.prepare(
        "SELECT security_id, owner_sid, owner_name, group_sid, group_name,
                control, ace_count, allow_count, deny_count
         FROM security_descriptors WHERE security_id = ?1 LIMIT 1",
    )?;
    let mut rows = stmt.query([security_id])?;
    if let Some(row) = rows.next()? {
        Ok(Some(map_row(row)?))
    } else {
        Ok(None)
    }
}

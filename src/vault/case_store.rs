use rusqlite::Connection;

use crate::util::clock::now_iso8601;
use crate::vault::error::VaultError;

#[derive(Debug, Clone, serde::Serialize)]
pub struct CaseInfo {
    pub name: String,
    pub number: String,
    pub analyst: String,
    pub notes: String,
    pub created_utc: String,
    pub display_timezone: String,
}

pub fn initialize(
    conn: &Connection,
    name: &str,
    number: &str,
    analyst: &str,
    notes: &str,
) -> Result<(), VaultError> {
    conn.execute(
        "INSERT INTO case_info (id, name, number, analyst, notes, created_utc, display_timezone)
         VALUES (1, ?1, ?2, ?3, ?4, ?5, 'UTC')
         ON CONFLICT(id) DO NOTHING",
        rusqlite::params![name, number, analyst, notes, now_iso8601()],
    )?;
    Ok(())
}

pub fn get(conn: &Connection) -> Result<CaseInfo, VaultError> {
    conn.query_row(
        "SELECT name, number, analyst, notes, created_utc, display_timezone FROM case_info WHERE id = 1",
        [],
        |row| {
            Ok(CaseInfo {
                name: row.get(0)?,
                number: row.get(1)?,
                analyst: row.get(2)?,
                notes: row.get(3)?,
                created_utc: row.get(4)?,
                display_timezone: row.get(5)?,
            })
        },
    )
    .map_err(|_| VaultError::NotFound)
}

pub fn set_timezone(conn: &Connection, timezone: &str) -> Result<(), VaultError> {
    conn.execute(
        "UPDATE case_info SET display_timezone = ?1 WHERE id = 1",
        [timezone],
    )?;
    Ok(())
}

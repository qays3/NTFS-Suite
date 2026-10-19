use rusqlite::Connection;

use crate::vault::error::VaultError;
use crate::vault::schema::{SCHEMA_V1, SCHEMA_VERSION};

pub fn apply(conn: &Connection) -> Result<(), VaultError> {
    let current = read_version(conn)?;
    if current == 0 {
        conn.execute_batch(SCHEMA_V1)?;
        write_version(conn, SCHEMA_VERSION)?;
    } else if current < SCHEMA_VERSION {
        migrate_upwards(conn, current)?;
    }
    crate::vault::rule_store::ensure(conn)?;
    crate::vault::record_store::ensure_columns(conn)?;
    crate::vault::record_store::ensure_indexes(conn)?;
    crate::vault::ioc_store::ensure(conn)?;
    crate::vault::usn_store::ensure(conn)?;
    crate::vault::security_store::ensure(conn)?;
    Ok(())
}

fn migrate_upwards(conn: &Connection, from: i64) -> Result<(), VaultError> {
    let mut version = from;
    while version < SCHEMA_VERSION {
        version += 1;
    }
    write_version(conn, version)?;
    Ok(())
}

pub fn read_version(conn: &Connection) -> Result<i64, VaultError> {
    let exists: bool = conn
        .query_row(
            "SELECT 1 FROM sqlite_master WHERE type='table' AND name='meta'",
            [],
            |_| Ok(true),
        )
        .unwrap_or(false);
    if !exists {
        return Ok(0);
    }
    let value: Option<String> = conn
        .query_row(
            "SELECT value FROM meta WHERE key = 'schema_version'",
            [],
            |row| row.get(0),
        )
        .ok();
    Ok(value.and_then(|v| v.parse::<i64>().ok()).unwrap_or(0))
}

fn write_version(conn: &Connection, version: i64) -> Result<(), VaultError> {
    conn.execute(
        "INSERT INTO meta (key, value) VALUES ('schema_version', ?1)
         ON CONFLICT(key) DO UPDATE SET value = excluded.value",
        [version.to_string()],
    )?;
    Ok(())
}

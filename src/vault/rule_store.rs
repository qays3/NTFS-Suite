use std::collections::HashMap;

use rusqlite::Connection;

use crate::detection::rule_engine::Rule;
use crate::vault::error::VaultError;

pub const ENSURE_SQL: &str = "
CREATE TABLE IF NOT EXISTS rules (
    id TEXT PRIMARY KEY,
    doc TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS rule_state (
    rule_id TEXT PRIMARY KEY,
    enabled INTEGER NOT NULL DEFAULT 1
);
";

pub fn ensure(conn: &Connection) -> Result<(), VaultError> {
    conn.execute_batch(ENSURE_SQL)?;
    Ok(())
}

pub fn list_custom(conn: &Connection) -> Result<Vec<Rule>, VaultError> {
    let mut stmt = conn.prepare("SELECT doc FROM rules ORDER BY id ASC")?;
    let rows = stmt.query_map([], |row| row.get::<_, String>(0))?;
    let mut out = Vec::new();
    for row in rows {
        let doc = row?;
        if let Ok(rule) = serde_json::from_str::<Rule>(&doc) {
            out.push(rule);
        }
    }
    Ok(out)
}

pub fn upsert(conn: &Connection, rule: &Rule) -> Result<(), VaultError> {
    let doc = serde_json::to_string(rule).unwrap_or_default();
    conn.execute(
        "INSERT INTO rules (id, doc) VALUES (?1, ?2)
         ON CONFLICT(id) DO UPDATE SET doc = ?2",
        rusqlite::params![rule.id, doc],
    )?;
    Ok(())
}

pub fn delete(conn: &Connection, id: &str) -> Result<(), VaultError> {
    conn.execute("DELETE FROM rules WHERE id = ?1", [id])?;
    conn.execute("DELETE FROM rule_state WHERE rule_id = ?1", [id])?;
    Ok(())
}

pub fn set_enabled(conn: &Connection, rule_id: &str, enabled: bool) -> Result<(), VaultError> {
    conn.execute(
        "INSERT INTO rule_state (rule_id, enabled) VALUES (?1, ?2)
         ON CONFLICT(rule_id) DO UPDATE SET enabled = ?2",
        rusqlite::params![rule_id, enabled as i64],
    )?;
    Ok(())
}

pub fn enabled_map(conn: &Connection) -> Result<HashMap<String, bool>, VaultError> {
    let mut stmt = conn.prepare("SELECT rule_id, enabled FROM rule_state")?;
    let rows = stmt.query_map([], |row| {
        Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)? != 0))
    })?;
    let mut map = HashMap::new();
    for row in rows {
        let (id, enabled) = row?;
        map.insert(id, enabled);
    }
    Ok(map)
}

pub fn next_custom_id(conn: &Connection) -> Result<String, VaultError> {
    let mut n = 1;
    loop {
        let id = format!("USER-{:02}", n);
        let exists: bool = conn
            .query_row("SELECT 1 FROM rules WHERE id = ?1", [&id], |_| Ok(true))
            .unwrap_or(false);
        if !exists {
            return Ok(id);
        }
        n += 1;
    }
}

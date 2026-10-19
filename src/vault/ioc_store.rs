use std::collections::HashSet;

use rusqlite::Connection;

use crate::vault::error::VaultError;

pub const ENSURE_SQL: &str = "
CREATE TABLE IF NOT EXISTS iocs (
    name TEXT NOT NULL DEFAULT '',
    path TEXT NOT NULL DEFAULT '',
    size INTEGER NOT NULL DEFAULT 0,
    hash TEXT NOT NULL DEFAULT ''
);
";

#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct Ioc {
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub path: String,
    #[serde(default)]
    pub size: i64,
    #[serde(default)]
    pub hash: String,
}

pub fn ensure(conn: &Connection) -> Result<(), VaultError> {
    conn.execute_batch(ENSURE_SQL)?;
    Ok(())
}

pub fn replace_all(conn: &mut Connection, entries: &[Ioc]) -> Result<usize, VaultError> {
    let tx = conn.transaction()?;
    {
        tx.execute("DELETE FROM iocs", [])?;
        let mut stmt = tx.prepare("INSERT INTO iocs (name, path, size, hash) VALUES (?1, ?2, ?3, ?4)")?;
        for e in entries {
            stmt.execute(rusqlite::params![e.name, e.path, e.size, e.hash])?;
        }
    }
    tx.commit()?;
    Ok(entries.len())
}

pub fn clear(conn: &Connection) -> Result<(), VaultError> {
    conn.execute("DELETE FROM iocs", [])?;
    Ok(())
}

pub fn count(conn: &Connection) -> Result<i64, VaultError> {
    conn.query_row("SELECT COUNT(*) FROM iocs", [], |row| row.get(0))
        .map_err(VaultError::from)
}

pub struct IocLookup {
    pub names: HashSet<String>,
    pub paths: HashSet<String>,
    pub sizes: HashSet<i64>,
}

pub fn lookup(conn: &Connection) -> Result<IocLookup, VaultError> {
    let mut names = HashSet::new();
    let mut paths = HashSet::new();
    let mut sizes = HashSet::new();
    let mut stmt = conn.prepare("SELECT name, path, size FROM iocs")?;
    let rows = stmt.query_map([], |row| {
        Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?, row.get::<_, i64>(2)?))
    })?;
    for row in rows.flatten() {
        if !row.0.is_empty() {
            names.insert(row.0.to_ascii_lowercase());
        }
        if !row.1.is_empty() {
            paths.insert(row.1.to_ascii_lowercase());
        }
        if row.2 > 0 {
            sizes.insert(row.2);
        }
    }
    Ok(IocLookup { names, paths, sizes })
}

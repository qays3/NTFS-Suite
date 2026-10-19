pub mod audit;
pub mod case_store;
pub mod error;
pub mod evidence_store;
pub mod finding_store;
pub mod ioc_store;
pub mod migrations;
pub mod record_store;
pub mod rule_store;
pub mod schema;
pub mod security_store;
pub mod usn_store;

use std::path::Path;

use rusqlite::Connection;

use error::VaultError;

pub struct Vault {
    pub conn: Connection,
}

impl Vault {
    pub fn create(
        path: &Path,
        name: &str,
        number: &str,
        analyst: &str,
        notes: &str,
    ) -> Result<Vault, VaultError> {
        if path.exists() {
            return Err(VaultError::AlreadyExists);
        }
        let conn = Connection::open(path)?;
        conn.pragma_update(None, "journal_mode", "WAL").ok();
        conn.pragma_update(None, "foreign_keys", "ON").ok();
        migrations::apply(&conn)?;
        case_store::initialize(&conn, name, number, analyst, notes)?;
        audit::record(&conn, analyst, "case_created", name)?;
        Ok(Vault { conn })
    }

    pub fn open(path: &Path) -> Result<Vault, VaultError> {
        if !path.exists() {
            return Err(VaultError::NotFound);
        }
        let conn = Connection::open(path)?;
        conn.pragma_update(None, "foreign_keys", "ON").ok();
        migrations::apply(&conn)?;
        Ok(Vault { conn })
    }

    pub fn open_in_memory() -> Result<Vault, VaultError> {
        let conn = Connection::open_in_memory()?;
        migrations::apply(&conn)?;
        Ok(Vault { conn })
    }

    pub fn schema_version(&self) -> Result<i64, VaultError> {
        migrations::read_version(&self.conn)
    }
}

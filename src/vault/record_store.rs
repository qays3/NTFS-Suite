use rusqlite::Connection;

use crate::vault::error::VaultError;

#[derive(Debug, Clone, Default, serde::Serialize)]
pub struct StoredRecord {
    pub entry: i64,
    pub sequence: i64,
    pub in_use: bool,
    pub is_directory: bool,
    pub has_ads: bool,
    pub orphan: bool,
    pub parent_entry: i64,
    pub si_created: String,
    pub si_modified: String,
    pub si_mft_modified: String,
    pub si_accessed: String,
    pub fn_created: String,
    pub name: String,
    pub path: String,
    pub si_flags: i64,
    pub owner_id: i64,
    pub security_id: i64,
    pub usn: i64,
    pub hard_link_count: i64,
    pub real_size: i64,
    pub short_name: String,
    pub reparse_tag: i64,
    pub reparse_target: String,
    pub resident_exe: bool,
}

pub const EXTRA_COLUMNS: &[(&str, &str)] = &[
    ("si_flags", "INTEGER NOT NULL DEFAULT 0"),
    ("owner_id", "INTEGER NOT NULL DEFAULT 0"),
    ("security_id", "INTEGER NOT NULL DEFAULT 0"),
    ("usn", "INTEGER NOT NULL DEFAULT 0"),
    ("hard_link_count", "INTEGER NOT NULL DEFAULT 0"),
    ("real_size", "INTEGER NOT NULL DEFAULT 0"),
    ("short_name", "TEXT NOT NULL DEFAULT ''"),
    ("reparse_tag", "INTEGER NOT NULL DEFAULT 0"),
    ("reparse_target", "TEXT NOT NULL DEFAULT ''"),
    ("resident_exe", "INTEGER NOT NULL DEFAULT 0"),
];

pub fn ensure_columns(conn: &Connection) -> Result<(), VaultError> {
    let mut present = std::collections::HashSet::new();
    if let Ok(mut stmt) = conn.prepare("PRAGMA table_info(records)") {
        if let Ok(rows) = stmt.query_map([], |row| row.get::<_, String>(1)) {
            for row in rows.flatten() {
                present.insert(row);
            }
        }
    }
    for (name, decl) in EXTRA_COLUMNS {
        if !present.contains(*name) {
            let sql = format!("ALTER TABLE records ADD COLUMN {} {}", name, decl);
            conn.execute(&sql, [])?;
        }
    }
    Ok(())
}

pub fn ensure_indexes(conn: &Connection) -> Result<(), VaultError> {
    let stmts = [
        "CREATE INDEX IF NOT EXISTS idx_records_reparse ON records(evidence_id, reparse_tag) WHERE reparse_tag <> 0",
        "CREATE INDEX IF NOT EXISTS idx_records_hardlink ON records(evidence_id, hard_link_count) WHERE hard_link_count > 1",
        "CREATE INDEX IF NOT EXISTS idx_records_owner ON records(evidence_id, owner_id)",
        "CREATE INDEX IF NOT EXISTS idx_records_security ON records(evidence_id, security_id)",
    ];
    for s in stmts {
        conn.execute(s, [])?;
    }
    Ok(())
}

pub fn insert_many(
    conn: &mut Connection,
    evidence_id: i64,
    records: &[StoredRecord],
) -> Result<usize, VaultError> {
    let tx = conn.transaction()?;
    {
        let mut stmt = tx.prepare(
            "INSERT OR REPLACE INTO records
             (evidence_id, entry, sequence, in_use, is_directory, has_ads, orphan, parent_entry,
              si_created, si_modified, si_mft_modified, si_accessed, fn_created, name, path,
              si_flags, owner_id, security_id, usn, hard_link_count, real_size, short_name,
              reparse_tag, reparse_target, resident_exe)
             VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?16,?17,?18,?19,?20,?21,?22,?23,?24,?25)",
        )?;
        for r in records {
            stmt.execute(rusqlite::params![
                evidence_id,
                r.entry,
                r.sequence,
                r.in_use as i64,
                r.is_directory as i64,
                r.has_ads as i64,
                r.orphan as i64,
                r.parent_entry,
                r.si_created,
                r.si_modified,
                r.si_mft_modified,
                r.si_accessed,
                r.fn_created,
                r.name,
                r.path,
                r.si_flags,
                r.owner_id,
                r.security_id,
                r.usn,
                r.hard_link_count,
                r.real_size,
                r.short_name,
                r.reparse_tag,
                r.reparse_target,
                r.resident_exe as i64,
            ])?;
        }
    }
    tx.commit()?;
    Ok(records.len())
}

#[derive(Debug, Clone, Default)]
pub struct RecordFilter {
    pub search: String,
    pub deleted_only: bool,
    pub ads_only: bool,
    pub dir_only: bool,
    pub orphan_only: bool,
    pub si_lt_fn_only: bool,
    pub fn_lt_si_only: bool,
    pub after: String,
    pub before: String,
}

fn where_clause(filter: &RecordFilter) -> (String, Vec<String>) {
    let mut clauses = vec![String::from("evidence_id = ?1")];
    let mut params: Vec<String> = Vec::new();
    if !filter.search.is_empty() {
        let i = 2 + params.len();
        clauses.push(format!("(name LIKE ?{i} OR path LIKE ?{i})"));
        params.push(format!("%{}%", filter.search));
    }
    if filter.deleted_only {
        clauses.push(String::from("in_use = 0"));
    }
    if filter.ads_only {
        clauses.push(String::from("has_ads = 1"));
    }
    if filter.dir_only {
        clauses.push(String::from("is_directory = 1"));
    }
    if filter.orphan_only {
        clauses.push(String::from("orphan = 1"));
    }
    if filter.si_lt_fn_only {
        clauses.push(String::from(
            "si_created <> '1601-01-01T00:00:00.0000000Z' AND fn_created <> '1601-01-01T00:00:00.0000000Z' AND si_created < fn_created",
        ));
    }
    if filter.fn_lt_si_only {
        clauses.push(String::from(
            "si_created <> '1601-01-01T00:00:00.0000000Z' AND fn_created <> '1601-01-01T00:00:00.0000000Z' AND fn_created < si_created",
        ));
    }
    if !filter.after.is_empty() || !filter.before.is_empty() {
        let ai = 2 + params.len();
        params.push(if filter.after.is_empty() {
            String::from("1700-01-01T00:00:00.0000000Z")
        } else {
            format!("{}T00:00:00.0000000Z", filter.after)
        });
        let bi = 2 + params.len();
        params.push(if filter.before.is_empty() {
            String::from("9999-12-31T23:59:59.9999999Z")
        } else {
            format!("{}T23:59:59.9999999Z", filter.before)
        });
        let fields = ["si_created", "si_modified", "si_mft_modified", "si_accessed", "fn_created"];
        let ors: Vec<String> = fields
            .iter()
            .map(|f| format!("({f} BETWEEN ?{ai} AND ?{bi})"))
            .collect();
        clauses.push(format!("({})", ors.join(" OR ")));
    }
    (clauses.join(" AND "), params)
}

#[derive(Debug, Clone, Default, serde::Serialize)]
pub struct RecordStats {
    pub records: i64,
    pub in_use: i64,
    pub deleted: i64,
    pub directories: i64,
    pub with_ads: i64,
    pub orphans: i64,
}

pub fn stats(conn: &Connection, evidence_id: i64) -> Result<RecordStats, VaultError> {
    conn.query_row(
        "SELECT COUNT(*),
                SUM(in_use),
                SUM(CASE WHEN in_use = 0 THEN 1 ELSE 0 END),
                SUM(is_directory),
                SUM(has_ads),
                SUM(orphan)
         FROM records WHERE evidence_id = ?1",
        [evidence_id],
        |row| {
            Ok(RecordStats {
                records: row.get(0)?,
                in_use: row.get::<_, Option<i64>>(1)?.unwrap_or(0),
                deleted: row.get::<_, Option<i64>>(2)?.unwrap_or(0),
                directories: row.get::<_, Option<i64>>(3)?.unwrap_or(0),
                with_ads: row.get::<_, Option<i64>>(4)?.unwrap_or(0),
                orphans: row.get::<_, Option<i64>>(5)?.unwrap_or(0),
            })
        },
    )
    .map_err(VaultError::from)
}

pub fn count(conn: &Connection, evidence_id: i64) -> Result<i64, VaultError> {
    count_filtered(conn, evidence_id, &RecordFilter::default())
}

pub fn count_filtered(
    conn: &Connection,
    evidence_id: i64,
    filter: &RecordFilter,
) -> Result<i64, VaultError> {
    let (clause, extra) = where_clause(filter);
    let sql = format!("SELECT COUNT(*) FROM records WHERE {}", clause);
    let mut stmt = conn.prepare(&sql)?;
    let mut bind: Vec<&dyn rusqlite::ToSql> = vec![&evidence_id];
    for e in extra.iter() {
        bind.push(e);
    }
    let n: i64 = stmt.query_row(bind.as_slice(), |row| row.get(0))?;
    Ok(n)
}

pub fn page_filtered(
    conn: &Connection,
    evidence_id: i64,
    filter: &RecordFilter,
    offset: i64,
    limit: i64,
) -> Result<Vec<StoredRecord>, VaultError> {
    let (clause, extra) = where_clause(filter);
    let sql = format!(
        "SELECT entry, sequence, in_use, is_directory, has_ads, orphan, parent_entry,
                si_created, si_modified, si_mft_modified, si_accessed, fn_created, name, path, si_flags, owner_id, security_id, usn, hard_link_count, real_size, short_name, reparse_tag, reparse_target, resident_exe
         FROM records WHERE {} ORDER BY entry ASC LIMIT ?{} OFFSET ?{}",
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
    let rows = stmt.query_map(bind.as_slice(), map_record)?;
    let mut out = Vec::new();
    for r in rows {
        out.push(r?);
    }
    Ok(out)
}

pub fn for_each_filtered<F: FnMut(&StoredRecord)>(
    conn: &Connection,
    evidence_id: i64,
    filter: &RecordFilter,
    mut handler: F,
) -> Result<(), VaultError> {
    let (clause, extra) = where_clause(filter);
    let sql = format!(
        "SELECT entry, sequence, in_use, is_directory, has_ads, orphan, parent_entry,
                si_created, si_modified, si_mft_modified, si_accessed, fn_created, name, path, si_flags, owner_id, security_id, usn, hard_link_count, real_size, short_name, reparse_tag, reparse_target, resident_exe
         FROM records WHERE {} ORDER BY entry ASC",
        clause
    );
    let mut stmt = conn.prepare(&sql)?;
    let mut bind: Vec<&dyn rusqlite::ToSql> = vec![&evidence_id];
    for e in extra.iter() {
        bind.push(e);
    }
    let mut rows = stmt.query(bind.as_slice())?;
    while let Some(row) = rows.next()? {
        let record = map_record(row)?;
        handler(&record);
    }
    Ok(())
}

fn map_record(row: &rusqlite::Row) -> rusqlite::Result<StoredRecord> {
    Ok(StoredRecord {
        entry: row.get(0)?,
        sequence: row.get(1)?,
        in_use: row.get::<_, i64>(2)? != 0,
        is_directory: row.get::<_, i64>(3)? != 0,
        has_ads: row.get::<_, i64>(4)? != 0,
        orphan: row.get::<_, i64>(5)? != 0,
        parent_entry: row.get(6)?,
        si_created: row.get(7)?,
        si_modified: row.get(8)?,
        si_mft_modified: row.get(9)?,
        si_accessed: row.get(10)?,
        fn_created: row.get(11)?,
        name: row.get(12)?,
        path: row.get(13)?,
        si_flags: row.get(14)?,
        owner_id: row.get(15)?,
        security_id: row.get(16)?,
        usn: row.get(17)?,
        hard_link_count: row.get(18)?,
        real_size: row.get(19)?,
        short_name: row.get(20)?,
        reparse_tag: row.get(21)?,
        reparse_target: row.get(22)?,
        resident_exe: row.get::<_, i64>(23)? != 0,
    })
}

pub fn get(conn: &Connection, evidence_id: i64, entry: i64) -> Result<Option<StoredRecord>, VaultError> {
    let mut stmt = conn.prepare(
        "SELECT entry, sequence, in_use, is_directory, has_ads, orphan, parent_entry,
                si_created, si_modified, si_mft_modified, si_accessed, fn_created, name, path, si_flags, owner_id, security_id, usn, hard_link_count, real_size, short_name, reparse_tag, reparse_target, resident_exe
         FROM records WHERE evidence_id = ?1 AND entry = ?2",
    )?;
    let mut rows = stmt.query(rusqlite::params![evidence_id, entry])?;
    if let Some(row) = rows.next()? {
        Ok(Some(map_record(row)?))
    } else {
        Ok(None)
    }
}

pub fn count_children(
    conn: &Connection,
    evidence_id: i64,
    parent_entry: i64,
) -> Result<i64, VaultError> {
    conn.query_row(
        "SELECT COUNT(*) FROM records WHERE evidence_id = ?1 AND parent_entry = ?2 AND entry <> ?2",
        rusqlite::params![evidence_id, parent_entry],
        |row| row.get(0),
    )
    .map_err(VaultError::from)
}

pub fn children(
    conn: &Connection,
    evidence_id: i64,
    parent_entry: i64,
    limit: i64,
) -> Result<Vec<StoredRecord>, VaultError> {
    let mut stmt = conn.prepare(
        "SELECT entry, sequence, in_use, is_directory, has_ads, orphan, parent_entry,
                si_created, si_modified, si_mft_modified, si_accessed, fn_created, name, path, si_flags, owner_id, security_id, usn, hard_link_count, real_size, short_name, reparse_tag, reparse_target, resident_exe
         FROM records WHERE evidence_id = ?1 AND parent_entry = ?2 AND entry <> ?2 ORDER BY entry LIMIT ?3",
    )?;
    let rows = stmt.query_map(rusqlite::params![evidence_id, parent_entry, limit], map_record)?;
    let mut out = Vec::new();
    for r in rows {
        out.push(r?);
    }
    Ok(out)
}

pub fn page(
    conn: &Connection,
    evidence_id: i64,
    offset: i64,
    limit: i64,
) -> Result<Vec<StoredRecord>, VaultError> {
    let mut stmt = conn.prepare(
        "SELECT entry, sequence, in_use, is_directory, has_ads, orphan, parent_entry,
                si_created, si_modified, si_mft_modified, si_accessed, fn_created, name, path, si_flags, owner_id, security_id, usn, hard_link_count, real_size, short_name, reparse_tag, reparse_target, resident_exe
         FROM records WHERE evidence_id = ?1 ORDER BY entry ASC LIMIT ?2 OFFSET ?3",
    )?;
    let rows = stmt.query_map(rusqlite::params![evidence_id, limit, offset], map_record)?;
    let mut out = Vec::new();
    for r in rows {
        out.push(r?);
    }
    Ok(out)
}

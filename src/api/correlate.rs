use std::collections::HashSet;

use rusqlite::Connection;

// Which security ids exist in $Secure (so a record's security id resolves).
pub fn secure_ids(conn: &Connection) -> HashSet<i64> {
    let mut set = HashSet::new();
    if let Ok(mut stmt) = conn.prepare("SELECT DISTINCT security_id FROM security_descriptors") {
        if let Ok(rows) = stmt.query_map([], |r| r.get::<_, i64>(0)) {
            for r in rows.flatten() {
                set.insert(r);
            }
        }
    }
    set
}

// Which of the given MFT entries appear in the $UsnJrnl change journal.
pub fn usn_entries(conn: &Connection, entries: &[i64]) -> HashSet<i64> {
    let mut set = HashSet::new();
    if entries.is_empty() {
        return set;
    }
    let list = entries
        .iter()
        .map(|e| e.to_string())
        .collect::<Vec<_>>()
        .join(",");
    let sql = format!("SELECT DISTINCT entry FROM usn_events WHERE entry IN ({})", list);
    if let Ok(mut stmt) = conn.prepare(&sql) {
        if let Ok(rows) = stmt.query_map([], |r| r.get::<_, i64>(0)) {
            for r in rows.flatten() {
                set.insert(r);
            }
        }
    }
    set
}

// The artifacts that mention a record. $MFT is always one, since the record is
// an $MFT entry; $UsnJrnl and $Secure are added when the entry or its security
// id is found in those artifacts.
pub fn sources_for(
    entry: i64,
    security_id: i64,
    usn: &HashSet<i64>,
    secure: &HashSet<i64>,
) -> Vec<String> {
    let mut s = vec![String::from("$MFT")];
    if usn.contains(&entry) {
        s.push(String::from("$UsnJrnl"));
    }
    if security_id != 0 && secure.contains(&security_id) {
        s.push(String::from("$Secure"));
    }
    s
}

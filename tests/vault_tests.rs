use ntfs_suite::vault::{audit, case_store, evidence_store, record_store};
use ntfs_suite::vault::record_store::StoredRecord;
use ntfs_suite::vault::schema::SCHEMA_VERSION;
use ntfs_suite::Vault;

fn sample_record(entry: i64, name: &str) -> StoredRecord {
    StoredRecord {
        entry,
        sequence: 1,
        in_use: true,
        is_directory: false,
        has_ads: false,
        orphan: false,
        parent_entry: 5,
        si_created: String::from("2024-01-01T00:00:00.0000000Z"),
        si_modified: String::from("2024-01-02T00:00:00.0000000Z"),
        si_mft_modified: String::from("2024-01-02T00:00:00.0000000Z"),
        si_accessed: String::from("2024-01-02T00:00:00.0000000Z"),
        fn_created: String::from("2024-01-01T00:00:00.0000000Z"),
        name: name.to_string(),
        path: format!("\\{}", name),
        ..Default::default()
    }
}

#[test]
fn creates_schema_and_case() {
    let mut vault = Vault::open_in_memory().unwrap();
    assert_eq!(vault.schema_version().unwrap(), SCHEMA_VERSION);
    case_store::initialize(&vault.conn, "case one", "C-1", "qays", "notes").unwrap();
    let info = case_store::get(&vault.conn).unwrap();
    assert_eq!(info.name, "case one");
    assert_eq!(info.display_timezone, "UTC");

    let id = evidence_store::add(&vault.conn, "$MFT", "/path/$MFT", 1024, "abc", "mft").unwrap();
    let records = vec![sample_record(60, "a.txt"), sample_record(61, "b.txt")];
    let written = record_store::insert_many(&mut vault.conn, id, &records).unwrap();
    assert_eq!(written, 2);
    assert_eq!(record_store::count(&vault.conn, id).unwrap(), 2);

    evidence_store::mark_parsed(&vault.conn, id).unwrap();
    let listed = evidence_store::list(&vault.conn).unwrap();
    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0].status, "parsed");
    assert!(listed[0].parsed_utc.is_some());
}

#[test]
fn paging_records() {
    let mut vault = Vault::open_in_memory().unwrap();
    case_store::initialize(&vault.conn, "c", "", "", "").unwrap();
    let id = evidence_store::add(&vault.conn, "$MFT", "/p", 10, "h", "mft").unwrap();
    let records: Vec<StoredRecord> = (0..50).map(|i| sample_record(i, "f")).collect();
    record_store::insert_many(&mut vault.conn, id, &records).unwrap();
    let page = record_store::page(&vault.conn, id, 10, 5).unwrap();
    assert_eq!(page.len(), 5);
    assert_eq!(page[0].entry, 10);
    assert_eq!(page[4].entry, 14);
}

#[test]
fn timezone_update() {
    let vault = Vault::open_in_memory().unwrap();
    case_store::initialize(&vault.conn, "c", "", "", "").unwrap();
    case_store::set_timezone(&vault.conn, "Asia/Amman").unwrap();
    assert_eq!(case_store::get(&vault.conn).unwrap().display_timezone, "Asia/Amman");
}

#[test]
fn audit_log_records_actions() {
    let vault = Vault::open_in_memory().unwrap();
    audit::record(&vault.conn, "qays", "case_created", "case one").unwrap();
    audit::record(&vault.conn, "qays", "evidence_added", "$MFT").unwrap();
    let entries = audit::list(&vault.conn).unwrap();
    assert_eq!(entries.len(), 2);
    assert_eq!(entries[0].action, "case_created");
    assert_eq!(entries[1].actor, "qays");
}

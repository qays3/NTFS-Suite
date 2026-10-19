use ntfs_suite::api::charts;
use ntfs_suite::vault::record_store::{self, StoredRecord};
use ntfs_suite::vault::Vault;

fn rec(entry: i64, name: &str, path: &str, si: &str, fnc: &str) -> StoredRecord {
    StoredRecord {
        entry,
        sequence: 1,
        in_use: true,
        is_directory: false,
        has_ads: false,
        orphan: false,
        parent_entry: 5,
        si_created: si.to_string(),
        si_modified: si.to_string(),
        si_mft_modified: si.to_string(),
        si_accessed: si.to_string(),
        fn_created: fnc.to_string(),
        name: name.to_string(),
        path: path.to_string(),
        ..Default::default()
    }
}

#[test]
fn dashboard_aggregates() {
    let mut vault = Vault::open_in_memory().unwrap();
    let rows = vec![
        rec(10, "a.txt", "\\Users\\a\\a.txt", "2024-03-24T08:57:48.2247295Z", "2024-03-24T08:57:48.2247295Z"),
        rec(11, "b.exe", "\\Users\\a\\b.exe", "2022-05-07T05:17:22.0000000Z", "2024-03-24T08:57:26.5452710Z"),
        rec(12, "c.dll", "\\Users\\a\\c.dll", "2024-03-25T14:00:00.1234567Z", "2024-03-25T14:00:00.1234567Z"),
    ];
    record_store::insert_many(&mut vault.conn, 1, &rows).unwrap();
    let wc = charts::where_clause(&None, &None);
    let board = charts::build(&vault.conn, 1, &wc).unwrap();
    assert_eq!(board.totals.records, 3);
    assert_eq!(board.subsecond.len(), 10);
    assert!(board.subsecond[0] >= 1);
    assert!(board.si_fn.iter().any(|p| p.stomp));
    assert!(!board.density.is_empty());
    assert!(board.extensions.iter().any(|e| e.name == "exe"));
}

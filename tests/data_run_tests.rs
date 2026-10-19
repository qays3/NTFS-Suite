use ntfs_suite::mft::data_runs::parse_data_runs;

#[test]
fn single_run() {
    let bytes = [0x21u8, 0x18, 0x34, 0x56, 0x00];
    let runs = parse_data_runs(&bytes).unwrap();
    assert_eq!(runs.len(), 1);
    assert_eq!(runs[0].length_clusters, 0x18);
    assert_eq!(runs[0].start_lcn, Some(0x5634));
}

#[test]
fn fragmented_two_runs() {
    let bytes = [0x11u8, 0x30, 0x60, 0x11, 0x10, 0x20, 0x00];
    let runs = parse_data_runs(&bytes).unwrap();
    assert_eq!(runs.len(), 2);
    assert_eq!(runs[0].length_clusters, 0x30);
    assert_eq!(runs[0].start_lcn, Some(0x60));
    assert_eq!(runs[1].length_clusters, 0x10);
    assert_eq!(runs[1].start_lcn, Some(0x60 + 0x20));
}

#[test]
fn negative_offset() {
    let bytes = [0x11u8, 0x10, 0x60, 0x11, 0x10, 0xE0, 0x00];
    let runs = parse_data_runs(&bytes).unwrap();
    assert_eq!(runs[1].start_lcn, Some(0x60 - 0x20));
}

#[test]
fn sparse_run_has_no_lcn() {
    let bytes = [0x01u8, 0x20, 0x00];
    let runs = parse_data_runs(&bytes).unwrap();
    assert_eq!(runs.len(), 1);
    assert_eq!(runs[0].length_clusters, 0x20);
    assert_eq!(runs[0].start_lcn, None);
}

#[test]
fn empty_terminates() {
    let bytes = [0x00u8];
    let runs = parse_data_runs(&bytes).unwrap();
    assert!(runs.is_empty());
}

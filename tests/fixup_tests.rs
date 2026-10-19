mod common;

use common::RecordBuilder;
use ntfs_suite::mft::header::FLAG_IN_USE;
use ntfs_suite::MftRecord;

fn t() -> u64 {
    132_223_104_000_000_000
}

#[test]
fn fixup_restores_sector_tails() {
    let raw = RecordBuilder::new(1, 1, FLAG_IN_USE)
        .add_standard_information(t(), t(), t(), t(), 0x20)
        .add_file_name(5, 5, t(), t(), t(), t(), 10, 1, "x.txt")
        .build();
    let record = MftRecord::parse(&raw).unwrap();
    assert!(record.fixup_ok);
}

#[test]
fn corrupt_fixup_is_flagged() {
    let mut raw = RecordBuilder::new(1, 1, FLAG_IN_USE)
        .add_standard_information(t(), t(), t(), t(), 0x20)
        .add_file_name(5, 5, t(), t(), t(), t(), 10, 1, "x.txt")
        .build();
    raw[510] = 0xFF;
    raw[511] = 0xFF;
    let record = MftRecord::parse(&raw).unwrap();
    assert!(!record.fixup_ok);
}

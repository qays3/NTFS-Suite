mod common;

use std::collections::HashMap;

use common::RecordBuilder;
use ntfs_suite::mft::header::{FLAG_DIRECTORY, FLAG_IN_USE};
use ntfs_suite::{MftRecord, PathResolver};

fn t() -> u64 {
    132_223_104_000_000_000
}

fn dir(number: u32, seq: u16, parent: u64, parent_seq: u16, name: &str) -> MftRecord {
    let raw = RecordBuilder::new(number, seq, FLAG_IN_USE | FLAG_DIRECTORY)
        .add_standard_information(t(), t(), t(), t(), 0x10)
        .add_file_name(parent, parent_seq, t(), t(), t(), t(), 0, 1, name)
        .build();
    MftRecord::parse(&raw).unwrap()
}

fn file(number: u32, seq: u16, parent: u64, parent_seq: u16, name: &str) -> MftRecord {
    let raw = RecordBuilder::new(number, seq, FLAG_IN_USE)
        .add_standard_information(t(), t(), t(), t(), 0x20)
        .add_file_name(parent, parent_seq, t(), t(), t(), t(), 100, 1, name)
        .build();
    MftRecord::parse(&raw).unwrap()
}

fn root() -> MftRecord {
    let raw = RecordBuilder::new(5, 5, FLAG_IN_USE | FLAG_DIRECTORY)
        .add_standard_information(t(), t(), t(), t(), 0x10)
        .add_file_name(5, 5, t(), t(), t(), t(), 0, 1, ".")
        .build();
    MftRecord::parse(&raw).unwrap()
}

#[test]
fn builds_full_path() {
    let mut records = HashMap::new();
    records.insert(5u64, root());
    records.insert(40u64, dir(40, 1, 5, 5, "Users"));
    records.insert(41u64, dir(41, 1, 40, 1, "qays"));
    records.insert(42u64, dir(42, 1, 41, 1, "Documents"));
    records.insert(60u64, file(60, 1, 42, 1, "report.docx"));
    let resolver = PathResolver::build(&records);
    let resolved = resolver.resolve(60).unwrap();
    assert_eq!(resolved.path, "\\Users\\qays\\Documents\\report.docx");
    assert!(!resolved.orphan);
}

#[test]
fn marks_orphan_on_missing_parent() {
    let mut records = HashMap::new();
    records.insert(5u64, root());
    records.insert(60u64, file(60, 1, 999, 1, "lost.txt"));
    let resolver = PathResolver::build(&records);
    let resolved = resolver.resolve(60).unwrap();
    assert!(resolved.orphan);
    assert!(resolved.path.starts_with('?'));
}

#[test]
fn marks_orphan_on_sequence_mismatch() {
    let mut records = HashMap::new();
    records.insert(5u64, root());
    records.insert(40u64, dir(40, 7, 5, 5, "Temp"));
    records.insert(60u64, file(60, 1, 40, 2, "reused.txt"));
    let resolver = PathResolver::build(&records);
    let resolved = resolver.resolve(60).unwrap();
    assert!(resolved.orphan);
}

#[test]
fn root_resolves_to_backslash() {
    let mut records = HashMap::new();
    records.insert(5u64, root());
    let resolver = PathResolver::build(&records);
    assert_eq!(resolver.resolve(5).unwrap().path, "\\");
}

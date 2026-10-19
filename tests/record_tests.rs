mod common;

use common::RecordBuilder;
use ntfs_suite::mft::header::FLAG_IN_USE;
use ntfs_suite::MftRecord;

fn si_time() -> u64 {
    132_223_104_000_000_000
}

#[test]
fn parses_header_and_fixup() {
    let raw = RecordBuilder::new(42, 3, FLAG_IN_USE)
        .add_standard_information(si_time(), si_time(), si_time(), si_time(), 0x20)
        .add_file_name(5, 5, si_time(), si_time(), si_time(), si_time(), 1024, 1, "test.txt")
        .build();
    let record = MftRecord::parse(&raw).unwrap();
    assert!(record.header.is_file());
    assert!(record.fixup_ok);
    assert_eq!(record.header.record_number, 42);
    assert_eq!(record.header.sequence_number, 3);
    assert!(record.in_use());
    assert_eq!(raw[510], 0xCD);
    assert_eq!(raw[511], 0xAB);
    assert_eq!(raw[1022], 0xCD);
    assert_eq!(raw[1023], 0xAB);
}

#[test]
fn reads_standard_information() {
    let raw = RecordBuilder::new(60, 1, FLAG_IN_USE)
        .add_standard_information(si_time(), si_time() + 100, si_time(), si_time(), 0x20)
        .add_file_name(5, 5, si_time(), si_time(), si_time(), si_time(), 10, 1, "a.txt")
        .build();
    let record = MftRecord::parse(&raw).unwrap();
    let si = record.standard_information().unwrap();
    assert_eq!(si.created.ticks, si_time());
    assert_eq!(si.modified.ticks, si_time() + 100);
    assert_eq!(si.flags, 0x20);
}

#[test]
fn reads_file_name_and_parent() {
    let raw = RecordBuilder::new(61, 1, FLAG_IN_USE)
        .add_standard_information(si_time(), si_time(), si_time(), si_time(), 0x20)
        .add_file_name(5, 5, si_time(), si_time(), si_time(), si_time(), 4096, 1, "report.docx")
        .build();
    let record = MftRecord::parse(&raw).unwrap();
    let fna = record.best_name().unwrap();
    assert_eq!(fna.name, "report.docx");
    assert_eq!(fna.parent_entry, 5);
    assert_eq!(fna.parent_sequence, 5);
    assert_eq!(fna.real_size, 4096);
}

#[test]
fn detects_alternate_data_stream() {
    let raw = RecordBuilder::new(70, 1, FLAG_IN_USE)
        .add_standard_information(si_time(), si_time(), si_time(), si_time(), 0x20)
        .add_file_name(5, 5, si_time(), si_time(), si_time(), si_time(), 10, 1, "host.txt")
        .add_resident_data(None, b"primary")
        .add_resident_data(Some("Zone.Identifier"), b"[ZoneTransfer]\r\nZoneId=3\r\n")
        .build();
    let record = MftRecord::parse(&raw).unwrap();
    let ads = record.alternate_streams();
    assert_eq!(ads.len(), 1);
    assert_eq!(ads[0].name.as_deref(), Some("Zone.Identifier"));
    let content = ads[0].resident_bytes().unwrap();
    assert!(content.windows(7).any(|w| w == b"ZoneId=3".get(0..7).unwrap()));
}

#[test]
fn deleted_record_flag() {
    let raw = RecordBuilder::new(80, 2, 0)
        .add_standard_information(si_time(), si_time(), si_time(), si_time(), 0x20)
        .add_file_name(5, 5, si_time(), si_time(), si_time(), si_time(), 10, 1, "gone.exe")
        .build();
    let record = MftRecord::parse(&raw).unwrap();
    assert!(!record.in_use());
}

#[test]
fn prefers_long_name_over_dos() {
    let raw = RecordBuilder::new(90, 1, FLAG_IN_USE)
        .add_standard_information(si_time(), si_time(), si_time(), si_time(), 0x20)
        .add_file_name(5, 5, si_time(), si_time(), si_time(), si_time(), 10, 2, "LONGFI~1.TXT")
        .add_file_name(5, 5, si_time(), si_time(), si_time(), si_time(), 10, 1, "longfilename.txt")
        .build();
    let record = MftRecord::parse(&raw).unwrap();
    assert_eq!(record.best_name().unwrap().name, "longfilename.txt");
    assert_eq!(record.file_names().len(), 2);
}

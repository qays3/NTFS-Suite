use ntfs_suite::usn::{for_each_record, reason_labels, reason_summary};

fn build_v2(
    file_ref: u64,
    parent_ref: u64,
    usn: i64,
    timestamp: u64,
    reason: u32,
    security_id: u32,
    attrs: u32,
    name: &str,
) -> Vec<u8> {
    let name_utf16: Vec<u8> = name.encode_utf16().flat_map(|u| u.to_le_bytes()).collect();
    let name_off: u16 = 0x3C;
    let mut body_len = name_off as usize + name_utf16.len();
    // 8-byte align.
    if body_len % 8 != 0 {
        body_len += 8 - (body_len % 8);
    }
    let mut rec = vec![0u8; body_len];
    rec[0..4].copy_from_slice(&(body_len as u32).to_le_bytes());
    rec[4..6].copy_from_slice(&2u16.to_le_bytes()); // major
    rec[6..8].copy_from_slice(&0u16.to_le_bytes()); // minor
    rec[0x08..0x10].copy_from_slice(&file_ref.to_le_bytes());
    rec[0x10..0x18].copy_from_slice(&parent_ref.to_le_bytes());
    rec[0x18..0x20].copy_from_slice(&(usn as u64).to_le_bytes());
    rec[0x20..0x28].copy_from_slice(&timestamp.to_le_bytes());
    rec[0x28..0x2C].copy_from_slice(&reason.to_le_bytes());
    rec[0x2C..0x30].copy_from_slice(&0u32.to_le_bytes()); // source info
    rec[0x30..0x34].copy_from_slice(&security_id.to_le_bytes());
    rec[0x34..0x38].copy_from_slice(&attrs.to_le_bytes());
    rec[0x38..0x3A].copy_from_slice(&(name_utf16.len() as u16).to_le_bytes());
    rec[0x3A..0x3C].copy_from_slice(&name_off.to_le_bytes());
    rec[0x3C..0x3C + name_utf16.len()].copy_from_slice(&name_utf16);
    rec
}

fn ref_of(entry: u64, sequence: u16) -> u64 {
    (entry & 0x0000_FFFF_FFFF_FFFF) | ((sequence as u64) << 48)
}

#[test]
fn parses_records_after_sparse_gap() {
    let mut buf = vec![0u8; 64]; // leading sparse zero region
    buf.extend(build_v2(
        ref_of(100, 3),
        ref_of(5, 5),
        0x1000,
        130000000000000000,
        0x0000_0100, // file create
        260,
        0x20,
        "evil.exe",
    ));
    buf.extend(build_v2(
        ref_of(100, 3),
        ref_of(5, 5),
        0x1050,
        130000000000000001,
        0x0000_0200 | 0x8000_0000, // file delete + close
        260,
        0x20,
        "evil.exe",
    ));

    let mut recs = Vec::new();
    let stats = for_each_record(&buf, |r| { recs.push(r.clone()); true });
    assert_eq!(stats.records, 2);
    assert_eq!(recs[0].entry, 100);
    assert_eq!(recs[0].sequence, 3);
    assert_eq!(recs[0].parent_entry, 5);
    assert_eq!(recs[0].name, "evil.exe");
    assert_eq!(recs[0].security_id, 260);
    assert_eq!(reason_summary(recs[0].reason), "create");
    assert_eq!(reason_summary(recs[1].reason), "delete");
    assert!(reason_labels(recs[1].reason).contains(&"file delete"));
    assert!(reason_labels(recs[1].reason).contains(&"close"));
}

#[test]
fn ignores_trailing_zeros() {
    let mut buf = build_v2(ref_of(7, 1), ref_of(5, 5), 1, 130000000000000000, 0x0000_0100, 0, 0, "a.txt");
    buf.extend(vec![0u8; 128]);
    let mut n = 0;
    for_each_record(&buf, |_| { n += 1; true });
    assert_eq!(n, 1);
}

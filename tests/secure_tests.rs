use ntfs_suite::secure::{for_each_entry, parse_descriptor, sid_to_string, well_known_name};

// S-1-5-18 (SYSTEM): revision 1, 1 sub-authority, authority 5, sub 18.
fn sid_system() -> Vec<u8> {
    let mut v = vec![1u8, 1u8];
    v.extend_from_slice(&[0, 0, 0, 0, 0, 5]); // authority 5, big-endian
    v.extend_from_slice(&18u32.to_le_bytes());
    v
}

fn build_descriptor() -> Vec<u8> {
    let system = sid_system();

    // DACL with one ACCESS_ALLOWED ACE granting SYSTEM.
    let mut ace = vec![0u8, 0u8]; // type 0 (allowed), flags 0
    let ace_size: u16 = (8 + system.len()) as u16;
    ace.extend_from_slice(&ace_size.to_le_bytes());
    ace.extend_from_slice(&0x1F01FFu32.to_le_bytes()); // access mask
    ace.extend_from_slice(&system);

    let mut dacl = vec![2u8, 0u8]; // acl revision 2, sbz
    let dacl_size: u16 = (8 + ace.len()) as u16;
    dacl.extend_from_slice(&dacl_size.to_le_bytes());
    dacl.extend_from_slice(&1u16.to_le_bytes()); // ace count
    dacl.extend_from_slice(&0u16.to_le_bytes()); // sbz2
    dacl.extend_from_slice(&ace);

    // Self-relative security descriptor header (20 bytes).
    let dacl_off: u32 = 20;
    let owner_off: u32 = 20 + dacl.len() as u32;
    let mut sd = vec![1u8, 0u8]; // revision, sbz1
    sd.extend_from_slice(&0x8004u16.to_le_bytes()); // control: self-relative + DACL present
    sd.extend_from_slice(&owner_off.to_le_bytes());
    sd.extend_from_slice(&0u32.to_le_bytes()); // group off
    sd.extend_from_slice(&0u32.to_le_bytes()); // sacl off
    sd.extend_from_slice(&dacl_off.to_le_bytes());
    sd.extend_from_slice(&dacl);
    sd.extend_from_slice(&system); // owner SID
    sd
}

#[test]
fn sid_renders_system() {
    let s = sid_system();
    assert_eq!(sid_to_string(&s, 0).unwrap(), "S-1-5-18");
    assert_eq!(well_known_name("S-1-5-18"), "SYSTEM");
    assert_eq!(well_known_name("S-1-5-32-544"), "Administrators");
    assert_eq!(well_known_name("S-1-5-21-111-222-333-500"), "Administrator");
    assert_eq!(well_known_name("S-1-5-21-111-222-333-1001"), "Account (RID 1001)");
}

#[test]
fn parses_descriptor_owner_and_dacl() {
    let sd = build_descriptor();
    let d = parse_descriptor(&sd).unwrap();
    assert_eq!(d.owner_sid, "S-1-5-18");
    assert_eq!(d.owner_name, "SYSTEM");
    assert_eq!(d.ace_count, 1);
    assert_eq!(d.allow_count, 1);
    assert_eq!(d.deny_count, 0);
}

#[test]
fn scans_sds_entries_and_dedupes() {
    let sd = build_descriptor();
    let length: u32 = 20 + sd.len() as u32;

    let build_entry = |sec_id: u32| -> Vec<u8> {
        let mut e = Vec::new();
        e.extend_from_slice(&0u32.to_le_bytes()); // hash
        e.extend_from_slice(&sec_id.to_le_bytes());
        e.extend_from_slice(&0u64.to_le_bytes()); // offset
        e.extend_from_slice(&length.to_le_bytes());
        e.extend_from_slice(&sd);
        while e.len() % 16 != 0 {
            e.push(0);
        }
        e
    };

    let mut sds = build_entry(0x100);
    sds.extend(build_entry(0x101));
    sds.extend(build_entry(0x100)); // duplicate mirror of 0x100

    let mut got = Vec::new();
    let stats = for_each_entry(&sds, |id, d| got.push((id, d.owner_name.clone())));
    assert_eq!(stats.descriptors, 2); // 0x100 and 0x101, duplicate skipped
    assert_eq!(got[0], (0x100, "SYSTEM".to_string()));
    assert_eq!(got[1], (0x101, "SYSTEM".to_string()));
}

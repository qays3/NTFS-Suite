use crate::util::bytes::{u16_le, u32_le, u64_le};
use crate::util::filetime::FileTime;

pub const MIN_RECORD_LEN: u32 = 60;
pub const MAX_RECORD_LEN: u32 = 64 * 1024;

#[derive(Debug, Clone)]
pub struct UsnRecord {
    pub usn: i64,
    pub timestamp: FileTime,
    pub entry: u64,
    pub sequence: u16,
    pub parent_entry: u64,
    pub parent_sequence: u16,
    pub reason: u32,
    pub source_info: u32,
    pub security_id: i64,
    pub file_attributes: u32,
    pub name: String,
}

#[derive(Debug, Default, Clone, Copy)]
pub struct UsnStats {
    pub records: u64,
    pub skipped: u64,
}

fn split_ref(reference: u64) -> (u64, u16) {
    (reference & 0x0000_FFFF_FFFF_FFFF, (reference >> 48) as u16)
}

// Parse one USN_RECORD_V2 at `off`. Returns the record and its on-disk length.
fn parse_v2(buf: &[u8], off: usize, record_len: u32) -> Option<(UsnRecord, u32)> {
    let end = off.checked_add(record_len as usize)?;
    if end > buf.len() {
        return None;
    }
    let slice = &buf[off..end];
    let file_ref = u64_le(slice, 0x08).ok()?;
    let parent_ref = u64_le(slice, 0x10).ok()?;
    let usn = u64_le(slice, 0x18).ok()? as i64;
    let ts = u64_le(slice, 0x20).ok()?;
    let reason = u32_le(slice, 0x28).ok()?;
    let source_info = u32_le(slice, 0x2C).ok()?;
    let security_id = u32_le(slice, 0x30).ok()?;
    let file_attributes = u32_le(slice, 0x34).ok()?;
    let name_len = u16_le(slice, 0x38).ok()? as usize;
    let name_off = u16_le(slice, 0x3A).ok()? as usize;
    if name_off < 0x3C || name_off + name_len > slice.len() || name_len % 2 != 0 {
        return None;
    }
    let mut units = Vec::with_capacity(name_len / 2);
    let mut i = name_off;
    while i + 1 < name_off + name_len {
        units.push(u16::from_le_bytes([slice[i], slice[i + 1]]));
        i += 2;
    }
    let name = String::from_utf16_lossy(&units);
    let (entry, sequence) = split_ref(file_ref);
    let (parent_entry, parent_sequence) = split_ref(parent_ref);
    Some((
        UsnRecord {
            usn,
            timestamp: FileTime::new(ts),
            entry,
            sequence,
            parent_entry,
            parent_sequence,
            reason,
            source_info,
            security_id: security_id as i64,
            file_attributes,
            name,
        },
        record_len,
    ))
}

// Parse a V3 record (128-bit file references). The two 16-byte references push
// every later field 16 bytes forward relative to V2.
fn parse_v3(buf: &[u8], off: usize, record_len: u32) -> Option<(UsnRecord, u32)> {
    let end = off.checked_add(record_len as usize)?;
    if end > buf.len() {
        return None;
    }
    let slice = &buf[off..end];
    // 0x08 FileReferenceNumber (16 bytes), 0x18 Parent (16 bytes).
    let file_ref = u64_le(slice, 0x08).ok()?;
    let parent_ref = u64_le(slice, 0x18).ok()?;
    let usn = u64_le(slice, 0x28).ok()? as i64;
    let ts = u64_le(slice, 0x30).ok()?;
    let reason = u32_le(slice, 0x38).ok()?;
    let source_info = u32_le(slice, 0x3C).ok()?;
    let security_id = u32_le(slice, 0x40).ok()?;
    let file_attributes = u32_le(slice, 0x44).ok()?;
    let name_len = u16_le(slice, 0x48).ok()? as usize;
    let name_off = u16_le(slice, 0x4A).ok()? as usize;
    if name_off < 0x4C || name_off + name_len > slice.len() || name_len % 2 != 0 {
        return None;
    }
    let mut units = Vec::with_capacity(name_len / 2);
    let mut i = name_off;
    while i + 1 < name_off + name_len {
        units.push(u16::from_le_bytes([slice[i], slice[i + 1]]));
        i += 2;
    }
    let name = String::from_utf16_lossy(&units);
    let (entry, sequence) = split_ref(file_ref);
    let (parent_entry, parent_sequence) = split_ref(parent_ref);
    Some((
        UsnRecord {
            usn,
            timestamp: FileTime::new(ts),
            entry,
            sequence,
            parent_entry,
            parent_sequence,
            reason,
            source_info,
            security_id: security_id as i64,
            file_attributes,
            name,
        },
        record_len,
    ))
}

// Scan a whole $UsnJrnl:$J stream. The stream is sparse, so leading and
// embedded zero regions are skipped; records resume on an 8-byte boundary.
pub fn for_each_record<F: FnMut(&UsnRecord) -> bool>(buf: &[u8], mut cb: F) -> UsnStats {
    let mut stats = UsnStats::default();
    let mut off = 0usize;
    while off + 4 <= buf.len() {
        let record_len = match u32_le(buf, off) {
            Ok(v) => v,
            Err(_) => break,
        };
        if record_len == 0 {
            // Sparse gap: jump to the next non-zero byte, aligned to 8.
            off += 8;
            while off + 4 <= buf.len() && u32_le(buf, off).unwrap_or(0) == 0 {
                off += 8;
            }
            continue;
        }
        if !(MIN_RECORD_LEN..=MAX_RECORD_LEN).contains(&record_len)
            || record_len % 8 != 0
            || off + record_len as usize > buf.len()
        {
            off += 8;
            stats.skipped += 1;
            continue;
        }
        let major = u16_le(buf, off + 4).unwrap_or(0);
        let parsed = match major {
            2 => parse_v2(buf, off, record_len),
            3 => parse_v3(buf, off, record_len),
            _ => None,
        };
        match parsed {
            Some((rec, len)) => {
                stats.records += 1;
                off += len as usize;
                if !cb(&rec) {
                    break;
                }
            }
            None => {
                off += 8;
                stats.skipped += 1;
            }
        }
    }
    stats
}

pub const REASON_FLAGS: &[(u32, &str)] = &[
    (0x0000_0001, "data overwrite"),
    (0x0000_0002, "data extend"),
    (0x0000_0004, "data truncation"),
    (0x0000_0010, "named data overwrite"),
    (0x0000_0020, "named data extend"),
    (0x0000_0040, "named data truncation"),
    (0x0000_0100, "file create"),
    (0x0000_0200, "file delete"),
    (0x0000_0400, "extended attribute change"),
    (0x0000_0800, "security change"),
    (0x0000_1000, "rename old name"),
    (0x0000_2000, "rename new name"),
    (0x0000_4000, "indexable change"),
    (0x0000_8000, "basic info change"),
    (0x0001_0000, "hard link change"),
    (0x0002_0000, "compression change"),
    (0x0004_0000, "encryption change"),
    (0x0008_0000, "object id change"),
    (0x0010_0000, "reparse point change"),
    (0x0020_0000, "stream change"),
    (0x0040_0000, "transacted change"),
    (0x0080_0000, "integrity change"),
    (0x8000_0000, "close"),
];

pub fn reason_labels(reason: u32) -> Vec<&'static str> {
    REASON_FLAGS
        .iter()
        .filter(|(bit, _)| reason & bit != 0)
        .map(|(_, name)| *name)
        .collect()
}

// A single word for grouping, picking the most meaningful reason present.
pub fn reason_summary(reason: u32) -> &'static str {
    if reason & 0x0000_0100 != 0 {
        "create"
    } else if reason & 0x0000_0200 != 0 {
        "delete"
    } else if reason & (0x0000_1000 | 0x0000_2000) != 0 {
        "rename"
    } else if reason & 0x0000_0800 != 0 {
        "security"
    } else if reason & (0x0000_0001 | 0x0000_0002 | 0x0000_0004) != 0 {
        "data"
    } else if reason & 0x0010_0000 != 0 {
        "reparse"
    } else if reason & 0x0000_8000 != 0 {
        "basic info"
    } else if reason == 0x8000_0000 {
        "close"
    } else {
        "other"
    }
}

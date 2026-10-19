use std::collections::HashSet;

use crate::util::bytes::{u16_le, u32_le};

// Access control flags of a security descriptor we care about.
const SE_DACL_PRESENT: u16 = 0x0004;

#[derive(Debug, Clone, Default)]
pub struct Descriptor {
    pub owner_sid: String,
    pub owner_name: String,
    pub group_sid: String,
    pub group_name: String,
    pub control: u16,
    pub ace_count: u32,
    pub allow_count: u32,
    pub deny_count: u32,
}

#[derive(Debug, Default, Clone, Copy)]
pub struct SecureStats {
    pub descriptors: u64,
    pub skipped: u64,
}

// Render a binary SID (self-relative) at `off` as its S-1-... string.
pub fn sid_to_string(buf: &[u8], off: usize) -> Option<String> {
    if off + 8 > buf.len() {
        return None;
    }
    let revision = buf[off];
    let sub_count = buf[off + 1] as usize;
    let mut authority: u64 = 0;
    for i in 0..6 {
        authority = (authority << 8) | buf[off + 2 + i] as u64;
    }
    let mut s = format!("S-{}-{}", revision, authority);
    let mut p = off + 8;
    for _ in 0..sub_count {
        if p + 4 > buf.len() {
            return None;
        }
        let sub = u32::from_le_bytes([buf[p], buf[p + 1], buf[p + 2], buf[p + 3]]);
        s.push('-');
        s.push_str(&sub.to_string());
        p += 4;
    }
    Some(s)
}

// Map a SID string to a human name where it is well known. Returns an empty
// string when nothing matches, so the caller falls back to the raw SID.
pub fn well_known_name(sid: &str) -> String {
    let fixed = match sid {
        "S-1-0-0" => "Nobody",
        "S-1-1-0" => "Everyone",
        "S-1-3-0" => "Creator Owner",
        "S-1-3-1" => "Creator Group",
        "S-1-5-7" => "Anonymous",
        "S-1-5-11" => "Authenticated Users",
        "S-1-5-18" => "SYSTEM",
        "S-1-5-19" => "Local Service",
        "S-1-5-20" => "Network Service",
        "S-1-5-32-544" => "Administrators",
        "S-1-5-32-545" => "Users",
        "S-1-5-32-546" => "Guests",
        "S-1-5-32-547" => "Power Users",
        "S-1-5-32-551" => "Backup Operators",
        "S-1-5-32-555" => "Remote Desktop Users",
        "S-1-5-32-559" => "Performance Log Users",
        _ => "",
    };
    if !fixed.is_empty() {
        return fixed.to_string();
    }
    // NT SERVICE\... accounts.
    if sid.starts_with("S-1-5-80-") {
        if sid == "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464" {
            return "TrustedInstaller".to_string();
        }
        return "NT Service".to_string();
    }
    // Account SIDs (S-1-5-21-<domain>-<rid>): read the trailing RID.
    if sid.starts_with("S-1-5-21-") {
        if let Some(rid) = sid.rsplit('-').next().and_then(|r| r.parse::<u32>().ok()) {
            let name = match rid {
                500 => "Administrator",
                501 => "Guest",
                502 => "krbtgt",
                512 => "Domain Admins",
                513 => "Domain Users",
                514 => "Domain Guests",
                515 => "Domain Computers",
                516 => "Domain Controllers",
                518 => "Schema Admins",
                519 => "Enterprise Admins",
                _ => "",
            };
            if !name.is_empty() {
                return name.to_string();
            }
            return format!("Account (RID {})", rid);
        }
    }
    String::new()
}

fn sid_at(sd: &[u8], offset: usize) -> (String, String) {
    if offset == 0 || offset >= sd.len() {
        return (String::new(), String::new());
    }
    match sid_to_string(sd, offset) {
        Some(s) => {
            let name = well_known_name(&s);
            (s, name)
        }
        None => (String::new(), String::new()),
    }
}

// Parse a self-relative SECURITY_DESCRIPTOR starting at the slice origin.
pub fn parse_descriptor(sd: &[u8]) -> Option<Descriptor> {
    if sd.len() < 20 || sd[0] != 1 {
        return None;
    }
    let control = u16_le(sd, 2).ok()?;
    let owner_off = u32_le(sd, 4).ok()? as usize;
    let group_off = u32_le(sd, 8).ok()? as usize;
    let dacl_off = u32_le(sd, 0x10).ok()? as usize;

    let (owner_sid, owner_name) = sid_at(sd, owner_off);
    let (group_sid, group_name) = sid_at(sd, group_off);

    let mut ace_count = 0u32;
    let mut allow_count = 0u32;
    let mut deny_count = 0u32;
    if control & SE_DACL_PRESENT != 0 && dacl_off != 0 && dacl_off + 8 <= sd.len() {
        let count = u16_le(sd, dacl_off + 4).unwrap_or(0) as u32;
        ace_count = count;
        let mut p = dacl_off + 8;
        for _ in 0..count {
            if p + 4 > sd.len() {
                break;
            }
            let ace_type = sd[p];
            let ace_size = u16_le(sd, p + 2).unwrap_or(0) as usize;
            if ace_size == 0 || p + ace_size > sd.len() {
                break;
            }
            match ace_type {
                0 => allow_count += 1,
                1 => deny_count += 1,
                _ => {}
            }
            p += ace_size;
        }
    }

    Some(Descriptor {
        owner_sid,
        owner_name,
        group_sid,
        group_name,
        control,
        ace_count,
        allow_count,
        deny_count,
    })
}

// Scan a $Secure:$SDS stream. Each entry is a 20-byte header (hash, security id,
// offset, length) followed by the self-relative descriptor, padded to 16 bytes.
// The stream holds a duplicate mirror copy, so security ids are de-duplicated.
pub fn for_each_entry<F: FnMut(u32, &Descriptor)>(sds: &[u8], mut cb: F) -> SecureStats {
    let mut stats = SecureStats::default();
    let mut seen: HashSet<u32> = HashSet::new();
    let mut off = 0usize;
    while off + 20 <= sds.len() {
        let security_id = u32_le(sds, off + 4).unwrap_or(0);
        let length = u32_le(sds, off + 0x10).unwrap_or(0) as usize;
        let _hash = u32_le(sds, off).unwrap_or(0);
        if length < 20 || off + length > sds.len() || security_id == 0 {
            // Padding or the gap before the next 256 KB mirror block.
            off += 16;
            continue;
        }
        let sd = &sds[off + 20..off + length];
        if let Some(desc) = parse_descriptor(sd) {
            if seen.insert(security_id) {
                cb(security_id, &desc);
                stats.descriptors += 1;
            }
        } else {
            stats.skipped += 1;
        }
        // Advance past this entry, aligned up to 16 bytes.
        let step = (length + 15) & !15;
        off += step.max(16);
    }
    stats
}

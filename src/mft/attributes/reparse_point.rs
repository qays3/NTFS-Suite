use crate::error::ParseError;
use crate::util::bytes::{u16_le, u32_le, utf16le_string};

pub const TAG_MOUNT_POINT: u32 = 0xA000_0003;
pub const TAG_SYMLINK: u32 = 0xA000_000C;

#[derive(Debug, Clone)]
pub struct ReparsePoint {
    pub tag: u32,
    pub target: String,
}

pub fn tag_name(tag: u32) -> &'static str {
    match tag {
        TAG_MOUNT_POINT => "junction",
        TAG_SYMLINK => "symbolic link",
        0x8000_0017 => "WIM image",
        0x8000_001B => "app execution alias",
        0x9000_001C => "cloud files",
        0xA000_001D => "OneDrive",
        0x8000_0014 => "HSM",
        0x8000_0006 => "SIS",
        _ => "reparse",
    }
}

impl ReparsePoint {
    pub fn parse(content: &[u8]) -> Result<ReparsePoint, ParseError> {
        if content.len() < 8 {
            return Err(ParseError::BadAttribute { offset: 0 });
        }
        let tag = u32_le(content, 0)?;
        let mut target = String::new();
        if tag == TAG_MOUNT_POINT || tag == TAG_SYMLINK {
            if content.len() >= 16 {
                let sub_off = u16_le(content, 8)? as usize;
                let sub_len = u16_le(content, 10)? as usize;
                let print_off = u16_le(content, 12)? as usize;
                let print_len = u16_le(content, 14)? as usize;
                let buffer_start = if tag == TAG_SYMLINK { 20 } else { 16 };
                let read = |off: usize, len: usize| -> Option<String> {
                    if len == 0 {
                        return None;
                    }
                    let start = buffer_start + off;
                    if start + len <= content.len() {
                        utf16le_string(content, start, len).ok()
                    } else {
                        None
                    }
                };
                target = read(print_off, print_len)
                    .or_else(|| read(sub_off, sub_len))
                    .unwrap_or_default();
            }
        }
        Ok(ReparsePoint { tag, target })
    }
}

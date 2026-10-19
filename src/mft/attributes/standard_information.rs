use crate::error::ParseError;
use crate::util::bytes::{u32_le, u64_le};
use crate::util::filetime::FileTime;

#[derive(Debug, Clone)]
pub struct StandardInformation {
    pub created: FileTime,
    pub modified: FileTime,
    pub mft_modified: FileTime,
    pub accessed: FileTime,
    pub flags: u32,
    pub owner_id: u32,
    pub security_id: u32,
    pub usn: u64,
}

impl StandardInformation {
    pub fn parse(content: &[u8]) -> Result<StandardInformation, ParseError> {
        if content.len() < 48 {
            return Err(ParseError::BadAttribute { offset: 0 });
        }
        let created = FileTime::new(u64_le(content, 0x00)?);
        let modified = FileTime::new(u64_le(content, 0x08)?);
        let mft_modified = FileTime::new(u64_le(content, 0x10)?);
        let accessed = FileTime::new(u64_le(content, 0x18)?);
        let flags = u32_le(content, 0x20)?;
        let owner_id = if content.len() >= 0x34 { u32_le(content, 0x30)? } else { 0 };
        let security_id = if content.len() >= 0x38 { u32_le(content, 0x34)? } else { 0 };
        let usn = if content.len() >= 0x48 { u64_le(content, 0x40)? } else { 0 };
        Ok(StandardInformation {
            created,
            modified,
            mft_modified,
            accessed,
            flags,
            owner_id,
            security_id,
            usn,
        })
    }
}

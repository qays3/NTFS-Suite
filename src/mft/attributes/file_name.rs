use crate::error::ParseError;
use crate::util::bytes::{u48_le, u64_le, utf16le_string, u16_le};
use crate::util::filetime::FileTime;

pub const NAMESPACE_POSIX: u8 = 0;
pub const NAMESPACE_WIN32: u8 = 1;
pub const NAMESPACE_DOS: u8 = 2;
pub const NAMESPACE_WIN32_DOS: u8 = 3;

#[derive(Debug, Clone)]
pub struct FileNameAttr {
    pub parent_entry: u64,
    pub parent_sequence: u16,
    pub created: FileTime,
    pub modified: FileTime,
    pub mft_modified: FileTime,
    pub accessed: FileTime,
    pub allocated_size: u64,
    pub real_size: u64,
    pub flags: u32,
    pub namespace: u8,
    pub name: String,
}

impl FileNameAttr {
    pub fn parse(content: &[u8]) -> Result<FileNameAttr, ParseError> {
        if content.len() < 66 {
            return Err(ParseError::BadAttribute { offset: 0 });
        }
        let parent_reference = u64_le(content, 0x00)?;
        let parent_entry = u48_le(content, 0x00)?;
        let parent_sequence = (parent_reference >> 48) as u16;
        let created = FileTime::new(u64_le(content, 0x08)?);
        let modified = FileTime::new(u64_le(content, 0x10)?);
        let mft_modified = FileTime::new(u64_le(content, 0x18)?);
        let accessed = FileTime::new(u64_le(content, 0x20)?);
        let allocated_size = u64_le(content, 0x28)?;
        let real_size = u64_le(content, 0x30)?;
        let flags = u16_le(content, 0x38)? as u32 | ((u16_le(content, 0x3A)? as u32) << 16);
        let name_length = content[0x40] as usize;
        let namespace = content[0x41];
        let name = utf16le_string(content, 0x42, name_length)?;
        Ok(FileNameAttr {
            parent_entry,
            parent_sequence,
            created,
            modified,
            mft_modified,
            accessed,
            allocated_size,
            real_size,
            flags,
            namespace,
            name,
        })
    }

    pub fn is_dos(&self) -> bool {
        self.namespace == NAMESPACE_DOS
    }
}

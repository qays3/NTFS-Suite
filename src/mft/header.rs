use crate::error::ParseError;
use crate::util::bytes::{u16_le, u32_le, u64_le};

pub const SIG_FILE: [u8; 4] = *b"FILE";
pub const SIG_BAAD: [u8; 4] = *b"BAAD";

pub const FLAG_IN_USE: u16 = 0x0001;
pub const FLAG_DIRECTORY: u16 = 0x0002;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Signature {
    File,
    Baad,
    Other([u8; 4]),
}

#[derive(Debug, Clone)]
pub struct RecordHeader {
    pub signature: Signature,
    pub fixup_offset: u16,
    pub fixup_count: u16,
    pub logfile_sequence_number: u64,
    pub sequence_number: u16,
    pub hard_link_count: u16,
    pub first_attribute_offset: u16,
    pub flags: u16,
    pub used_size: u32,
    pub allocated_size: u32,
    pub base_record_reference: u64,
    pub next_attribute_id: u16,
    pub record_number: u32,
}

impl RecordHeader {
    pub fn parse(buf: &[u8]) -> Result<RecordHeader, ParseError> {
        if buf.len() < 48 {
            return Err(ParseError::ShortRecord { len: buf.len() });
        }
        let sig_bytes = [buf[0], buf[1], buf[2], buf[3]];
        let signature = if sig_bytes == SIG_FILE {
            Signature::File
        } else if sig_bytes == SIG_BAAD {
            Signature::Baad
        } else {
            Signature::Other(sig_bytes)
        };
        Ok(RecordHeader {
            signature,
            fixup_offset: u16_le(buf, 0x04)?,
            fixup_count: u16_le(buf, 0x06)?,
            logfile_sequence_number: u64_le(buf, 0x08)?,
            sequence_number: u16_le(buf, 0x10)?,
            hard_link_count: u16_le(buf, 0x12)?,
            first_attribute_offset: u16_le(buf, 0x14)?,
            flags: u16_le(buf, 0x16)?,
            used_size: u32_le(buf, 0x18)?,
            allocated_size: u32_le(buf, 0x1C)?,
            base_record_reference: u64_le(buf, 0x20)?,
            next_attribute_id: u16_le(buf, 0x28)?,
            record_number: u32_le(buf, 0x2C)?,
        })
    }

    pub fn is_file(&self) -> bool {
        matches!(self.signature, Signature::File)
    }

    pub fn is_baad(&self) -> bool {
        matches!(self.signature, Signature::Baad)
    }

    pub fn in_use(&self) -> bool {
        self.flags & FLAG_IN_USE != 0
    }

    pub fn is_directory(&self) -> bool {
        self.flags & FLAG_DIRECTORY != 0
    }

    pub fn is_extension_record(&self) -> bool {
        base_entry(self.base_record_reference) != 0
    }
}

pub fn base_entry(reference: u64) -> u64 {
    reference & 0x0000_FFFF_FFFF_FFFF
}

pub fn reference_sequence(reference: u64) -> u16 {
    (reference >> 48) as u16
}

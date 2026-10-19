pub mod standard_information;
pub mod file_name;
pub mod data;
pub mod reparse_point;

use crate::error::ParseError;
use crate::util::bytes::{u16_le, u32_le, u64_le, utf16le_string};
use data::{DataAttr, DataContent};
use file_name::FileNameAttr;
use reparse_point::ReparsePoint;
use standard_information::StandardInformation;

pub const TYPE_STANDARD_INFORMATION: u32 = 0x10;
pub const TYPE_ATTRIBUTE_LIST: u32 = 0x20;
pub const TYPE_FILE_NAME: u32 = 0x30;
pub const TYPE_OBJECT_ID: u32 = 0x40;
pub const TYPE_DATA: u32 = 0x80;
pub const TYPE_INDEX_ROOT: u32 = 0x90;
pub const TYPE_INDEX_ALLOCATION: u32 = 0xA0;
pub const TYPE_REPARSE_POINT: u32 = 0xC0;
pub const TYPE_END: u32 = 0xFFFF_FFFF;

#[derive(Debug, Clone)]
pub struct AttributeHeader {
    pub type_id: u32,
    pub total_length: u32,
    pub non_resident: bool,
    pub name: Option<String>,
    pub attribute_id: u16,
}

#[derive(Debug, Clone)]
pub enum ParsedAttribute {
    StandardInformation(StandardInformation),
    FileName(FileNameAttr),
    Data(DataAttr),
    ReparsePoint(ReparsePoint),
    IndexRoot,
    IndexAllocation,
    AttributeList,
    Other(u32),
}

#[derive(Debug, Clone)]
pub struct Attribute {
    pub header: AttributeHeader,
    pub parsed: ParsedAttribute,
}

pub fn parse_attributes(record: &[u8], first_offset: usize) -> Result<Vec<Attribute>, ParseError> {
    let mut out = Vec::new();
    let mut off = first_offset;
    loop {
        if off + 4 > record.len() {
            break;
        }
        let type_id = u32_le(record, off)?;
        if type_id == TYPE_END {
            break;
        }
        if off + 16 > record.len() {
            break;
        }
        let total_length = u32_le(record, off + 4)? as usize;
        if total_length < 16 || off + total_length > record.len() {
            break;
        }
        let non_resident = record[off + 8] != 0;
        let name_length = record[off + 9] as usize;
        let name_offset = u16_le(record, off + 10)? as usize;
        let attribute_id = u16_le(record, off + 14)?;
        let name = if name_length > 0 {
            Some(utf16le_string(record, off + name_offset, name_length)?)
        } else {
            None
        };
        let header = AttributeHeader {
            type_id,
            total_length: total_length as u32,
            non_resident,
            name: name.clone(),
            attribute_id,
        };
        let parsed = parse_one(record, off, type_id, non_resident, name.clone())?;
        out.push(Attribute { header, parsed });
        off += total_length;
    }
    Ok(out)
}

fn parse_one(
    record: &[u8],
    off: usize,
    type_id: u32,
    non_resident: bool,
    name: Option<String>,
) -> Result<ParsedAttribute, ParseError> {
    match type_id {
        TYPE_STANDARD_INFORMATION => {
            let content = resident_content(record, off)?;
            Ok(ParsedAttribute::StandardInformation(StandardInformation::parse(content)?))
        }
        TYPE_FILE_NAME => {
            let content = resident_content(record, off)?;
            Ok(ParsedAttribute::FileName(FileNameAttr::parse(content)?))
        }
        TYPE_DATA => Ok(ParsedAttribute::Data(parse_data(record, off, non_resident, name)?)),
        TYPE_REPARSE_POINT => {
            let content = resident_content(record, off)?;
            Ok(ParsedAttribute::ReparsePoint(ReparsePoint::parse(content)?))
        }
        TYPE_INDEX_ROOT => Ok(ParsedAttribute::IndexRoot),
        TYPE_INDEX_ALLOCATION => Ok(ParsedAttribute::IndexAllocation),
        TYPE_ATTRIBUTE_LIST => Ok(ParsedAttribute::AttributeList),
        other => Ok(ParsedAttribute::Other(other)),
    }
}

fn resident_content(record: &[u8], off: usize) -> Result<&[u8], ParseError> {
    let content_length = u32_le(record, off + 0x10)? as usize;
    let content_offset = u16_le(record, off + 0x14)? as usize;
    let start = off + content_offset;
    let end = start + content_length;
    if end > record.len() {
        return Err(ParseError::OutOfBounds {
            off: start,
            len: content_length,
            total: record.len(),
        });
    }
    Ok(&record[start..end])
}

fn parse_data(
    record: &[u8],
    off: usize,
    non_resident: bool,
    name: Option<String>,
) -> Result<DataAttr, ParseError> {
    if non_resident {
        let allocated_size = u64_le(record, off + 0x28)?;
        let real_size = u64_le(record, off + 0x30)?;
        let initialized_size = u64_le(record, off + 0x38)?;
        let runs_offset = u16_le(record, off + 0x20)? as usize;
        let total_length = u32_le(record, off + 4)? as usize;
        let runs_start = off + runs_offset;
        let runs_end = off + total_length;
        let runs = if runs_start < runs_end && runs_end <= record.len() {
            crate::mft::data_runs::parse_data_runs(&record[runs_start..runs_end])?
        } else {
            Vec::new()
        };
        Ok(DataAttr {
            name,
            content: DataContent::NonResident {
                allocated_size,
                real_size,
                initialized_size,
                runs,
            },
        })
    } else {
        let content = resident_content(record, off)?;
        Ok(DataAttr {
            name,
            content: DataContent::Resident(content.to_vec()),
        })
    }
}

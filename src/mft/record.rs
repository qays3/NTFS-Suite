use crate::error::ParseError;
use crate::mft::attributes::file_name::{FileNameAttr, NAMESPACE_DOS};
use crate::mft::attributes::reparse_point::ReparsePoint;
use crate::mft::attributes::standard_information::StandardInformation;
use crate::mft::attributes::{parse_attributes, Attribute, ParsedAttribute};
use crate::mft::attributes::data::DataAttr;
use crate::mft::fixup::apply_fixup;
use crate::mft::header::{RecordHeader, Signature};

#[derive(Debug, Clone)]
pub struct MftRecord {
    pub header: RecordHeader,
    pub attributes: Vec<Attribute>,
    pub fixup_ok: bool,
}

impl MftRecord {
    pub fn parse(raw: &[u8]) -> Result<MftRecord, ParseError> {
        let header = RecordHeader::parse(raw)?;
        if let Signature::Other(found) = header.signature {
            return Err(ParseError::BadSignature { found });
        }
        let mut buf = raw.to_vec();
        let fixup_ok = apply_fixup(
            &mut buf,
            header.fixup_offset as usize,
            header.fixup_count as usize,
        )
        .is_ok();
        let attributes = if header.is_baad() {
            Vec::new()
        } else {
            parse_attributes(&buf, header.first_attribute_offset as usize).unwrap_or_default()
        };
        Ok(MftRecord { header, attributes, fixup_ok })
    }

    pub fn standard_information(&self) -> Option<&StandardInformation> {
        self.attributes.iter().find_map(|a| match &a.parsed {
            ParsedAttribute::StandardInformation(si) => Some(si),
            _ => None,
        })
    }

    pub fn file_names(&self) -> Vec<&FileNameAttr> {
        self.attributes
            .iter()
            .filter_map(|a| match &a.parsed {
                ParsedAttribute::FileName(fna) => Some(fna),
                _ => None,
            })
            .collect()
    }

    pub fn best_name(&self) -> Option<&FileNameAttr> {
        let names = self.file_names();
        names
            .iter()
            .find(|n| n.namespace != NAMESPACE_DOS)
            .copied()
            .or_else(|| names.first().copied())
    }

    pub fn data_streams(&self) -> Vec<&DataAttr> {
        self.attributes
            .iter()
            .filter_map(|a| match &a.parsed {
                ParsedAttribute::Data(d) => Some(d),
                _ => None,
            })
            .collect()
    }

    pub fn alternate_streams(&self) -> Vec<&DataAttr> {
        self.data_streams().into_iter().filter(|d| d.is_ads()).collect()
    }

    pub fn reparse_point(&self) -> Option<&ReparsePoint> {
        self.attributes.iter().find_map(|a| match &a.parsed {
            ParsedAttribute::ReparsePoint(rp) => Some(rp),
            _ => None,
        })
    }

    pub fn short_name(&self) -> Option<String> {
        self.file_names()
            .iter()
            .find(|n| n.namespace == NAMESPACE_DOS)
            .map(|n| n.name.clone())
    }

    pub fn data_size(&self) -> u64 {
        self.data_streams()
            .iter()
            .find(|d| d.name.is_none())
            .map(|d| d.size())
            .or_else(|| self.best_name().map(|f| f.real_size))
            .unwrap_or(0)
    }

    pub fn resident_has_mz(&self) -> bool {
        self.data_streams().iter().any(|d| match d.resident_bytes() {
            Some(bytes) => bytes.len() >= 2 && &bytes[0..2] == b"MZ",
            None => false,
        })
    }

    pub fn in_use(&self) -> bool {
        self.header.in_use()
    }

    pub fn is_directory(&self) -> bool {
        self.header.is_directory()
    }
}

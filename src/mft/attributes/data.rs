use crate::error::ParseError;
use crate::mft::data_runs::{parse_data_runs, DataRun};

#[derive(Debug, Clone)]
pub enum DataContent {
    Resident(Vec<u8>),
    NonResident {
        allocated_size: u64,
        real_size: u64,
        initialized_size: u64,
        runs: Vec<DataRun>,
    },
}

#[derive(Debug, Clone)]
pub struct DataAttr {
    pub name: Option<String>,
    pub content: DataContent,
}

impl DataAttr {
    pub fn is_ads(&self) -> bool {
        self.name.is_some()
    }

    pub fn size(&self) -> u64 {
        match &self.content {
            DataContent::Resident(bytes) => bytes.len() as u64,
            DataContent::NonResident { real_size, .. } => *real_size,
        }
    }

    pub fn resident_bytes(&self) -> Option<&[u8]> {
        match &self.content {
            DataContent::Resident(bytes) => Some(bytes),
            DataContent::NonResident { .. } => None,
        }
    }
}

pub fn parse_non_resident_runs(
    attribute: &[u8],
    runs_offset: usize,
) -> Result<Vec<DataRun>, ParseError> {
    if runs_offset >= attribute.len() {
        return Err(ParseError::OutOfBounds {
            off: runs_offset,
            len: 1,
            total: attribute.len(),
        });
    }
    parse_data_runs(&attribute[runs_offset..])
}

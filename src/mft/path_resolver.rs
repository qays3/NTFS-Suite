use std::collections::HashMap;

use crate::mft::record::MftRecord;

pub const ROOT_ENTRY: u64 = 5;

#[derive(Debug, Clone)]
pub struct ResolvedEntry {
    pub entry: u64,
    pub sequence: u16,
    pub name: String,
    pub parent_entry: u64,
    pub parent_sequence: u16,
    pub path: String,
    pub orphan: bool,
    pub in_use: bool,
    pub is_directory: bool,
}

pub struct PathResolver {
    entries: HashMap<u64, EntryInfo>,
}

struct EntryInfo {
    sequence: u16,
    name: String,
    parent_entry: u64,
    parent_sequence: u16,
    in_use: bool,
    is_directory: bool,
}

#[derive(Debug, Clone)]
pub struct EntrySummary {
    pub entry: u64,
    pub sequence: u16,
    pub name: String,
    pub parent_entry: u64,
    pub parent_sequence: u16,
    pub in_use: bool,
    pub is_directory: bool,
}

impl PathResolver {
    pub fn new() -> PathResolver {
        PathResolver { entries: HashMap::new() }
    }

    pub fn insert_summary(&mut self, summary: EntrySummary) {
        self.entries.insert(
            summary.entry,
            EntryInfo {
                sequence: summary.sequence,
                name: summary.name,
                parent_entry: summary.parent_entry,
                parent_sequence: summary.parent_sequence,
                in_use: summary.in_use,
                is_directory: summary.is_directory,
            },
        );
    }

    pub fn summarize(number: u64, record: &MftRecord) -> EntrySummary {
        let (name, parent_entry, parent_sequence) = match record.best_name() {
            Some(fna) => (fna.name.clone(), fna.parent_entry, fna.parent_sequence),
            None => (String::new(), 0, 0),
        };
        EntrySummary {
            entry: number,
            sequence: record.header.sequence_number,
            name,
            parent_entry,
            parent_sequence,
            in_use: record.in_use(),
            is_directory: record.is_directory(),
        }
    }

    pub fn build(records: &HashMap<u64, MftRecord>) -> PathResolver {
        let mut resolver = PathResolver::new();
        for (number, record) in records.iter() {
            resolver.insert_summary(PathResolver::summarize(*number, record));
        }
        resolver
    }

    pub fn resolve(&self, entry: u64) -> Option<ResolvedEntry> {
        let info = self.entries.get(&entry)?;
        let (path, orphan) = self.build_path(entry, info);
        Some(ResolvedEntry {
            entry,
            sequence: info.sequence,
            name: info.name.clone(),
            parent_entry: info.parent_entry,
            parent_sequence: info.parent_sequence,
            path,
            orphan,
            in_use: info.in_use,
            is_directory: info.is_directory,
        })
    }

    fn build_path(&self, entry: u64, info: &EntryInfo) -> (String, bool) {
        if entry == ROOT_ENTRY {
            return (String::from("\\"), false);
        }
        let mut parts: Vec<String> = Vec::new();
        parts.push(info.name.clone());
        let mut current_parent = info.parent_entry;
        let mut current_parent_seq = info.parent_sequence;
        let mut orphan = false;
        let mut guard = 0;
        loop {
            guard += 1;
            if guard > 4096 {
                orphan = true;
                break;
            }
            if current_parent == ROOT_ENTRY {
                break;
            }
            let parent = match self.entries.get(&current_parent) {
                Some(p) => p,
                None => {
                    orphan = true;
                    break;
                }
            };
            if parent.sequence != current_parent_seq {
                orphan = true;
                break;
            }
            parts.push(parent.name.clone());
            current_parent = parent.parent_entry;
            current_parent_seq = parent.parent_sequence;
        }
        parts.reverse();
        let joined = parts.join("\\");
        let path = if orphan {
            format!("?\\{}", joined)
        } else {
            format!("\\{}", joined)
        };
        (path, orphan)
    }
}

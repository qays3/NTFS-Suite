use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

#[derive(Deserialize)]
pub struct BrowseRequest {
    #[serde(default)]
    pub path: String,
}

#[derive(Serialize)]
pub struct BrowseEntry {
    pub name: String,
    pub path: String,
    pub is_dir: bool,
    pub size: i64,
}

#[derive(Serialize)]
pub struct BrowseResponse {
    pub path: String,
    pub parent: Option<String>,
    pub roots: Vec<String>,
    pub entries: Vec<BrowseEntry>,
}

pub fn browse(request: &BrowseRequest) -> BrowseResponse {
    let roots = list_roots();
    if request.path.is_empty() {
        let home = home_dir();
        return listing(&home, roots);
    }
    let path = PathBuf::from(&request.path);
    if path.is_dir() {
        listing(&path, roots)
    } else {
        let fallback = home_dir();
        listing(&fallback, roots)
    }
}

fn listing(dir: &Path, roots: Vec<String>) -> BrowseResponse {
    let mut entries = Vec::new();
    if let Ok(read) = std::fs::read_dir(dir) {
        for item in read.flatten() {
            let meta = item.metadata();
            let is_dir = meta.as_ref().map(|m| m.is_dir()).unwrap_or(false);
            let size = meta.as_ref().map(|m| m.len() as i64).unwrap_or(0);
            let name = item.file_name().to_string_lossy().to_string();
            if name.starts_with('.') {
                continue;
            }
            entries.push(BrowseEntry {
                name,
                path: item.path().to_string_lossy().to_string(),
                is_dir,
                size,
            });
        }
    }
    entries.sort_by(|a, b| match (a.is_dir, b.is_dir) {
        (true, false) => std::cmp::Ordering::Less,
        (false, true) => std::cmp::Ordering::Greater,
        _ => a.name.to_lowercase().cmp(&b.name.to_lowercase()),
    });
    BrowseResponse {
        path: dir.to_string_lossy().to_string(),
        parent: dir.parent().map(|p| p.to_string_lossy().to_string()),
        roots,
        entries,
    }
}

fn home_dir() -> PathBuf {
    if let Ok(p) = std::env::var("USERPROFILE") {
        return PathBuf::from(p);
    }
    if let Ok(p) = std::env::var("HOME") {
        return PathBuf::from(p);
    }
    PathBuf::from("/")
}

#[cfg(target_os = "windows")]
fn list_roots() -> Vec<String> {
    let mut roots = Vec::new();
    for letter in b'A'..=b'Z' {
        let drive = format!("{}:\\", letter as char);
        if Path::new(&drive).exists() {
            roots.push(drive);
        }
    }
    roots
}

#[cfg(not(target_os = "windows"))]
fn list_roots() -> Vec<String> {
    vec![String::from("/")]
}

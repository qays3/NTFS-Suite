use std::path::{Path, PathBuf};

use crate::settings::model::Settings;

pub struct SettingsPaths {
    pub base_dir: PathBuf,
    pub settings_path: PathBuf,
    pub default_cases_dir: PathBuf,
}

pub fn resolve_paths() -> SettingsPaths {
    let base_dir = exe_dir();
    let settings_path = base_dir.join("settings.json");
    let default_cases_dir = base_dir.join("cases");
    SettingsPaths { base_dir, settings_path, default_cases_dir }
}

pub fn load(path: &Path) -> Option<Settings> {
    let text = std::fs::read_to_string(path).ok()?;
    serde_json::from_str(&text).ok()
}

pub fn save(path: &Path, settings: &Settings) -> std::io::Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let text = serde_json::to_string_pretty(settings)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;
    std::fs::write(path, text)
}

pub fn is_writable(dir: &Path) -> bool {
    if std::fs::create_dir_all(dir).is_err() {
        return false;
    }
    let probe = dir.join(".ntfssuite-write-test");
    match std::fs::write(&probe, b"ok") {
        Ok(_) => {
            std::fs::remove_file(&probe).ok();
            true
        }
        Err(_) => false,
    }
}

fn exe_dir() -> PathBuf {
    std::env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(|d| d.to_path_buf()))
        .unwrap_or_else(|| PathBuf::from("."))
}

use std::path::PathBuf;
use std::sync::Mutex;

use crate::plugins::registry::PluginRegistry;
use crate::server::jobs::JobRegistry;
use crate::settings::{Settings, SettingsPaths};
use crate::vault::Vault;

pub const APP_NAME: &str = "NTFS Suite";
pub const APP_VERSION: &str = env!("CARGO_PKG_VERSION");

pub struct OpenCase {
    pub path: PathBuf,
    pub vault: Vault,
}

pub struct Inner {
    pub settings: Settings,
    pub open_case: Option<OpenCase>,
}

pub struct AppState {
    pub port: u16,
    pub registry: PluginRegistry,
    pub jobs: JobRegistry,
    pub paths: SettingsPaths,
    pub inner: Mutex<Inner>,
}

impl AppState {
    pub fn new(port: u16, paths: SettingsPaths, settings: Settings) -> AppState {
        AppState {
            port,
            registry: PluginRegistry::with_builtins(),
            jobs: JobRegistry::new(),
            paths,
            inner: Mutex::new(Inner { settings, open_case: None }),
        }
    }

    pub fn open_case_path(&self) -> Option<std::path::PathBuf> {
        self.inner.lock().unwrap().open_case.as_ref().map(|c| c.path.clone())
    }
}

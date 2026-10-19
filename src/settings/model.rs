use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Settings {
    pub setup_complete: bool,
    pub storage_mode: String,
    pub cases_dir: String,
    pub analyst: String,
    pub organization: String,
    pub default_timezone: String,
    pub downgrade_cloud_sync: bool,
    pub encrypt_new_vaults: bool,
    pub auto_shutdown_seconds: u64,
    pub theme: String,
}

impl Settings {
    pub fn defaults(cases_dir: String) -> Settings {
        Settings {
            setup_complete: false,
            storage_mode: String::from("portable"),
            cases_dir,
            analyst: String::new(),
            organization: String::new(),
            default_timezone: String::from("UTC"),
            downgrade_cloud_sync: true,
            encrypt_new_vaults: false,
            auto_shutdown_seconds: 900,
            theme: String::from("dark"),
        }
    }
}

mod common;

use std::io::Write;

use common::RecordBuilder;
use ntfs_suite::mft::header::{FLAG_DIRECTORY, FLAG_IN_USE};
use ntfs_suite::plugins::artifact_plugin::{ArtifactPlugin, IngestCtx};
use ntfs_suite::plugins::mft::MftPlugin;
use ntfs_suite::plugins::registry::PluginRegistry;
use ntfs_suite::vault::{evidence_store, record_store};
use ntfs_suite::Vault;

fn t() -> u64 {
    132_223_104_000_000_000
}

fn synthetic_mft() -> Vec<u8> {
    let mut data = Vec::new();
    data.extend_from_slice(
        &RecordBuilder::new(5, 5, FLAG_IN_USE | FLAG_DIRECTORY)
            .add_standard_information(t(), t(), t(), t(), 0x10)
            .add_file_name(5, 5, t(), t(), t(), t(), 0, 1, ".")
            .build(),
    );
    data.extend_from_slice(
        &RecordBuilder::new(40, 1, FLAG_IN_USE | FLAG_DIRECTORY)
            .add_standard_information(t(), t(), t(), t(), 0x10)
            .add_file_name(5, 5, t(), t(), t(), t(), 0, 1, "Users")
            .build(),
    );
    data.extend_from_slice(
        &RecordBuilder::new(60, 1, FLAG_IN_USE)
            .add_standard_information(t(), t(), t(), t(), 0x20)
            .add_file_name(40, 1, t(), t(), t(), t(), 100, 1, "evil.exe")
            .add_resident_data(Some("Zone.Identifier"), b"[ZoneTransfer]\r\nZoneId=3\r\n")
            .build(),
    );
    data
}

fn temp_path(tag: &str) -> std::path::PathBuf {
    let mut p = std::env::temp_dir();
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    p.push(format!("ntfssuite-{}-{}.mft", tag, nanos));
    p
}

#[test]
fn registry_identifies_mft() {
    let registry = PluginRegistry::with_builtins();
    assert_eq!(registry.ids(), vec!["mft", "usnjrnl", "secure"]);
    let plugin = registry.identify(b"FILE0\x00\x00\x00").unwrap();
    assert_eq!(plugin.id(), "mft");
    assert!(registry.identify(b"NOPE").is_none());
}

#[test]
fn ingests_synthetic_mft_into_vault() {
    let path = temp_path("ingest");
    {
        let mut f = std::fs::File::create(&path).unwrap();
        f.write_all(&synthetic_mft()).unwrap();
    }
    let mut vault = Vault::open_in_memory().unwrap();
    let id = evidence_store::add(&vault.conn, "$MFT", path.to_str().unwrap(), 3072, "h", "mft").unwrap();
    let ctx = IngestCtx::new(3);
    let stats = MftPlugin.ingest(&path, &mut vault, id, &ctx).unwrap();
    assert_eq!(stats.records, 3);
    assert_eq!(stats.with_ads, 1);
    assert_eq!(stats.in_use, 3);
    assert_eq!(record_store::count(&vault.conn, id).unwrap(), 3);

    let page = record_store::page(&vault.conn, id, 0, 100).unwrap();
    let evil = page.iter().find(|r| r.name == "evil.exe").unwrap();
    assert_eq!(evil.path, "\\Users\\evil.exe");
    assert!(evil.has_ads);
    assert!(!evil.orphan);

    // The plugin stores records; the ingest orchestration marks the evidence
    // parsed (same call run_ingest makes for every plugin).
    evidence_store::mark_parsed(&vault.conn, id).unwrap();
    let listed = evidence_store::list(&vault.conn).unwrap();
    assert_eq!(listed[0].status, "parsed");

    std::fs::remove_file(&path).ok();
}

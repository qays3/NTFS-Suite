pub const SCHEMA_VERSION: i64 = 1;

pub const SCHEMA_V1: &str = "
CREATE TABLE IF NOT EXISTS meta (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS case_info (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    name TEXT NOT NULL,
    number TEXT NOT NULL DEFAULT '',
    analyst TEXT NOT NULL DEFAULT '',
    notes TEXT NOT NULL DEFAULT '',
    created_utc TEXT NOT NULL,
    display_timezone TEXT NOT NULL DEFAULT 'UTC'
);

CREATE TABLE IF NOT EXISTS evidence (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    source_path TEXT NOT NULL,
    size INTEGER NOT NULL,
    sha256 TEXT NOT NULL,
    plugin TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'added',
    added_utc TEXT NOT NULL,
    parsed_utc TEXT
);

CREATE TABLE IF NOT EXISTS records (
    evidence_id INTEGER NOT NULL,
    entry INTEGER NOT NULL,
    sequence INTEGER NOT NULL,
    in_use INTEGER NOT NULL,
    is_directory INTEGER NOT NULL,
    has_ads INTEGER NOT NULL,
    orphan INTEGER NOT NULL,
    parent_entry INTEGER NOT NULL,
    si_created TEXT NOT NULL,
    si_modified TEXT NOT NULL,
    si_mft_modified TEXT NOT NULL,
    si_accessed TEXT NOT NULL,
    fn_created TEXT NOT NULL,
    name TEXT NOT NULL,
    path TEXT NOT NULL,
    PRIMARY KEY (evidence_id, entry)
);

CREATE INDEX IF NOT EXISTS idx_records_name ON records (name);
CREATE INDEX IF NOT EXISTS idx_records_parent ON records (evidence_id, parent_entry);

CREATE TABLE IF NOT EXISTS events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    evidence_id INTEGER NOT NULL,
    plugin TEXT NOT NULL,
    entry INTEGER NOT NULL,
    time_utc TEXT NOT NULL,
    macb TEXT NOT NULL,
    source TEXT NOT NULL,
    name TEXT NOT NULL,
    path TEXT NOT NULL,
    deleted INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_events_time ON events (time_utc);

CREATE TABLE IF NOT EXISTS findings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    evidence_id INTEGER NOT NULL,
    rule_id TEXT NOT NULL,
    title TEXT NOT NULL,
    severity TEXT NOT NULL,
    score INTEGER NOT NULL,
    mitre TEXT NOT NULL DEFAULT '',
    entry INTEGER NOT NULL,
    path TEXT NOT NULL,
    reason TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'new',
    notes TEXT NOT NULL DEFAULT '',
    created_utc TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS audit (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    time_utc TEXT NOT NULL,
    actor TEXT NOT NULL,
    action TEXT NOT NULL,
    detail TEXT NOT NULL DEFAULT ''
);
";

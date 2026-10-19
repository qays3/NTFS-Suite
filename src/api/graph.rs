use std::sync::Arc;

use axum::extract::State;
use axum::http::StatusCode;
use axum::Json;
use rusqlite::Connection;
use serde::{Deserialize, Serialize};

use crate::server::state::AppState;
use crate::vault::{finding_store, record_store, Vault};

#[derive(Serialize)]
pub struct Node {
    pub id: String,
    pub kind: String,
    pub label: String,
    pub sub: String,
}

#[derive(Serialize)]
pub struct Edge {
    pub from: String,
    pub to: String,
    pub rel: String,
}

#[derive(Serialize, Default)]
pub struct GraphReply {
    pub nodes: Vec<Node>,
    pub edges: Vec<Edge>,
}

#[derive(Deserialize)]
pub struct RootsQuery {
    pub evidence_id: i64,
}

pub async fn roots(
    State(state): State<Arc<AppState>>,
    Json(req): Json<RootsQuery>,
) -> Result<Json<Vec<Node>>, StatusCode> {
    let inner = state.inner.lock().unwrap();
    let case = inner.open_case.as_ref().ok_or(StatusCode::BAD_REQUEST)?;
    let ranked = finding_store::ranked_files(&case.vault.conn, req.evidence_id, 40)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let nodes = ranked
        .into_iter()
        .map(|r| {
            NodeOwned {
                id: format!("file:{}", r.entry),
                kind: "file",
                label: if r.name.is_empty() { r.path } else { r.name },
                sub: format!("{} findings, score {}", r.finding_count, r.total_score),
            }
            .into()
        })
        .collect();
    Ok(Json(nodes))
}

struct NodeOwned {
    id: String,
    kind: &'static str,
    label: String,
    sub: String,
}

impl NodeOwned {
    fn into(self) -> Node {
        Node {
            id: self.id,
            kind: self.kind.to_string(),
            label: self.label,
            sub: self.sub,
        }
    }
}

#[derive(Serialize)]
pub struct MetaFile {
    pub entry: i64,
    pub name: String,
    pub role: String,
    pub present: bool,
    pub deleted: bool,
    pub is_directory: bool,
    pub si_created: String,
    pub records: i64,
}

#[derive(Serialize, Default)]
pub struct Anatomy {
    pub metafiles: Vec<MetaFile>,
    pub extend: Vec<MetaFile>,
}

const SYSTEM_FILES: &[(i64, &str, &str)] = &[
    (0, "$MFT", "The Master File Table. Every file and folder has at least one record here, usually 1024 bytes, holding its name, its four Standard Information and four File Name timestamps, its size, flags and where its data lives. The whole tool is built from parsing these records."),
    (1, "$MFTMirr", "A mirror of the first few $MFT records. If the start of the $MFT is corrupt the file system rebuilds from this backup, so the volume still mounts."),
    (2, "$LogFile", "A circular transaction log. NTFS writes an intended metadata change here before making it, then replays or rolls it back after a crash to keep the file system consistent. Rich forensic source, parsed by a later plugin."),
    (3, "$Volume", "Holds the volume label, the NTFS version, and the dirty flag that tells Windows to run chkdsk after an unclean shutdown."),
    (4, "$AttrDef", "The table that defines every attribute type a record can carry, such as $STANDARD_INFORMATION (0x10), $FILE_NAME (0x30) and $DATA (0x80), with their names and size limits."),
    (5, ".", "The root directory of the volume, the top of the folder tree that every path begins from. Its own record number is 5."),
    (6, "$Bitmap", "One bit per cluster marking free or in use. This is how NTFS chooses where to place new data and how much free space remains."),
    (7, "$Boot", "The boot sector at the very start of the volume. It holds the BIOS parameter block (sector and cluster sizes, the $MFT location) and the boot loader."),
    (8, "$BadClus", "A map of clusters the disk has reported bad, so NTFS never stores file data on them."),
    (9, "$Secure", "A central store of security descriptors, the owners and permissions. Files point to an entry here instead of each carrying its own copy, which saves space."),
    (10, "$UpCase", "A 128 KB uppercase conversion table used to compare file names without case, so that README and readme are treated as the same name."),
    (11, "$Extend", "A directory that holds the optional NTFS features, each as its own metadata file, including the change journal, disk quotas and reparse point index."),
];

const EXTEND_FILES: &[(&str, &str)] = &[
    ("$ObjId", "Object identifiers that distributed link tracking uses to follow a file even after it is renamed or moved to another folder or volume."),
    ("$Quota", "Per user disk quota records that track and can limit how much space each account uses on the volume."),
    ("$Reparse", "An index of the reparse points on the volume, such as junctions, mount points and symbolic links, so they can be enumerated quickly."),
    ("$UsnJrnl", "The Update Sequence Number change journal. It records every change to every file, create, delete, rename and data change, and is one of the most useful forensic timelines. Parsed by a later plugin."),
    ("$RmMetadata", "Resource manager metadata for Transactional NTFS, including its own transaction log and tables used to commit or roll back grouped file changes."),
];

#[derive(Deserialize)]
pub struct AnatomyQuery {
    pub evidence_id: i64,
}

pub async fn anatomy(
    State(state): State<Arc<AppState>>,
    Json(req): Json<AnatomyQuery>,
) -> Result<Json<Anatomy>, StatusCode> {
    let inner = state.inner.lock().unwrap();
    let case = inner.open_case.as_ref().ok_or(StatusCode::BAD_REQUEST)?;
    let conn = &case.vault.conn;
    let eid = req.evidence_id;
    let mut out = Anatomy::default();

    let total = record_store::count(conn, eid).unwrap_or(0);
    for (entry, name, role) in SYSTEM_FILES {
        let rec = record_store::get(conn, eid, *entry).ok().flatten();
        out.metafiles.push(meta_from(conn, eid, *entry, name, role, rec.as_ref(), total));
    }

    let children = record_store::children(conn, eid, 11, 64).unwrap_or_default();
    for (name, role) in EXTEND_FILES {
        let found = children.iter().find(|c| c.name.eq_ignore_ascii_case(name));
        let records = match found {
            Some(c) if c.is_directory => record_store::count_children(conn, eid, c.entry).unwrap_or(0),
            Some(_) => 1,
            None => 0,
        };
        out.extend.push(MetaFile {
            entry: found.map(|c| c.entry).unwrap_or(-1),
            name: name.to_string(),
            role: role.to_string(),
            present: found.is_some(),
            deleted: found.map(|c| !c.in_use).unwrap_or(false),
            is_directory: found.map(|c| c.is_directory).unwrap_or(false),
            si_created: found.map(|c| c.si_created.clone()).unwrap_or_default(),
            records,
        });
    }
    Ok(Json(out))
}

fn meta_from(
    conn: &Connection,
    eid: i64,
    entry: i64,
    name: &str,
    role: &str,
    rec: Option<&record_store::StoredRecord>,
    total: i64,
) -> MetaFile {
    let records = if entry == 0 {
        total
    } else {
        match rec {
            Some(r) if r.is_directory => record_store::count_children(conn, eid, entry).unwrap_or(0),
            Some(_) => 1,
            None => 0,
        }
    };
    MetaFile {
        entry,
        name: name.to_string(),
        role: role.to_string(),
        present: rec.is_some(),
        deleted: rec.map(|r| !r.in_use).unwrap_or(false),
        is_directory: rec.map(|r| r.is_directory).unwrap_or(false),
        si_created: rec.map(|r| r.si_created.clone()).unwrap_or_default(),
        records,
    }
}

#[derive(Deserialize)]
pub struct NeighborsQuery {
    pub evidence_id: i64,
    pub id: String,
}

pub async fn neighbors(
    State(state): State<Arc<AppState>>,
    Json(req): Json<NeighborsQuery>,
) -> Result<Json<GraphReply>, StatusCode> {
    let inner = state.inner.lock().unwrap();
    let case = inner.open_case.as_ref().ok_or(StatusCode::BAD_REQUEST)?;
    let conn = &case.vault.conn;
    let eid = req.evidence_id;

    let (kind, value) = req.id.split_once(':').ok_or(StatusCode::BAD_REQUEST)?;
    let entry: i64 = value.parse().map_err(|_| StatusCode::BAD_REQUEST)?;

    let reply = match kind {
        "file" => file_neighbors(conn, eid, entry).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?,
        "folder" => folder_neighbors(conn, eid, entry).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?,
        _ => GraphReply::default(),
    };
    Ok(Json(reply))
}

fn file_node(record: &record_store::StoredRecord) -> NodeOwned {
    NodeOwned {
        id: format!("file:{}", record.entry),
        kind: if record.is_directory { "folder" } else { "file" },
        label: record.name.clone(),
        sub: format!("entry {}{}", record.entry, if record.in_use { "" } else { ", deleted" }),
    }
}

fn file_neighbors(conn: &Connection, eid: i64, entry: i64) -> Result<GraphReply, rusqlite::Error> {
    let mut reply = GraphReply::default();
    let record = match record_store::get(conn, eid, entry).ok().flatten() {
        Some(r) => r,
        None => return Ok(reply),
    };
    let self_id = format!("file:{}", record.entry);
    reply.nodes.push(file_node(&record).into());

    if let Some(parent) = record_store::get(conn, eid, record.parent_entry).ok().flatten() {
        let folder_id = format!("folder:{}", parent.entry);
        reply.nodes.push(NodeOwned {
            id: folder_id.clone(),
            kind: "folder",
            label: parent.name.clone(),
            sub: String::from("folder"),
        }.into());
        reply.edges.push(Edge { from: folder_id, to: self_id.clone(), rel: String::from("contains") });
    }

    if record.has_ads {
        let ads_id = format!("ads:{}", record.entry);
        reply.nodes.push(NodeOwned {
            id: ads_id.clone(),
            kind: "ads",
            label: format!("{} stream", record.name),
            sub: String::from("alternate data stream"),
        }.into());
        reply.edges.push(Edge { from: self_id.clone(), to: ads_id, rel: String::from("has stream") });
    }

    let rules = finding_store::rules_for_entry(conn, eid, record.entry).unwrap_or_default();
    for rule in rules {
        let fid = format!("finding:{}:{}", record.entry, rule.rule_id);
        reply.nodes.push(NodeOwned {
            id: fid.clone(),
            kind: "finding",
            label: rule.rule_id.clone(),
            sub: rule.title.clone(),
        }.into());
        reply.edges.push(Edge { from: fid, to: self_id.clone(), rel: String::from("flags") });
    }

    let siblings = record_store::children(conn, eid, record.parent_entry, 12).unwrap_or_default();
    let folder_id = format!("folder:{}", record.parent_entry);
    for sib in siblings {
        if sib.entry == record.entry {
            continue;
        }
        let sid = format!("file:{}", sib.entry);
        reply.nodes.push(file_node(&sib).into());
        reply.edges.push(Edge { from: folder_id.clone(), to: sid, rel: String::from("contains") });
    }

    Ok(reply)
}

// ---------------------------------------------------------------------------
// Ownership (owner id / security id from $STANDARD_INFORMATION)
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
pub struct OwnershipQuery {
    pub evidence_id: i64,
}

#[derive(Serialize)]
pub struct OwnerBucket {
    pub id: i64,
    pub count: i64,
    pub examples: Vec<String>,
    pub name: String,
    pub sid: String,
}

#[derive(Serialize)]
pub struct OwnershipCheck {
    pub label: String,
    pub detail: String,
    pub level: String,
}

#[derive(Serialize, Default)]
pub struct OwnershipReply {
    pub owners: Vec<OwnerBucket>,
    pub securities: Vec<OwnerBucket>,
    pub total: i64,
    pub with_owner: i64,
    pub distinct_owners: i64,
    pub distinct_securities: i64,
    pub checks: Vec<OwnershipCheck>,
    pub note: String,
    pub secure_present: bool,
    pub secure_count: i64,
}

pub async fn ownership(
    State(state): State<Arc<AppState>>,
    Json(req): Json<OwnershipQuery>,
) -> Result<Json<OwnershipReply>, StatusCode> {
    let case_path = state.open_case_path().ok_or(StatusCode::BAD_REQUEST)?;
    let eid = req.evidence_id;
    let reply = tokio::task::spawn_blocking(move || {
        let vault = Vault::open(&case_path).map_err(|_| ())?;
        Ok::<OwnershipReply, ()>(ownership_query(&vault.conn, eid))
    })
    .await
    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(Json(reply))
}

fn ownership_query(conn: &Connection, eid: i64) -> OwnershipReply {
    let mut reply = OwnershipReply::default();

    // One grouped scan per column gives the buckets and every total we need.
    let owner_groups = bucket(conn, eid, "owner_id").unwrap_or_default();
    let security_groups = bucket(conn, eid, "security_id").unwrap_or_default();

    reply.total = owner_groups.iter().map(|b| b.count).sum();
    reply.with_owner = owner_groups.iter().filter(|b| b.id != 0).map(|b| b.count).sum();
    reply.distinct_owners = owner_groups.iter().filter(|b| b.id != 0).count() as i64;
    reply.distinct_securities = security_groups.iter().filter(|b| b.id != 0).count() as i64;

    reply.owners = owner_groups.into_iter().take(12).collect();
    for b in reply.owners.iter_mut() {
        b.examples = owner_examples(conn, eid, "owner_id", b.id, 3).unwrap_or_default();
    }
    reply.securities = security_groups.into_iter().take(20).collect();

    // Resolve security ids to owner names when a $Secure has been added.
    let descriptors = crate::vault::security_store::all(conn).unwrap_or_default();
    reply.secure_count = descriptors.len() as i64;
    reply.secure_present = reply.secure_count > 0;
    if reply.secure_present {
        let map: std::collections::HashMap<i64, (String, String)> = descriptors
            .into_iter()
            .map(|d| {
                let label = if d.owner_name.is_empty() { d.owner_sid.clone() } else { d.owner_name.clone() };
                (d.security_id, (label, d.owner_sid))
            })
            .collect();
        for b in reply.securities.iter_mut() {
            if let Some((label, sid)) = map.get(&b.id) {
                b.name = label.clone();
                b.sid = sid.clone();
            }
        }
    }

    // Checks that only use what we actually captured.
    let pct = if reply.total > 0 {
        (reply.with_owner as f64 / reply.total as f64 * 100.0).round() as i64
    } else {
        0
    };
    reply.checks.push(OwnershipCheck {
        label: "Quota owner id coverage".to_string(),
        detail: format!(
            "{} of {} records carry a non-zero owner id ({}%). The $SI owner id is the disk quota owner, an index into $Quota, and is 0 on volumes with quotas turned off, which is the common case. A 0% reading here is expected, not a gap. Real file ownership comes from the security id below.",
            reply.with_owner, reply.total, pct
        ),
        level: "info".to_string(),
    });
    reply.checks.push(OwnershipCheck {
        label: "Distinct principals".to_string(),
        detail: format!(
            "{} distinct owner ids and {} distinct security ids appear across this volume.",
            reply.distinct_owners, reply.distinct_securities
        ),
        level: "info".to_string(),
    });
    if let Some(top) = reply.owners.iter().find(|b| b.id != 0) {
        if reply.with_owner > 0 {
            let share = (top.count as f64 / reply.with_owner as f64 * 100.0).round() as i64;
            reply.checks.push(OwnershipCheck {
                label: "Dominant owner".to_string(),
                detail: format!(
                    "Owner id {} holds {} files, {}% of all owned records. A single id owning system and user files alike can indicate a mounted image or a copied profile.",
                    top.id, top.count, share
                ),
                level: "info".to_string(),
            });
        }
    }

    if reply.secure_present {
        reply.checks.push(OwnershipCheck {
            label: "Security names resolved".to_string(),
            detail: format!(
                "{} security descriptors were read from $Secure, so the owner behind each security id is shown by name.",
                reply.secure_count
            ),
            level: "info".to_string(),
        });
        reply.note = "Owner id is the $SI disk quota owner (an index into $Quota) and is 0 when quotas are off. Security id indexes into $Secure. $Secure has been parsed, so each security id resolves to its owner SID and name below.".to_string();
    } else {
        reply.note = "Owner id is the $SI disk quota owner (an index into $Quota) and is 0 when quotas are off. Security id indexes into $Secure, which holds the real owner, group and permissions. Add a $Secure to this case to resolve the security ids below to account names."
            .to_string();
    }

    reply
}

fn bucket(conn: &Connection, eid: i64, column: &str) -> Result<Vec<OwnerBucket>, rusqlite::Error> {
    let sql = format!(
        "SELECT {col}, COUNT(*) c FROM records WHERE evidence_id = ?1
         GROUP BY {col} ORDER BY c DESC",
        col = column
    );
    let mut stmt = conn.prepare(&sql)?;
    let rows = stmt.query_map(rusqlite::params![eid], |r| {
        Ok(OwnerBucket {
            id: r.get(0)?,
            count: r.get(1)?,
            examples: Vec::new(),
            name: String::new(),
            sid: String::new(),
        })
    })?;
    rows.collect()
}

fn owner_examples(
    conn: &Connection,
    eid: i64,
    column: &str,
    id: i64,
    limit: i64,
) -> Result<Vec<String>, rusqlite::Error> {
    if id == 0 {
        return Ok(Vec::new());
    }
    let sql = format!(
        "SELECT path FROM records WHERE evidence_id = ?1 AND {col} = ?2 AND path <> ''
         ORDER BY entry LIMIT ?3",
        col = column
    );
    let mut stmt = conn.prepare(&sql)?;
    let rows = stmt.query_map(rusqlite::params![eid, id, limit], |r| r.get::<_, String>(0))?;
    rows.collect()
}

fn folder_neighbors(conn: &Connection, eid: i64, entry: i64) -> Result<GraphReply, rusqlite::Error> {
    let mut reply = GraphReply::default();
    let folder_id = format!("folder:{}", entry);
    if let Some(folder) = record_store::get(conn, eid, entry).ok().flatten() {
        reply.nodes.push(NodeOwned {
            id: folder_id.clone(),
            kind: "folder",
            label: folder.name.clone(),
            sub: folder.path.clone(),
        }.into());
    } else {
        reply.nodes.push(NodeOwned {
            id: folder_id.clone(),
            kind: "folder",
            label: format!("entry {}", entry),
            sub: String::from("folder"),
        }.into());
    }
    let kids = record_store::children(conn, eid, entry, 25).unwrap_or_default();
    for kid in kids {
        let kid_id = format!("file:{}", kid.entry);
        reply.nodes.push(file_node(&kid).into());
        reply.edges.push(Edge { from: folder_id.clone(), to: kid_id, rel: String::from("contains") });
    }
    Ok(reply)
}

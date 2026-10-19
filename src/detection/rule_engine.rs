use std::borrow::Cow;

use regex::RegexBuilder;
use serde::{Deserialize, Serialize};

use crate::detection::{extension, is_zeroed, iso_epoch_seconds};
use crate::vault::record_store::StoredRecord;

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Rule {
    #[serde(default)]
    pub id: String,
    pub title: String,
    pub severity: String,
    #[serde(default)]
    pub mitre: String,
    #[serde(default)]
    pub reason: String,
    pub condition: Node,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(untagged)]
pub enum Node {
    All { all: Vec<Node> },
    Any { any: Vec<Node> },
    Not { not: Box<Node> },
    Leaf(Predicate),
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Predicate {
    pub field: String,
    pub op: String,
    #[serde(default)]
    pub value: serde_json::Value,
}

pub fn eval(node: &Node, r: &StoredRecord) -> bool {
    match node {
        Node::All { all } => all.iter().all(|n| eval(n, r)),
        Node::Any { any } => any.iter().any(|n| eval(n, r)),
        Node::Not { not } => !eval(not, r),
        Node::Leaf(p) => eval_pred(p, r),
    }
}

fn parent_path(path: &str) -> &str {
    match path.rfind('\\') {
        Some(i) => &path[..i],
        None => "",
    }
}

fn field_str<'a>(field: &str, r: &'a StoredRecord) -> Option<Cow<'a, str>> {
    match field {
        "name" => Some(Cow::Borrowed(r.name.as_str())),
        "ext" => Some(Cow::Owned(extension(&r.name))),
        "path" => Some(Cow::Borrowed(r.path.as_str())),
        "parent_path" => Some(Cow::Borrowed(parent_path(&r.path))),
        "si_created" => Some(Cow::Borrowed(r.si_created.as_str())),
        "si_modified" => Some(Cow::Borrowed(r.si_modified.as_str())),
        "si_mft_modified" => Some(Cow::Borrowed(r.si_mft_modified.as_str())),
        "si_accessed" => Some(Cow::Borrowed(r.si_accessed.as_str())),
        "fn_created" => Some(Cow::Borrowed(r.fn_created.as_str())),
        _ => None,
    }
}

fn field_bool(field: &str, r: &StoredRecord) -> Option<bool> {
    match field {
        "is_directory" => Some(r.is_directory),
        "deleted" => Some(!r.in_use),
        "has_ads" => Some(r.has_ads),
        "orphan" => Some(r.orphan),
        _ => None,
    }
}

fn field_num(field: &str, r: &StoredRecord) -> Option<i64> {
    match field {
        "entry" => Some(r.entry),
        "sequence" => Some(r.sequence),
        "parent_entry" => Some(r.parent_entry),
        _ => None,
    }
}

fn eval_pred(p: &Predicate, r: &StoredRecord) -> bool {
    match p.op.as_str() {
        "is_true" => field_bool(&p.field, r).unwrap_or(false),
        "is_false" => !field_bool(&p.field, r).unwrap_or(true),
        "eq" | "ne" | "contains" | "starts_with" | "ends_with" | "in" | "regex" => {
            let field = match field_str(&p.field, r) {
                Some(v) => v.to_ascii_lowercase(),
                None => return false,
            };
            string_op(&p.op, &field, &p.value)
        }
        "gt" | "lt" | "gte" | "lte" => {
            let a = field_num(&p.field, r);
            let b = p.value.as_i64();
            match (a, b) {
                (Some(a), Some(b)) => compare_num(&p.op, a, b),
                _ => false,
            }
        }
        "before" | "after" => {
            let a = match field_str(&p.field, r) {
                Some(v) => v,
                None => return false,
            };
            if is_zeroed(&a) {
                return false;
            }
            let b = match p.value.as_str() {
                Some(s) => s,
                None => return false,
            };
            if p.op == "before" {
                a.as_ref() < b
            } else {
                a.as_ref() > b
            }
        }
        "lt_field" | "gt_field" => {
            let other = match p.value.as_str() {
                Some(s) => s,
                None => return false,
            };
            let a = field_str(&p.field, r);
            let b = field_str(other, r);
            match (a, b) {
                (Some(a), Some(b)) if !is_zeroed(&a) && !is_zeroed(&b) => {
                    if p.op == "lt_field" {
                        a.as_ref() < b.as_ref()
                    } else {
                        a.as_ref() > b.as_ref()
                    }
                }
                _ => false,
            }
        }
        "gap_gt" => {
            let other = p.value.get("field").and_then(|v| v.as_str());
            let seconds = p.value.get("seconds").and_then(|v| v.as_i64()).unwrap_or(0);
            let (other, seconds) = match other {
                Some(o) => (o, seconds),
                None => return false,
            };
            let a = field_str(&p.field, r).and_then(|s| iso_epoch_seconds(&s));
            let b = field_str(other, r).and_then(|s| iso_epoch_seconds(&s));
            match (a, b) {
                (Some(a), Some(b)) => b - a > seconds,
                _ => false,
            }
        }
        _ => false,
    }
}

fn compare_num(op: &str, a: i64, b: i64) -> bool {
    match op {
        "gt" => a > b,
        "lt" => a < b,
        "gte" => a >= b,
        "lte" => a <= b,
        _ => false,
    }
}

fn string_op(op: &str, field_lower: &str, value: &serde_json::Value) -> bool {
    if op == "in" {
        if let Some(arr) = value.as_array() {
            return arr
                .iter()
                .filter_map(|v| v.as_str())
                .any(|s| s.to_ascii_lowercase() == field_lower);
        }
        return false;
    }
    if op == "regex" {
        let pat = match value.as_str() {
            Some(s) => s,
            None => return false,
        };
        return match RegexBuilder::new(pat)
            .case_insensitive(true)
            .size_limit(1 << 20)
            .dfa_size_limit(1 << 20)
            .build()
        {
            Ok(re) => re.is_match(field_lower),
            Err(_) => false,
        };
    }
    let needle = match value.as_str() {
        Some(s) => s.to_ascii_lowercase(),
        None => return false,
    };
    match op {
        "eq" => field_lower == needle,
        "ne" => field_lower != needle,
        "contains" => field_lower.contains(&needle),
        "starts_with" => field_lower.starts_with(&needle),
        "ends_with" => field_lower.ends_with(&needle),
        _ => false,
    }
}

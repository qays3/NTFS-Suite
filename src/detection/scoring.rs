use crate::detection::Severity;

pub fn base_score(severity: Severity) -> i64 {
    match severity {
        Severity::High => 50,
        Severity::Medium => 25,
        Severity::Low => 10,
    }
}

pub fn apply_cloud_downgrade(score: i64) -> i64 {
    let reduced = score / 4;
    if reduced < 1 {
        1
    } else {
        reduced
    }
}

use std::time::{SystemTime, UNIX_EPOCH};

use crate::util::filetime::unix_seconds_to_iso8601;

pub fn now_unix_seconds() -> i64 {
    match SystemTime::now().duration_since(UNIX_EPOCH) {
        Ok(d) => d.as_secs() as i64,
        Err(_) => 0,
    }
}

pub fn now_iso8601() -> String {
    unix_seconds_to_iso8601(now_unix_seconds())
}

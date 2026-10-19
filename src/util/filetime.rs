pub const TICKS_PER_SECOND: i64 = 10_000_000;
pub const EPOCH_DIFFERENCE_SECONDS: i64 = 11_644_473_600;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct FileTime {
    pub ticks: u64,
}

impl FileTime {
    pub fn new(ticks: u64) -> Self {
        FileTime { ticks }
    }

    pub fn is_zero(&self) -> bool {
        self.ticks == 0
    }

    pub fn subsecond_ticks(&self) -> u64 {
        self.ticks % (TICKS_PER_SECOND as u64)
    }

    pub fn has_zero_subseconds(&self) -> bool {
        self.ticks != 0 && self.subsecond_ticks() == 0
    }

    pub fn unix_seconds(&self) -> i64 {
        (self.ticks as i64) / TICKS_PER_SECOND - EPOCH_DIFFERENCE_SECONDS
    }

    pub fn unix_nanos(&self) -> i128 {
        let secs = self.unix_seconds() as i128;
        let sub = (self.ticks % (TICKS_PER_SECOND as u64)) as i128;
        secs * 1_000_000_000i128 + sub * 100i128
    }

    pub fn to_iso8601_utc(&self) -> String {
        if self.ticks == 0 {
            return String::from("1601-01-01T00:00:00.0000000Z");
        }
        let total_seconds = (self.ticks / TICKS_PER_SECOND as u64) as i64;
        let sub = self.ticks % TICKS_PER_SECOND as u64;
        let (year, month, day, hour, minute, second) = civil_from_ticks(total_seconds);
        format!(
            "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}.{:07}Z",
            year, month, day, hour, minute, second, sub
        )
    }
}

const DAYS_1601_TO_1970: i64 = 134_774;

fn civil_from_ticks(seconds_since_1601: i64) -> (i64, u32, u32, u32, u32, u32) {
    let days_since_1601 = seconds_since_1601.div_euclid(86_400);
    let secs_of_day = seconds_since_1601.rem_euclid(86_400);
    let hour = (secs_of_day / 3600) as u32;
    let minute = ((secs_of_day % 3600) / 60) as u32;
    let second = (secs_of_day % 60) as u32;
    let days_since_1970 = days_since_1601 - DAYS_1601_TO_1970;
    let (year, month, day) = civil_from_days(days_since_1970);
    (year, month, day, hour, minute, second)
}

pub fn unix_seconds_to_iso8601(seconds: i64) -> String {
    let days = seconds.div_euclid(86_400);
    let secs_of_day = seconds.rem_euclid(86_400);
    let hour = (secs_of_day / 3600) as u32;
    let minute = ((secs_of_day % 3600) / 60) as u32;
    let second = (secs_of_day % 60) as u32;
    let (year, month, day) = civil_from_days(days);
    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
        year, month, day, hour, minute, second
    )
}

fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    let year = if m <= 2 { y + 1 } else { y };
    (year, m, d)
}

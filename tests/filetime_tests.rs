use ntfs_suite::util::filetime::FileTime;

#[test]
fn unix_epoch_filetime() {
    let ft = FileTime::new(116_444_736_000_000_000);
    assert_eq!(ft.unix_seconds(), 0);
    assert_eq!(ft.to_iso8601_utc(), "1970-01-01T00:00:00.0000000Z");
}

#[test]
fn known_date_2020() {
    let ft = FileTime::new(132_223_104_000_000_000);
    assert_eq!(ft.unix_seconds(), 1_577_836_800);
    assert_eq!(ft.to_iso8601_utc(), "2020-01-01T00:00:00.0000000Z");
}

#[test]
fn zero_subseconds_detected() {
    let whole = FileTime::new(132_223_104_000_000_000);
    assert!(whole.has_zero_subseconds());
    let fractional = FileTime::new(132_223_104_000_000_000 + 1_234_567);
    assert!(!fractional.has_zero_subseconds());
    assert_eq!(fractional.subsecond_ticks(), 1_234_567);
}

#[test]
fn zero_ticks_is_1601() {
    let ft = FileTime::new(0);
    assert!(ft.is_zero());
    assert!(!ft.has_zero_subseconds());
    assert_eq!(ft.to_iso8601_utc(), "1601-01-01T00:00:00.0000000Z");
}

#[test]
fn iso_includes_fractions() {
    let ft = FileTime::new(132_223_104_000_000_000 + 1_234_567);
    assert_eq!(ft.to_iso8601_utc(), "2020-01-01T00:00:00.1234567Z");
}

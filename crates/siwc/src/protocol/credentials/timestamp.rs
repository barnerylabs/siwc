//! Parsing `earliest_refresh_at` timestamps from Unix seconds or RFC 3339 text.

use crate::time::UnixTime;

/// Maximum Unix timestamp accepted in seconds (`10^12`, year 33658).
const MAX_UNIX_SECS: u64 = 1_000_000_000_000;

/// Parses a JSON-encoded or plain `earliest_refresh_at` text as a [`UnixTime`].
///
/// Accepts:
/// - Unsigned integer or decimal Unix seconds (`1795435200`, `"1795435200"`,
///   `1795435200.5`)
/// - RFC 3339 / ISO-8601 UTC and fixed-offset timestamps
///   (`2026-11-23T12:00:00Z`, `2026-11-23T13:00:00.250+01:00`)
///
/// Returns `None` for any unrecognised text so opaque values never fail token
/// parsing.
pub(super) fn parse(raw: &str) -> Option<UnixTime> {
    let text = raw.trim_ascii();
    let text = text
        .strip_prefix('"')
        .and_then(|inner| inner.strip_suffix('"'))
        .unwrap_or(text)
        .trim_ascii();
    if text.is_empty() {
        return None;
    }
    parse_unix_seconds(text)
        .or_else(|| parse_rfc3339(text))
        .map(UnixTime::from_secs)
}

fn parse_unix_seconds(text: &str) -> Option<u64> {
    if let Ok(secs) = text.parse::<u64>() {
        return (secs <= MAX_UNIX_SECS).then_some(secs);
    }
    let (whole, fraction) = text.split_once('.')?;
    if whole.is_empty()
        || fraction.is_empty()
        || !whole.bytes().all(|b| b.is_ascii_digit())
        || !fraction.bytes().all(|b| b.is_ascii_digit())
    {
        return None;
    }
    let secs = whole.parse::<u64>().ok()?;
    // Ceiling so a fractional boundary such as `100.2` is not refreshed at `100`.
    let rounded = if fraction.bytes().any(|b| b != b'0') {
        secs.checked_add(1)?
    } else {
        secs
    };
    (rounded <= MAX_UNIX_SECS).then_some(rounded)
}

fn parse_rfc3339(text: &str) -> Option<u64> {
    let bytes = text.as_bytes();
    if bytes.len() < 20 || bytes[4] != b'-' || bytes[7] != b'-' {
        return None;
    }
    if !matches!(bytes[10], b'T' | b't' | b' ') || bytes[13] != b':' || bytes[16] != b':' {
        return None;
    }
    let year = i64::from(digits(&bytes[0..4])?);
    let month = digits(&bytes[5..7])?;
    let day = digits(&bytes[8..10])?;
    let hour = i64::from(digits(&bytes[11..13])?);
    let minute = i64::from(digits(&bytes[14..16])?);
    let second = i64::from(digits(&bytes[17..19])?);

    if year < 1969 || !(1..=12).contains(&month) || !valid_day(year, month, day) {
        return None;
    }
    // Allow leap second `:60`, clamped into the next second via ceiling logic.
    if hour > 23 || minute > 59 || second > 60 {
        return None;
    }

    let mut rest = &bytes[19..];
    let mut subsecond_nonzero = false;
    if let Some(after_dot) = rest.strip_prefix(b".") {
        let frac_len = after_dot
            .iter()
            .take_while(|byte| byte.is_ascii_digit())
            .count();
        if frac_len == 0 {
            return None;
        }
        subsecond_nonzero = after_dot[..frac_len].iter().any(|&b| b != b'0');
        rest = &after_dot[frac_len..];
    }

    let offset_secs: i64 = match rest {
        b"Z" | b"z" => 0,
        [sign @ (b'+' | b'-'), h1, h2, b':', m1, m2] => {
            let off_h = i64::from(digits(&[*h1, *h2])?);
            let off_m = i64::from(digits(&[*m1, *m2])?);
            if off_h > 23 || off_m > 59 {
                return None;
            }
            let total = off_h * 3600 + off_m * 60;
            if *sign == b'+' { total } else { -total }
        }
        _ => return None,
    };

    let days = days_from_civil(year, i64::from(month), i64::from(day));
    let clamped_second = second.min(59);
    let mut unix = days
        .checked_mul(86_400)?
        .checked_add(hour * 3600 + minute * 60 + clamped_second)?
        .checked_sub(offset_secs)?;
    if second == 60 || subsecond_nonzero {
        unix = unix.checked_add(1)?;
    }
    let secs = u64::try_from(unix).ok()?;
    (secs <= MAX_UNIX_SECS).then_some(secs)
}

fn digits(slice: &[u8]) -> Option<u32> {
    let mut acc = 0_u32;
    for &byte in slice {
        if !byte.is_ascii_digit() {
            return None;
        }
        acc = acc.checked_mul(10)?.checked_add(u32::from(byte - b'0'))?;
    }
    Some(acc)
}

fn is_leap_year(year: i64) -> bool {
    (year % 4 == 0 && year % 100 != 0) || year % 400 == 0
}

fn valid_day(year: i64, month: u32, day: u32) -> bool {
    if day == 0 {
        return false;
    }
    let max_day = match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if is_leap_year(year) => 29,
        2 => 28,
        _ => return false,
    };
    day <= max_day
}

/// Days since `1970-01-01` in the proleptic Gregorian calendar, counted in
/// 400-year cycles.
fn days_from_civil(year: i64, month: i64, day: i64) -> i64 {
    let adjusted_year = year - i64::from(month <= 2);
    let era = if adjusted_year >= 0 {
        adjusted_year
    } else {
        adjusted_year - 399
    } / 400;
    let yoe = adjusted_year - era * 400;
    let doy = (153 * (month + if month > 2 { -3 } else { 9 }) + 2) / 5 + day - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_unix_seconds_and_rfc3339_with_offsets_and_fractions() {
        assert_eq!(
            parse("1700000000"),
            Some(UnixTime::from_secs(1_700_000_000))
        );
        assert_eq!(
            parse("\"1700000000\""),
            Some(UnixTime::from_secs(1_700_000_000))
        );
        assert_eq!(
            parse("1700000000.000"),
            Some(UnixTime::from_secs(1_700_000_000))
        );
        assert_eq!(
            parse("1700000000.25"),
            Some(UnixTime::from_secs(1_700_000_001))
        );
        assert_eq!(
            parse("\"1970-01-01T00:00:00Z\""),
            Some(UnixTime::from_secs(0))
        );
        assert_eq!(
            parse("\"2024-02-29T23:59:59Z\""),
            Some(UnixTime::from_secs(1_709_251_199))
        );
        assert_eq!(
            parse("2026-11-23T13:00:00+01:00"),
            Some(UnixTime::from_secs(1_795_435_200))
        );
        assert_eq!(
            parse("2026-11-23T11:00:00.100-01:00"),
            Some(UnixTime::from_secs(1_795_435_201))
        );
        // Negative offset whose UTC instant is at/after the epoch, plus leap second `:60.500`.
        assert_eq!(
            parse("1969-12-31T23:30:00-01:00"),
            Some(UnixTime::from_secs(1800))
        );
        assert_eq!(
            parse("2024-02-29T23:59:60.500Z"),
            Some(UnixTime::from_secs(1_709_251_200))
        );
    }

    #[test]
    fn rejects_non_leap_feb_29_out_of_range_fields_and_opaque_strings() {
        for bad in [
            "",
            "\"\"",
            "\"synthetic-earliest\"",
            "2025-02-29T00:00:00Z",
            "2026-13-01T00:00:00Z",
            "2026-00-01T00:00:00Z",
            "2026-11-31T00:00:00Z",
            "2026-11-23T24:00:00Z",
            "2026-11-23T12:60:00Z",
            "2026-11-23T12:00:00+24:00",
            "2026-11-23T12:00:00.",
            "1969-12-31T23:59:59Z",
            "1000000000001",
        ] {
            assert_eq!(parse(bad), None, "{bad}");
        }
    }
}

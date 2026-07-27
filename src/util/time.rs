//! Time formatting helpers shared across the codebase -- currently
//! just the HTTP `Date` header format, moved here from
//! `http::response` (its original, `pub(crate)`-only home) since
//! civil-calendar arithmetic isn't really an HTTP-response concern
//! and other modules (a future `Expires`/`If-Modified-Since` header
//! elsewhere, or a non-HTTP log timestamp) may eventually want the
//! same conversion.

const WEEKDAYS: [&str; 7] = ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"];
const MONTHS: [&str; 12] = [
    "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
];

/// Converts a Unix timestamp (seconds since epoch, UTC) to the
/// RFC 9110 IMF-fixdate format. Implements the same civil-calendar
/// arithmetic `gmtime` does, restricted to what formatting the `Date`
/// header needs (no timezone handling -- always UTC).
pub fn format_http_date(unix_secs: u64) -> String {
    let days_since_epoch = unix_secs / 86400;
    let secs_of_day = unix_secs % 86400;
    let hour = secs_of_day / 3600;
    let minute = (secs_of_day % 3600) / 60;
    let second = secs_of_day % 60;

    // 1970-01-01 was a Thursday (weekday index 4).
    let weekday = WEEKDAYS[((days_since_epoch + 4) % 7) as usize];

    let (year, month, day) = civil_from_days(days_since_epoch as i64);

    format!(
        "{weekday}, {day:02} {month} {year} {hour:02}:{minute:02}:{second:02} GMT",
        month = MONTHS[(month - 1) as usize]
    )
}

/// Howard Hinnant's `civil_from_days` algorithm: converts a day count
/// since the Unix epoch into a proleptic-Gregorian (year, month, day).
/// A standard, well-tested piece of civil calendar arithmetic (avoids
/// hand-rolling leap-year logic, a well-known source of off-by-one
/// bugs at century/400-year boundaries).
fn civil_from_days(z: i64) -> (i64, i64, i64) {
    let z = z + 719468;
    let era = if z >= 0 { z } else { z - 146096 } / 146097;
    let doe = (z - era * 146097) as u64; // [0, 146096]
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365; // [0, 399]
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100); // [0, 365]
    let mp = (5 * doy + 2) / 153; // [0, 11]
    let d = (doy - (153 * mp + 2) / 5 + 1) as i64; // [1, 31]
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as i64; // [1, 12]
    let y = if m <= 2 { y + 1 } else { y };
    (y, m, d)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn formats_unix_epoch_correctly() {
        // 1970-01-01 00:00:00 UTC was a Thursday.
        assert_eq!(format_http_date(0), "Thu, 01 Jan 1970 00:00:00 GMT");
    }

    #[test]
    fn formats_a_known_recent_date_correctly() {
        // 2024-01-15 12:30:45 UTC (verified against a reference gmtime).
        let unix_secs = 1_705_321_845;
        assert_eq!(format_http_date(unix_secs), "Mon, 15 Jan 2024 12:30:45 GMT");
    }

    #[test]
    fn handles_leap_year_february_29() {
        // 2024-02-29 00:00:00 UTC -- 2024 is a leap year.
        let unix_secs = 1_709_164_800;
        assert_eq!(format_http_date(unix_secs), "Thu, 29 Feb 2024 00:00:00 GMT");
    }

    #[test]
    fn handles_year_boundary() {
        // 2023-12-31 23:59:59 UTC.
        let unix_secs = 1_704_067_199;
        assert_eq!(format_http_date(unix_secs), "Sun, 31 Dec 2023 23:59:59 GMT");
    }
}

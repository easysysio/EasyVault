// =============================================================================
// clock.rs — current time and the timestamp format EasyVault stores.
//
// Every timestamp EasyVault writes (audit rows, token and session expiry) is
// RFC 3339 in UTC with an explicit "+00:00" offset, e.g.
// "2026-11-18T10:00:00.123456+00:00". Keeping one fixed shape means stored
// values compare correctly as plain strings (audit retention relies on it).
// =============================================================================

use time::format_description::well_known::Rfc3339;
use time::{Duration, OffsetDateTime};

use crate::error::AppError;

/// The current time in UTC.
pub fn now() -> OffsetDateTime {
    OffsetDateTime::now_utc()
}

/// Format a time as RFC 3339 in UTC with a "+00:00" offset.
pub fn rfc3339(t: OffsetDateTime) -> String {
    let s = t.to_offset(time::UtcOffset::UTC).format(&Rfc3339).unwrap_or_default();
    match s.strip_suffix('Z') {
        Some(base) => format!("{base}+00:00"),
        None => s,
    }
}

/// The current time plus `seconds`, or a 400 if that is past year 9999.
pub fn after_seconds(seconds: i64) -> Result<OffsetDateTime, AppError> {
    now()
        .checked_add(Duration::seconds(seconds))
        .filter(|t| t.year() <= 9999)
        .ok_or_else(|| AppError::BadRequest("ttl is too large".into()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn formats_utc_with_explicit_offset() {
        let t = OffsetDateTime::from_unix_timestamp(1_795_000_000).unwrap();
        assert_eq!(rfc3339(t), "2026-11-18T11:06:40+00:00");
        let t = t + Duration::microseconds(123_456);
        assert_eq!(rfc3339(t), "2026-11-18T11:06:40.123456+00:00");
    }

    #[test]
    fn huge_ttl_is_rejected() {
        assert!(after_seconds(60).is_ok());
        assert!(after_seconds(i64::MAX).is_err());
    }
}

//! Statistics rules re-implemented from the original (see MECHANICS.md for
//! the function addresses each number comes from).

use std::time::Duration;

/// Connection loop tick (service `ConnectionLoop`, `WaitOne(200)`).
pub const LOOP_TICK: Duration = Duration::from_millis(200);
/// Statistics refresh only after more than this has passed (`GetTunnelStatistics`).
pub const STATS_MIN_INTERVAL_SECS: f64 = 1.0;
/// Retry back-off after a failed connect: start, then double, capped.
pub const RETRY_START_MS: u64 = 200;
pub const RETRY_MAX_MS: u64 = 5000;
/// Disconnect gives up waiting after this long (service connection loop).
pub const DISCONNECT_TIMEOUT: Duration = Duration::from_secs(30);
/// Liveness probe: re-validate a tunnel whose received bytes haven't moved
/// and whose last handshake is older than this (wgbooster 0x1800ef120, `0x6d`).
pub const LIVENESS_IDLE_SECS: u64 = 109;
/// WireGuard REJECT_AFTER_TIME: a session older than this is unusable.
pub const REJECT_AFTER_SECS: u64 = 180;

/// Bits per second from two byte counters, like the service does:
/// `(new - old) * 8 / seconds`. No rate until a first non-zero sample exists.
pub fn rate_bits(prev_bytes: u64, now_bytes: u64, secs: f64) -> Option<u64> {
    if prev_bytes == 0 || secs <= 0.0 {
        return None;
    }
    Some((now_bytes.saturating_sub(prev_bytes) as f64 * 8.0 / secs) as u64)
}

/// The original's loss text: ratio × 100 with up to two decimals.
pub fn fmt_loss(ratio: f32) -> String {
    let pct = ratio * 100.0;
    let s = format!("{pct:.2}");
    let s = s.trim_end_matches('0').trim_end_matches('.');
    format!("{s} %")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rates() {
        assert_eq!(rate_bits(0, 1000, 1.0), None);
        assert_eq!(rate_bits(1000, 2024, 1.0), Some(8192));
        assert_eq!(fmt_loss(0.125), "12.5 %");
        assert_eq!(fmt_loss(0.0), "0 %");
    }
}

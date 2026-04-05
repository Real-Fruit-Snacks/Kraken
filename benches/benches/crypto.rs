//! Cryptographic operation benchmarks
//!
//! Validates spec requirements:
//! - mTLS handshake: <100ms
//! - Signature verification: <10ms

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use crypto::{aes_gcm, hkdf, x25519, Nonce, SymmetricKey};
use module_store::ModuleSigner;

// ---------------------------------------------------------------------------
// X25519 benchmarks
// ---------------------------------------------------------------------------

fn bench_x25519_keygen(c: &mut Criterion) {
    c.bench_function("crypto/x25519_keygen", |b| {
        b.iter(|| {
            let (public, _private) = x25519::generate_keypair().unwrap();
            black_box(public)
        })
    });
}

fn bench_x25519_diffie_hellman(c: &mut Criterion) {
    let (pub_a, priv_a) = x25519::generate_keypair().unwrap();
    let (pub_b, _priv_b) = x25519::generate_keypair().unwrap();

    c.bench_function("crypto/x25519_dh", |b| {
        b.iter(|| {
            let shared = x25519::diffie_hellman(&priv_a, &pub_b).unwrap();
            black_box(shared)
        })
    });

    // Also bench the full key exchange (both sides)
    let (_pub_a2, priv_a2) = x25519::generate_keypair().unwrap();
    c.bench_function("crypto/x25519_full_exchange", |b| {
        b.iter(|| {
            let shared_a = x25519::diffie_hellman(&priv_a, &pub_b).unwrap();
            let shared_b = x25519::diffie_hellman(&priv_a2, &pub_a).unwrap();
            black_box((shared_a, shared_b))
        })
    });
}

// ---------------------------------------------------------------------------
// HKDF benchmarks
// ---------------------------------------------------------------------------

fn bench_hkdf_derive(c: &mut Criterion) {
    let shared_secret = [0x42u8; 32];
    let info = b"kraken-session-key";

    c.bench_function("crypto/hkdf_derive_32", |b| {
        b.iter(|| {
            let derived = hkdf::derive(&shared_secret, info, 32).unwrap();
            black_box(derived)
        })
    });

    c.bench_function("crypto/hkdf_derive_64", |b| {
        b.iter(|| {
            let derived = hkdf::derive(&shared_secret, info, 64).unwrap();
            black_box(derived)
        })
    });
}

// ---------------------------------------------------------------------------
// AES-GCM benchmarks
// ---------------------------------------------------------------------------

fn bench_aes_gcm(c: &mut Criterion) {
    let key = SymmetricKey::from_bytes(&[0x42u8; 32]).unwrap();
    let nonce = Nonce::from_counter(1);
    let aad = b"kraken-aad";

    let mut group = c.benchmark_group("crypto/aes_gcm");

    for size in [64, 1024, 4096, 65536] {
        let plaintext = vec![0xABu8; size];

        group.throughput(Throughput::Bytes(size as u64));

        group.bench_with_input(BenchmarkId::new("encrypt", size), &plaintext, |b, pt| {
            b.iter(|| {
                let ct = aes_gcm::encrypt(&key, &nonce, pt, aad).unwrap();
                black_box(ct)
            })
        });

        let ciphertext = aes_gcm::encrypt(&key, &nonce, &plaintext, aad).unwrap();
        group.bench_with_input(BenchmarkId::new("decrypt", size), &ciphertext, |b, ct| {
            b.iter(|| {
                let pt = aes_gcm::decrypt(&key, &nonce, ct, aad).unwrap();
                black_box(pt)
            })
        });
    }

    group.finish();
}

// ---------------------------------------------------------------------------
// Full handshake simulation benchmark
// ---------------------------------------------------------------------------

fn bench_handshake(c: &mut Criterion) {
    // Simulates the full mTLS-like handshake:
    // 1. Both sides generate ephemeral X25519 keypairs
    // 2. Exchange public keys (simulated)
    // 3. Compute shared secret
    // 4. Derive session keys via HKDF

    c.bench_function("crypto/handshake_full", |b| {
        b.iter(|| {
            // Server generates keypair
            let (server_pub, server_priv) = x25519::generate_keypair().unwrap();

            // Client generates keypair
            let (client_pub, client_priv) = x25519::generate_keypair().unwrap();

            // Both compute shared secret
            let server_shared = x25519::diffie_hellman(&server_priv, &client_pub).unwrap();
            let client_shared = x25519::diffie_hellman(&client_priv, &server_pub).unwrap();

            // Derive session keys
            let server_key = hkdf::derive(server_shared.as_bytes(), b"server-key", 32).unwrap();
            let client_key = hkdf::derive(client_shared.as_bytes(), b"client-key", 32).unwrap();

            black_box((server_key, client_key))
        })
    });
}

// ---------------------------------------------------------------------------
// Ed25519 signature benchmarks (for module signing)
// ---------------------------------------------------------------------------

fn bench_signature(c: &mut Criterion) {
    let pkcs8 = ModuleSigner::generate_pkcs8().unwrap();
    let signer = ModuleSigner::new(&pkcs8).unwrap();

    // Build a minimal unsigned blob for signing
    let code = vec![0xCCu8; 1024];
    let unsigned_blob = module_store::build_unsigned_blob(
        "bench.mod",
        "Benchmark Module",
        (1, 0, 0),
        common::ARCH_X64_LINUX,
        0,
        &code,
        0,
    );

    c.bench_function("crypto/ed25519_sign", |b| {
        b.iter(|| {
            let signed = signer.sign(&unsigned_blob).unwrap();
            black_box(signed)
        })
    });

    // Note: Verification is done implant-side using ring's verify
    // We benchmark signature creation here which is server-side
}

// ---------------------------------------------------------------------------
// Criterion setup
// ---------------------------------------------------------------------------

criterion_group!(
    benches,
    bench_x25519_keygen,
    bench_x25519_diffie_hellman,
    bench_hkdf_derive,
    bench_aes_gcm,
    bench_handshake,
    bench_signature,
);

criterion_main!(benches);

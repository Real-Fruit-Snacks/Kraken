//! Module loading and signing benchmarks
//!
//! Validates spec requirements:
//! - Module load time: <100ms
//! - Signature verification: <10ms (covered in crypto bench)

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use module_store::{build_unsigned_blob, ModuleSigner};

// ---------------------------------------------------------------------------
// Module signing benchmarks
// ---------------------------------------------------------------------------

fn bench_module_sign(c: &mut Criterion) {
    let pkcs8 = ModuleSigner::generate_pkcs8().unwrap();
    let signer = ModuleSigner::new(&pkcs8).unwrap();

    let mut group = c.benchmark_group("module/sign");

    for code_size in [1024, 4096, 65536, 262144] {
        let code = vec![0xCCu8; code_size];
        let unsigned_blob = build_unsigned_blob(
            "bench.mod",
            "Benchmark Module",
            (1, 0, 0),
            common::ARCH_X64_LINUX,
            0,
            &code,
            0,
        );

        group.throughput(Throughput::Bytes(code_size as u64));
        group.bench_with_input(
            BenchmarkId::new("code_size", code_size),
            &unsigned_blob,
            |b, blob| {
                b.iter(|| {
                    let signed = signer.sign(blob).unwrap();
                    black_box(signed)
                })
            },
        );
    }

    group.finish();
}

// ---------------------------------------------------------------------------
// Module blob construction benchmarks
// ---------------------------------------------------------------------------

fn bench_build_blob(c: &mut Criterion) {
    let mut group = c.benchmark_group("module/build_blob");

    for code_size in [1024, 4096, 65536] {
        let code = vec![0xCCu8; code_size];

        group.throughput(Throughput::Bytes(code_size as u64));
        group.bench_with_input(
            BenchmarkId::new("code_size", code_size),
            &code,
            |b, code| {
                b.iter(|| {
                    let blob = build_unsigned_blob(
                        "bench.mod",
                        "Benchmark Module",
                        (1, 0, 0),
                        common::ARCH_X64_LINUX,
                        0,
                        code,
                        0,
                    );
                    black_box(blob)
                })
            },
        );
    }

    group.finish();
}

// ---------------------------------------------------------------------------
// Key generation benchmark
// ---------------------------------------------------------------------------

fn bench_keygen(c: &mut Criterion) {
    c.bench_function("module/keygen_ed25519", |b| {
        b.iter(|| {
            let pkcs8 = ModuleSigner::generate_pkcs8().unwrap();
            black_box(pkcs8)
        })
    });
}

// ---------------------------------------------------------------------------
// Full module preparation pipeline
// ---------------------------------------------------------------------------

fn bench_full_pipeline(c: &mut Criterion) {
    // Simulates the full module preparation:
    // 1. Build unsigned blob
    // 2. Sign with Ed25519
    // This is what the server does when preparing a module for deployment

    let pkcs8 = ModuleSigner::generate_pkcs8().unwrap();
    let signer = ModuleSigner::new(&pkcs8).unwrap();

    let mut group = c.benchmark_group("module/full_pipeline");

    for code_size in [4096, 65536] {
        let code = vec![0xCCu8; code_size];

        group.throughput(Throughput::Bytes(code_size as u64));
        group.bench_with_input(
            BenchmarkId::new("code_size", code_size),
            &code,
            |b, code| {
                b.iter(|| {
                    // Build blob
                    let blob = build_unsigned_blob(
                        "bench.mod",
                        "Benchmark Module",
                        (1, 0, 0),
                        common::ARCH_X64_LINUX,
                        0,
                        code,
                        0,
                    );

                    // Sign
                    let signed = signer.sign(&blob).unwrap();

                    black_box(signed)
                })
            },
        );
    }

    group.finish();
}

// ---------------------------------------------------------------------------
// Criterion setup
// ---------------------------------------------------------------------------

criterion_group!(
    benches,
    bench_module_sign,
    bench_build_blob,
    bench_keygen,
    bench_full_pipeline,
);

criterion_main!(benches);

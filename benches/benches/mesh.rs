//! Mesh networking benchmarks
//!
//! Validates spec requirements:
//! - Link establishment: <1s
//! - Message relay latency: <100ms per hop
//! - Topology updates: <5s

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use common::ImplantId;
use mesh::{MeshRouter, PeerLinkState};

// ---------------------------------------------------------------------------
// Link establishment benchmarks
// ---------------------------------------------------------------------------

fn bench_add_link(c: &mut Criterion) {
    c.bench_function("mesh/add_link", |b| {
        b.iter_with_setup(
            || {
                let router = MeshRouter::new();
                let from = ImplantId::new();
                let to = ImplantId::new();
                (router, from, to)
            },
            |(mut router, from, to)| {
                router.add_link(from, to, PeerLinkState::Active, 10);
                black_box(router)
            },
        )
    });

    // Benchmark adding multiple links (simulates mesh growth)
    let mut group = c.benchmark_group("mesh/add_links");
    for count in [10, 50, 100, 500] {
        group.bench_with_input(BenchmarkId::new("count", count), &count, |b, &n| {
            b.iter_with_setup(
                || {
                    let nodes: Vec<_> = (0..n).map(|_| ImplantId::new()).collect();
                    (MeshRouter::new(), nodes)
                },
                |(mut router, nodes)| {
                    // Create a chain topology
                    for window in nodes.windows(2) {
                        router.add_link(window[0], window[1], PeerLinkState::Active, 10);
                    }
                    black_box(router)
                },
            )
        });
    }
    group.finish();
}

// ---------------------------------------------------------------------------
// Route computation benchmarks
// ---------------------------------------------------------------------------

fn bench_compute_route(c: &mut Criterion) {
    // Linear topology: A -> B -> C -> ... -> N
    let mut group = c.benchmark_group("mesh/compute_route");

    for hop_count in [2, 5, 10, 20, 50] {
        let nodes: Vec<_> = (0..=hop_count).map(|_| ImplantId::new()).collect();
        let mut router = MeshRouter::new();

        // Build linear chain
        for window in nodes.windows(2) {
            router.add_link(window[0], window[1], PeerLinkState::Active, 10);
        }

        let source = nodes[0];
        let dest = *nodes.last().unwrap();

        group.bench_with_input(BenchmarkId::new("hops", hop_count), &hop_count, |b, _| {
            b.iter(|| {
                // Clear cache to force recomputation
                router.invalidate_cache();
                let route = router.compute_route(source, dest);
                black_box(route)
            })
        });
    }

    group.finish();
}

fn bench_compute_route_cached(c: &mut Criterion) {
    // Test cache hit performance
    let nodes: Vec<_> = (0..10).map(|_| ImplantId::new()).collect();
    let mut router = MeshRouter::new();

    for window in nodes.windows(2) {
        router.add_link(window[0], window[1], PeerLinkState::Active, 10);
    }

    let source = nodes[0];
    let dest = *nodes.last().unwrap();

    // Prime the cache
    let _ = router.compute_route(source, dest);

    c.bench_function("mesh/compute_route_cached", |b| {
        b.iter(|| {
            let route = router.compute_route(source, dest);
            black_box(route)
        })
    });
}

// ---------------------------------------------------------------------------
// Multi-path computation benchmarks
// ---------------------------------------------------------------------------

fn bench_compute_routes_multipath(c: &mut Criterion) {
    // Diamond topology for testing multipath
    //     B
    //    / \
    //   A   D
    //    \ /
    //     C

    let node_a = ImplantId::new();
    let node_b = ImplantId::new();
    let node_c = ImplantId::new();
    let node_d = ImplantId::new();

    let mut router = MeshRouter::new();
    router.add_link(node_a, node_b, PeerLinkState::Active, 10);
    router.add_link(node_b, node_d, PeerLinkState::Active, 10);
    router.add_link(node_a, node_c, PeerLinkState::Active, 10);
    router.add_link(node_c, node_d, PeerLinkState::Active, 10);

    c.bench_function("mesh/compute_routes_multipath_2", |b| {
        b.iter(|| {
            router.invalidate_cache();
            let routes = router.compute_routes(node_a, node_d, 2);
            black_box(routes)
        })
    });
}

// ---------------------------------------------------------------------------
// Topology update benchmarks
// ---------------------------------------------------------------------------

fn bench_topology_update(c: &mut Criterion) {
    let mut group = c.benchmark_group("mesh/topology_update");

    for node_count in [10, 50, 100] {
        let nodes: Vec<_> = (0..node_count).map(|_| ImplantId::new()).collect();

        group.bench_with_input(
            BenchmarkId::new("remove_link", node_count),
            &nodes,
            |b, nodes| {
                b.iter_with_setup(
                    || {
                        let mut router = MeshRouter::new();
                        for window in nodes.windows(2) {
                            router.add_link(window[0], window[1], PeerLinkState::Active, 10);
                        }
                        // Prime cache
                        let _ = router.compute_route(nodes[0], nodes[node_count - 1]);
                        router
                    },
                    |mut router| {
                        // Remove middle link - triggers cache invalidation
                        let mid = node_count / 2;
                        router.remove_link(nodes[mid], nodes[mid + 1]);
                        black_box(router)
                    },
                )
            },
        );

        group.bench_with_input(
            BenchmarkId::new("add_shortcut", node_count),
            &nodes,
            |b, nodes| {
                b.iter_with_setup(
                    || {
                        let mut router = MeshRouter::new();
                        for window in nodes.windows(2) {
                            router.add_link(window[0], window[1], PeerLinkState::Active, 10);
                        }
                        router
                    },
                    |mut router| {
                        // Add shortcut link
                        router.add_link(nodes[0], nodes[node_count - 1], PeerLinkState::Active, 5);
                        black_box(router)
                    },
                )
            },
        );
    }

    group.finish();
}

fn bench_get_topology(c: &mut Criterion) {
    let mut group = c.benchmark_group("mesh/get_topology");

    for node_count in [10, 50, 100, 500] {
        let nodes: Vec<_> = (0..node_count).map(|_| ImplantId::new()).collect();
        let mut router = MeshRouter::new();

        // Create fully connected mesh (n*(n-1) edges)
        // Actually let's just do a ring to keep edge count manageable
        for i in 0..node_count {
            let next = (i + 1) % node_count;
            router.add_link(nodes[i], nodes[next], PeerLinkState::Active, 10);
        }

        group.bench_with_input(
            BenchmarkId::new("nodes", node_count),
            &router,
            |b, router| {
                b.iter(|| {
                    let topo = router.get_topology();
                    black_box(topo)
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
    bench_add_link,
    bench_compute_route,
    bench_compute_route_cached,
    bench_compute_routes_multipath,
    bench_topology_update,
    bench_get_topology,
);

criterion_main!(benches);

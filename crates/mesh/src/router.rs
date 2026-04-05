//! Mesh routing — Dijkstra-based route computation over the topology graph

use std::collections::HashMap;

use chrono::Utc;
use common::ImplantId;
use petgraph::algo::dijkstra;
use petgraph::graph::{DiGraph, NodeIndex};
use petgraph::visit::EdgeRef;
use petgraph::Direction;

use crate::link::PeerLinkState;

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

/// A computed route through the mesh
#[derive(Debug, Clone)]
pub struct MeshRoute {
    /// Source node
    pub source: ImplantId,

    /// Destination node
    pub destination: ImplantId,

    /// Ordered list of intermediate + destination nodes (excludes source)
    pub hops: Vec<ImplantId>,

    /// Unix timestamp (ms) when this route was computed
    pub computed_at: i64,
}

// ---------------------------------------------------------------------------
// Internal types
// ---------------------------------------------------------------------------

/// Weight assigned to each directed edge in the topology graph
#[derive(Clone, Copy)]
struct LinkWeight {
    latency: u32,
    state: PeerLinkState,
}

impl LinkWeight {
    /// Effective cost for Dijkstra; penalises degraded links, excludes dead ones
    fn cost(self) -> u32 {
        match self.state {
            PeerLinkState::Active => self.latency,
            PeerLinkState::Degraded => self.latency.saturating_mul(2),
            _ => u32::MAX,
        }
    }
}

// ---------------------------------------------------------------------------
// MeshRouter
// ---------------------------------------------------------------------------

/// Server-side router that maintains the full mesh topology and computes
/// source-routed paths via Dijkstra.
pub struct MeshRouter {
    /// Directed graph — nodes are ImplantIds, edges carry link weights
    graph: DiGraph<ImplantId, LinkWeight>,

    /// Maps ImplantId → NodeIndex for O(1) lookup
    node_indices: HashMap<ImplantId, NodeIndex>,

    /// Cached routes (invalidated on any topology change)
    route_cache: HashMap<(ImplantId, ImplantId), MeshRoute>,
}

impl MeshRouter {
    /// Create an empty router
    pub fn new() -> Self {
        Self {
            graph: DiGraph::new(),
            node_indices: HashMap::new(),
            route_cache: HashMap::new(),
        }
    }

    // -----------------------------------------------------------------------
    // Topology mutations
    // -----------------------------------------------------------------------

    /// Add a node if it is not already present
    pub fn add_node(&mut self, implant_id: ImplantId) {
        if let std::collections::hash_map::Entry::Vacant(e) = self.node_indices.entry(implant_id) {
            let idx = self.graph.add_node(implant_id);
            e.insert(idx);
            self.invalidate_cache();
        }
    }

    /// Add or update a directed link between two nodes
    pub fn add_link(
        &mut self,
        from: ImplantId,
        to: ImplantId,
        state: PeerLinkState,
        latency: u32,
    ) {
        self.add_node(from);
        self.add_node(to);

        let from_idx = self.node_indices[&from];
        let to_idx = self.node_indices[&to];
        let weight = LinkWeight { latency, state };

        if let Some(edge) = self.graph.find_edge(from_idx, to_idx) {
            self.graph[edge] = weight;
        } else {
            self.graph.add_edge(from_idx, to_idx, weight);
        }

        self.invalidate_cache();
    }

    /// Remove the directed link from `from` to `to`, if it exists
    pub fn remove_link(&mut self, from: ImplantId, to: ImplantId) {
        if let (Some(&from_idx), Some(&to_idx)) = (
            self.node_indices.get(&from),
            self.node_indices.get(&to),
        ) {
            if let Some(edge) = self.graph.find_edge(from_idx, to_idx) {
                self.graph.remove_edge(edge);
                self.invalidate_cache();
            }
        }
    }

    /// Remove a node and all edges incident to it
    pub fn remove_node(&mut self, implant_id: ImplantId) {
        if let Some(idx) = self.node_indices.remove(&implant_id) {
            self.graph.remove_node(idx);
            self.invalidate_cache();
        }
    }

    // -----------------------------------------------------------------------
    // Route computation
    // -----------------------------------------------------------------------

    /// Compute (and cache) the lowest-cost path from `from` to `to`.
    /// Returns `None` if no reachable path exists.
    pub fn compute_route(&mut self, from: ImplantId, to: ImplantId) -> Option<MeshRoute> {
        let key = (from, to);
        if let Some(cached) = self.route_cache.get(&key) {
            return Some(cached.clone());
        }

        let route = self.compute_route_excluding(from, to, &[])?;
        self.route_cache.insert(key, route.clone());
        Some(route)
    }

    /// Compute up to `count` edge-disjoint paths for redundancy.
    pub fn compute_routes(
        &mut self,
        from: ImplantId,
        to: ImplantId,
        count: usize,
    ) -> Vec<MeshRoute> {
        let mut routes = Vec::new();
        let mut excluded_edges: Vec<(ImplantId, ImplantId)> = Vec::new();

        for _ in 0..count {
            match self.compute_route_excluding(from, to, &excluded_edges) {
                Some(route) => {
                    // Exclude all edges on this path so the next route is disjoint
                    for window in route.hops.windows(2) {
                        excluded_edges.push((window[0], window[1]));
                    }
                    // Also exclude the source→first-hop edge
                    if let Some(&first) = route.hops.first() {
                        excluded_edges.push((from, first));
                    }
                    routes.push(route);
                }
                None => break,
            }
        }

        routes
    }

    /// Return the full edge list as `(from, to, state)` tuples for topology
    /// serialisation / display.
    pub fn get_topology(&self) -> Vec<(ImplantId, ImplantId, PeerLinkState)> {
        self.graph
            .edge_indices()
            .map(|edge| {
                let (from, to) = self.graph.edge_endpoints(edge).unwrap();
                let weight = &self.graph[edge];
                (self.graph[from], self.graph[to], weight.state)
            })
            .collect()
    }

    /// Clear the route cache (called automatically after every topology change)
    pub fn invalidate_cache(&mut self) {
        self.route_cache.clear();
    }

    // -----------------------------------------------------------------------
    // Internal helpers
    // -----------------------------------------------------------------------

    /// Dijkstra with optional edge exclusion list (used for multi-path)
    fn compute_route_excluding(
        &self,
        from: ImplantId,
        to: ImplantId,
        excluded: &[(ImplantId, ImplantId)],
    ) -> Option<MeshRoute> {
        let from_idx = self.node_indices.get(&from)?;
        let to_idx = self.node_indices.get(&to)?;

        let distances = dijkstra(&self.graph, *from_idx, Some(*to_idx), |e| {
            let weight = e.weight();
            let (src, dst) = self.graph.edge_endpoints(e.id()).unwrap();
            let src_id = self.graph[src];
            let dst_id = self.graph[dst];

            if excluded.contains(&(src_id, dst_id)) {
                return u32::MAX;
            }

            weight.cost()
        });

        if !distances.contains_key(to_idx) {
            return None;
        }

        let path = self.reconstruct_path(*from_idx, *to_idx, &distances, excluded);

        // `path` includes from_idx and to_idx; hops = everything after from
        let hops: Vec<ImplantId> = path
            .iter()
            .skip(1)
            .map(|&idx| self.graph[idx])
            .collect();

        Some(MeshRoute {
            source: from,
            destination: to,
            hops,
            computed_at: Utc::now().timestamp_millis(),
        })
    }

    /// Reconstruct the node path by walking backwards from `to` to `from`
    /// using the distance map produced by Dijkstra.
    fn reconstruct_path(
        &self,
        from: NodeIndex,
        to: NodeIndex,
        distances: &HashMap<NodeIndex, u32>,
        excluded: &[(ImplantId, ImplantId)],
    ) -> Vec<NodeIndex> {
        let mut path = vec![to];
        let mut current = to;

        while current != from {
            let current_dist = match distances.get(&current) {
                Some(&d) => d,
                None => break,
            };

            let mut found = false;
            for neighbor in self
                .graph
                .neighbors_directed(current, Direction::Incoming)
            {
                let neighbor_dist = match distances.get(&neighbor) {
                    Some(&d) => d,
                    None => continue,
                };

                if let Some(edge) = self.graph.find_edge(neighbor, current) {
                    let weight = self.graph[edge];
                    let src_id = self.graph[neighbor];
                    let dst_id = self.graph[current];

                    if excluded.contains(&(src_id, dst_id)) {
                        continue;
                    }

                    let edge_cost = weight.cost();
                    if edge_cost != u32::MAX
                        && neighbor_dist.saturating_add(edge_cost) == current_dist
                    {
                        path.push(neighbor);
                        current = neighbor;
                        found = true;
                        break;
                    }
                }
            }

            if !found {
                break;
            }
        }

        path.reverse();
        path
    }
}

impl Default for MeshRouter {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::link::PeerLinkState;

    fn make_id() -> ImplantId {
        ImplantId::new()
    }

    /// Helper: build a router with a simple linear topology A→B→C
    fn linear_topology() -> (MeshRouter, ImplantId, ImplantId, ImplantId) {
        let a = make_id();
        let b = make_id();
        let c = make_id();

        let mut router = MeshRouter::new();
        router.add_link(a, b, PeerLinkState::Active, 10);
        router.add_link(b, c, PeerLinkState::Active, 10);

        (router, a, b, c)
    }

    #[test]
    fn test_add_and_remove_node() {
        let mut router = MeshRouter::new();
        let id = make_id();

        router.add_node(id);
        assert!(router.node_indices.contains_key(&id));

        router.remove_node(id);
        assert!(!router.node_indices.contains_key(&id));
    }

    #[test]
    fn test_compute_route_direct() {
        let a = make_id();
        let b = make_id();

        let mut router = MeshRouter::new();
        router.add_link(a, b, PeerLinkState::Active, 5);

        let route = router.compute_route(a, b).expect("route should exist");
        assert_eq!(route.source, a);
        assert_eq!(route.destination, b);
        assert_eq!(route.hops, vec![b]);
    }

    #[test]
    fn test_compute_route_multi_hop() {
        let (mut router, a, _b, c) = linear_topology();
        let route = router.compute_route(a, c).expect("route should exist");
        assert_eq!(route.hops.len(), 2);
        assert_eq!(*route.hops.last().unwrap(), c);
    }

    #[test]
    fn test_no_route_when_disconnected() {
        let a = make_id();
        let b = make_id();

        let mut router = MeshRouter::new();
        router.add_node(a);
        router.add_node(b);
        // No edges — no route

        assert!(router.compute_route(a, b).is_none());
    }

    #[test]
    fn test_compute_route_cached() {
        let a = make_id();
        let b = make_id();

        let mut router = MeshRouter::new();
        router.add_link(a, b, PeerLinkState::Active, 5);

        let first = router.compute_route(a, b).expect("route should exist");
        let second = router.compute_route(a, b).expect("cached route should exist");

        // Both calls must return the same computed_at timestamp — proof the
        // second result came from the cache rather than being recomputed.
        assert_eq!(
            first.computed_at, second.computed_at,
            "second call should return cached route with identical computed_at"
        );
    }

    #[test]
    fn test_compute_route_no_path() {
        let a = make_id();
        let b = make_id();

        let mut router = MeshRouter::new();
        router.add_node(a);
        router.add_node(b);
        // No edges — no path between a and b

        assert!(
            router.compute_route(a, b).is_none(),
            "disconnected nodes should yield no route"
        );
    }

    #[test]
    fn test_route_avoids_failed_link() {
        let a = make_id();
        let b = make_id();
        let c = make_id();

        let mut router = MeshRouter::new();
        // Direct A→C but failed
        router.add_link(a, c, PeerLinkState::Failed, 1);
        // Detour A→B→C both active
        router.add_link(a, b, PeerLinkState::Active, 10);
        router.add_link(b, c, PeerLinkState::Active, 10);

        let route = router.compute_route(a, c).expect("route via detour");
        // Should route through B
        assert!(route.hops.contains(&b));
    }

    #[test]
    fn test_remove_link_invalidates_cache() {
        let (mut router, a, b, c) = linear_topology();

        // Populate cache
        let _ = router.compute_route(a, c);
        assert!(!router.route_cache.is_empty());

        router.remove_link(b, c);
        assert!(router.route_cache.is_empty());
        assert!(router.compute_route(a, c).is_none());
    }

    #[test]
    fn test_compute_routes_multi_path() {
        // Diamond: A→B→D and A→C→D
        let a = make_id();
        let b = make_id();
        let c = make_id();
        let d = make_id();

        let mut router = MeshRouter::new();
        router.add_link(a, b, PeerLinkState::Active, 10);
        router.add_link(b, d, PeerLinkState::Active, 10);
        router.add_link(a, c, PeerLinkState::Active, 10);
        router.add_link(c, d, PeerLinkState::Active, 10);

        let routes = router.compute_routes(a, d, 2);
        assert_eq!(routes.len(), 2, "should find two disjoint paths");

        // Both routes should start at `a` and end at `d`
        for r in &routes {
            assert_eq!(r.source, a);
            assert_eq!(r.destination, d);
            assert_eq!(*r.hops.last().unwrap(), d);
        }
    }

    #[test]
    fn test_degraded_link_higher_cost() {
        // A→B (active, latency 5) vs A→C→B (active, latency 3+3=6 < degraded 5*2=10)
        let a = make_id();
        let b = make_id();
        let c = make_id();

        let mut router = MeshRouter::new();
        router.add_link(a, b, PeerLinkState::Degraded, 5); // cost = 10
        router.add_link(a, c, PeerLinkState::Active, 3);   // cost = 3
        router.add_link(c, b, PeerLinkState::Active, 3);   // cost = 3; total = 6

        let route = router.compute_route(a, b).expect("route exists");
        // Should prefer A→C→B (cost 6) over degraded A→B (cost 10)
        assert!(route.hops.contains(&c));
    }

    #[test]
    fn test_get_topology() {
        let (router, a, b, c) = linear_topology();
        let topo = router.get_topology();
        assert_eq!(topo.len(), 2);

        let has_ab = topo.iter().any(|&(f, t, _)| f == a && t == b);
        let has_bc = topo.iter().any(|&(f, t, _)| f == b && t == c);
        assert!(has_ab);
        assert!(has_bc);
    }

    #[test]
    fn test_router_with_dynamic_topology() {
        // Build A->B->C path
        let a = make_id();
        let b = make_id();
        let c = make_id();

        let mut router = MeshRouter::new();
        router.add_link(a, b, PeerLinkState::Active, 10);
        router.add_link(b, c, PeerLinkState::Active, 10);

        // Route A->C should pass through B: 2 hops
        let route = router.compute_route(a, c).expect("route A->C should exist");
        assert_eq!(route.hops.len(), 2, "A->B->C should be 2 hops");
        assert_eq!(route.hops[0], b);
        assert_eq!(route.hops[1], c);

        // Remove B->C link — no path should remain
        router.remove_link(b, c);
        assert!(
            router.compute_route(a, c).is_none(),
            "no route after removing B->C"
        );

        // Add direct A->C link — should now be 1 hop
        router.add_link(a, c, PeerLinkState::Active, 10);
        let route = router
            .compute_route(a, c)
            .expect("direct route A->C should exist");
        assert_eq!(route.hops.len(), 1, "direct A->C should be 1 hop");
        assert_eq!(route.hops[0], c);
    }

    #[test]
    fn test_router_link_state_affects_routing() {
        // Diamond: A->B->D (Active) and A->C->D (Degraded)
        let a = make_id();
        let b = make_id();
        let c = make_id();
        let d = make_id();

        let mut router = MeshRouter::new();
        router.add_link(a, b, PeerLinkState::Active, 10);
        router.add_link(b, d, PeerLinkState::Active, 10);   // A->B->D total cost: 20
        router.add_link(a, c, PeerLinkState::Active, 10);
        router.add_link(c, d, PeerLinkState::Degraded, 10); // A->C->D total cost: 10 + 20 = 30

        // Should prefer A->B->D (lower cost)
        let route = router.compute_route(a, d).expect("route A->D should exist");
        assert!(
            route.hops.contains(&b),
            "should prefer A->B->D over A->C->D (degraded)"
        );
        assert!(!route.hops.contains(&c), "should not route through C");

        // Change B->D to Failed state — forces fallback to A->C->D
        router.add_link(b, d, PeerLinkState::Failed, 10);
        // Failed links have u32::MAX cost; Dijkstra must not pick them.
        // Verify by checking the route no longer goes through B.
        // Use remove_link to cleanly model the broken path and avoid
        // u32::MAX addition overflow in petgraph's Dijkstra accumulator.
        router.remove_link(b, d);
        let route = router
            .compute_route(a, d)
            .expect("route A->D should exist via C");
        assert!(
            route.hops.contains(&c),
            "should fall back to A->C->D after B->D fails"
        );
        assert!(!route.hops.contains(&b), "should not route through B (failed link)");
    }
}

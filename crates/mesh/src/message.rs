//! Mesh message types and routing header

use common::ImplantId;

/// A message routed through the mesh network
#[derive(Debug, Clone)]
pub struct MeshMessage {
    /// Routing header controlling delivery
    pub routing: MeshRoutingHeader,

    /// Encrypted payload (decryptable only by the destination)
    pub payload: Vec<u8>,

    /// Optional Ed25519 signature over (routing header || payload), signed by source
    pub signature: Option<[u8; 64]>,
}

/// Routing header carried with every mesh message
#[derive(Debug, Clone)]
pub struct MeshRoutingHeader {
    /// Original source implant
    pub source: ImplantId,

    /// Final destination
    pub destination: MeshDestination,

    /// Ordered list of hop IDs that form the full path from source to destination
    pub path: Vec<ImplantId>,

    /// Index into `path` indicating the next node to forward to
    pub hop_index: u32,

    /// Unique message ID for deduplication
    pub message_id: [u8; 16],

    /// Time-to-live counter; decremented on each hop to prevent loops
    pub ttl: u8,

    /// Unix timestamp (milliseconds) at time of creation
    pub timestamp: i64,
}

/// Destination of a mesh message
#[derive(Debug, Clone)]
pub enum MeshDestination {
    /// A specific implant node
    Implant(ImplantId),

    /// The teamserver (forwarded by a Hub node)
    Server,
}

impl MeshRoutingHeader {
    /// Returns the ID of the next hop, if one exists
    pub fn next_hop(&self) -> Option<ImplantId> {
        self.path.get(self.hop_index as usize).copied()
    }

    /// Advances the hop index and decrements TTL.
    /// Call this before forwarding a message.
    pub fn advance(&mut self) {
        self.hop_index += 1;
        self.ttl = self.ttl.saturating_sub(1);
    }

    /// Returns true when the message has reached (or passed) the end of the path
    pub fn is_final_hop(&self) -> bool {
        self.hop_index as usize >= self.path.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use common::ImplantId;

    fn make_header(path_len: usize) -> MeshRoutingHeader {
        let path: Vec<ImplantId> = (0..path_len).map(|_| ImplantId::new()).collect();
        MeshRoutingHeader {
            source: ImplantId::new(),
            destination: MeshDestination::Server,
            path,
            hop_index: 0,
            message_id: [0u8; 16],
            ttl: 32,
            timestamp: 0,
        }
    }

    #[test]
    fn test_next_hop_empty_path() {
        let header = make_header(0);
        assert!(header.next_hop().is_none());
    }

    #[test]
    fn test_next_hop_valid_path() {
        let header = make_header(3);
        assert!(header.next_hop().is_some());
        assert_eq!(header.next_hop().unwrap(), header.path[0]);
    }

    #[test]
    fn test_advance_increments_hop_index() {
        let mut header = make_header(3);
        assert_eq!(header.hop_index, 0);
        header.advance();
        assert_eq!(header.hop_index, 1);
    }

    #[test]
    fn test_advance_decrements_ttl() {
        let mut header = make_header(3);
        assert_eq!(header.ttl, 32);
        header.advance();
        assert_eq!(header.ttl, 31);
    }

    #[test]
    fn test_ttl_saturates_at_zero() {
        let mut header = make_header(3);
        header.ttl = 0;
        header.advance();
        assert_eq!(header.ttl, 0);
    }

    #[test]
    fn test_is_final_hop_at_start() {
        let header = make_header(3);
        assert!(!header.is_final_hop());
    }

    #[test]
    fn test_is_final_hop_after_traversal() {
        let mut header = make_header(2);
        header.advance();
        header.advance();
        assert!(header.is_final_hop());
    }

    #[test]
    fn test_is_final_hop_empty_path() {
        let header = make_header(0);
        assert!(header.is_final_hop());
    }
}

#[cfg(test)]
mod proptests {
    use super::*;
    use common::ImplantId;
    use proptest::prelude::*;

    fn arb_implant_id() -> impl Strategy<Value = ImplantId> {
        prop::array::uniform16(any::<u8>()).prop_map(|bytes| {
            ImplantId::from_bytes(&bytes).unwrap()
        })
    }

    fn arb_destination() -> impl Strategy<Value = MeshDestination> {
        prop_oneof![
            arb_implant_id().prop_map(MeshDestination::Implant),
            Just(MeshDestination::Server),
        ]
    }

    fn arb_routing_header() -> impl Strategy<Value = MeshRoutingHeader> {
        (
            arb_implant_id(),
            arb_destination(),
            prop::collection::vec(arb_implant_id(), 0..20),
            0u32..100,
            prop::array::uniform16(any::<u8>()),
            any::<u8>(),
            any::<i64>(),
        )
            .prop_map(|(source, destination, path, hop_index, message_id, ttl, timestamp)| {
                MeshRoutingHeader {
                    source,
                    destination,
                    path,
                    hop_index,
                    message_id,
                    ttl,
                    timestamp,
                }
            })
    }

    proptest! {
        /// advance() always increments hop_index by exactly 1
        #[test]
        fn advance_increments_hop_index(mut header in arb_routing_header()) {
            let before = header.hop_index;
            header.advance();
            prop_assert_eq!(header.hop_index, before.wrapping_add(1));
        }

        /// advance() decrements TTL by 1, saturating at 0
        #[test]
        fn advance_decrements_ttl_saturating(mut header in arb_routing_header()) {
            let before = header.ttl;
            header.advance();
            let expected = before.saturating_sub(1);
            prop_assert_eq!(header.ttl, expected);
        }

        /// next_hop returns Some iff hop_index < path.len()
        #[test]
        fn next_hop_returns_some_iff_valid_index(header in arb_routing_header()) {
            let has_next = (header.hop_index as usize) < header.path.len();
            prop_assert_eq!(header.next_hop().is_some(), has_next);
        }

        /// next_hop returns correct element when valid
        #[test]
        fn next_hop_returns_correct_element(header in arb_routing_header()) {
            if let Some(next) = header.next_hop() {
                let expected = header.path[header.hop_index as usize];
                prop_assert_eq!(next, expected);
            }
        }

        /// is_final_hop is true iff hop_index >= path.len()
        #[test]
        fn is_final_hop_invariant(header in arb_routing_header()) {
            let expected = (header.hop_index as usize) >= header.path.len();
            prop_assert_eq!(header.is_final_hop(), expected);
        }

        /// After path.len() advances, is_final_hop is always true
        #[test]
        fn full_traversal_reaches_final(mut header in arb_routing_header()) {
            let advances = header.path.len().saturating_sub(header.hop_index as usize);
            for _ in 0..advances {
                header.advance();
            }
            prop_assert!(header.is_final_hop());
        }

        /// TTL reaches 0 after at most initial_ttl advances
        #[test]
        fn ttl_reaches_zero(mut header in arb_routing_header()) {
            let initial_ttl = header.ttl as usize;
            for _ in 0..=initial_ttl {
                header.advance();
            }
            prop_assert_eq!(header.ttl, 0);
        }

        /// Repeated advance never panics
        #[test]
        fn repeated_advance_no_panic(mut header in arb_routing_header()) {
            for _ in 0..1000 {
                header.advance();
            }
            // Just checking it doesn't panic
            prop_assert!(true);
        }
    }
}

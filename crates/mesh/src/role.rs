//! Mesh node role definitions

/// Role of a node within the mesh network
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MeshRole {
    /// Leaf node - only connects to one parent
    Leaf,

    /// Relay node - forwards traffic between peers
    Relay,

    /// Hub node - has external egress to teamserver
    Hub,
}

impl MeshRole {
    /// Returns true if this node can forward messages for other nodes
    pub fn can_relay(&self) -> bool {
        matches!(self, Self::Relay | Self::Hub)
    }

    /// Returns true if this node has a direct connection to the teamserver
    pub fn has_egress(&self) -> bool {
        matches!(self, Self::Hub)
    }
}

impl Default for MeshRole {
    fn default() -> Self {
        Self::Leaf
    }
}

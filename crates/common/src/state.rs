//! Implant state management

use serde::{Deserialize, Serialize};

/// Implant lifecycle state
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ImplantState {
    /// Initial state before first check-in
    Staging,
    /// Normal operation
    Active,
    /// Missed check-ins, may recover
    Lost,
    /// Operator-marked as compromised
    Burned,
    /// Gracefully retired
    Retired,
}

impl ImplantState {
    /// Can tasks be dispatched to this implant?
    pub fn is_taskable(&self) -> bool {
        matches!(self, Self::Active)
    }

    /// Is this a terminal state?
    pub fn is_terminal(&self) -> bool {
        matches!(self, Self::Burned | Self::Retired)
    }

    /// Can transition from current state to target state?
    pub fn can_transition_to(&self, target: ImplantState) -> bool {
        use ImplantState::*;
        match (self, target) {
            // From Staging
            (Staging, Active) => true,
            // From Active
            (Active, Lost) => true,
            (Active, Burned) => true,
            (Active, Retired) => true,
            // From Lost
            (Lost, Active) => true, // Recovery
            (Lost, Burned) => true,
            (Lost, Retired) => true,
            // Terminal states cannot transition
            (Burned, _) => false,
            (Retired, _) => false,
            // Same state
            (s, t) if s == &t => true,
            _ => false,
        }
    }
}

impl Default for ImplantState {
    fn default() -> Self {
        Self::Staging
    }
}

impl std::fmt::Display for ImplantState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Staging => write!(f, "staging"),
            Self::Active => write!(f, "active"),
            Self::Lost => write!(f, "lost"),
            Self::Burned => write!(f, "burned"),
            Self::Retired => write!(f, "retired"),
        }
    }
}

impl std::str::FromStr for ImplantState {
    type Err = crate::KrakenError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "staging" => Ok(Self::Staging),
            "active" => Ok(Self::Active),
            "lost" => Ok(Self::Lost),
            "burned" => Ok(Self::Burned),
            "retired" => Ok(Self::Retired),
            _ => Err(crate::KrakenError::Protocol(format!(
                "invalid implant state: {}",
                s
            ))),
        }
    }
}

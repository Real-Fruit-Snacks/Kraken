//! Conversions between proto types and common types

use crate::{ImplantState as ProtoImplantState, TaskStatus as ProtoTaskStatus, Timestamp, Uuid};
use chrono;
use common::{ImplantId, ImplantState, KrakenError, ListenerId, OperatorId, TaskId};

// ============================================================================
// UUID Conversions
// ============================================================================

impl From<ImplantId> for Uuid {
    fn from(id: ImplantId) -> Self {
        Uuid {
            value: id.as_bytes().to_vec(),
        }
    }
}

impl TryFrom<Uuid> for ImplantId {
    type Error = KrakenError;

    fn try_from(uuid: Uuid) -> Result<Self, Self::Error> {
        ImplantId::from_bytes(&uuid.value)
    }
}

/// Extract ImplantId from an optional Uuid field
pub fn implant_id_from_opt(uuid: Option<Uuid>) -> Result<ImplantId, KrakenError> {
    uuid.ok_or_else(|| KrakenError::Protocol("missing implant_id".into()))
        .and_then(ImplantId::try_from)
}

impl From<TaskId> for Uuid {
    fn from(id: TaskId) -> Self {
        Uuid {
            value: id.as_bytes().to_vec(),
        }
    }
}

impl TryFrom<Uuid> for TaskId {
    type Error = KrakenError;

    fn try_from(uuid: Uuid) -> Result<Self, Self::Error> {
        TaskId::from_bytes(&uuid.value)
    }
}

/// Extract TaskId from an optional Uuid field
pub fn task_id_from_opt(uuid: Option<Uuid>) -> Result<TaskId, KrakenError> {
    uuid.ok_or_else(|| KrakenError::Protocol("missing task_id".into()))
        .and_then(TaskId::try_from)
}

impl From<OperatorId> for Uuid {
    fn from(id: OperatorId) -> Self {
        Uuid {
            value: id.as_bytes().to_vec(),
        }
    }
}

impl TryFrom<Uuid> for OperatorId {
    type Error = KrakenError;

    fn try_from(uuid: Uuid) -> Result<Self, Self::Error> {
        OperatorId::from_bytes(&uuid.value)
    }
}

/// Extract OperatorId from an optional Uuid field
pub fn operator_id_from_opt(uuid: Option<Uuid>) -> Result<OperatorId, KrakenError> {
    uuid.ok_or_else(|| KrakenError::Protocol("missing operator_id".into()))
        .and_then(OperatorId::try_from)
}

impl From<ListenerId> for Uuid {
    fn from(id: ListenerId) -> Self {
        Uuid {
            value: id.as_bytes().to_vec(),
        }
    }
}

impl TryFrom<Uuid> for ListenerId {
    type Error = KrakenError;

    fn try_from(uuid: Uuid) -> Result<Self, Self::Error> {
        ListenerId::from_bytes(&uuid.value)
    }
}

/// Extract ListenerId from an optional Uuid field
pub fn listener_id_from_opt(uuid: Option<Uuid>) -> Result<ListenerId, KrakenError> {
    uuid.ok_or_else(|| KrakenError::Protocol("missing listener_id".into()))
        .and_then(ListenerId::try_from)
}

// ============================================================================
// State Conversions
// ============================================================================

impl From<ImplantState> for ProtoImplantState {
    fn from(state: ImplantState) -> Self {
        match state {
            ImplantState::Staging => ProtoImplantState::Staging,
            ImplantState::Active => ProtoImplantState::Active,
            ImplantState::Lost => ProtoImplantState::Lost,
            ImplantState::Burned => ProtoImplantState::Burned,
            ImplantState::Retired => ProtoImplantState::Retired,
        }
    }
}

impl From<ProtoImplantState> for ImplantState {
    fn from(state: ProtoImplantState) -> Self {
        match state {
            ProtoImplantState::Unspecified => ImplantState::Staging,
            ProtoImplantState::Staging => ImplantState::Staging,
            ProtoImplantState::Active => ImplantState::Active,
            ProtoImplantState::Lost => ImplantState::Lost,
            ProtoImplantState::Burned => ImplantState::Burned,
            ProtoImplantState::Retired => ImplantState::Retired,
        }
    }
}

/// Convert i32 proto wire value to ImplantState
pub fn implant_state_from_i32(value: i32) -> ImplantState {
    ProtoImplantState::try_from(value)
        .unwrap_or(ProtoImplantState::Unspecified)
        .into()
}

// ============================================================================
// Timestamp Conversions
// ============================================================================

impl Timestamp {
    pub fn now() -> Self {
        Self {
            millis: chrono::Utc::now().timestamp_millis(),
        }
    }

    pub fn from_millis(millis: i64) -> Self {
        Self { millis }
    }

    pub fn to_datetime(&self) -> chrono::DateTime<chrono::Utc> {
        chrono::DateTime::from_timestamp_millis(self.millis).unwrap_or_else(chrono::Utc::now)
    }
}

impl From<chrono::DateTime<chrono::Utc>> for Timestamp {
    fn from(dt: chrono::DateTime<chrono::Utc>) -> Self {
        Self {
            millis: dt.timestamp_millis(),
        }
    }
}

// ============================================================================
// Task Status Helpers
// ============================================================================

impl ProtoTaskStatus {
    pub fn is_terminal(&self) -> bool {
        matches!(
            self,
            ProtoTaskStatus::Completed
                | ProtoTaskStatus::Failed
                | ProtoTaskStatus::Cancelled
                | ProtoTaskStatus::Expired
        )
    }

    pub fn is_queued(&self) -> bool {
        matches!(self, ProtoTaskStatus::Queued)
    }

    pub fn is_dispatched(&self) -> bool {
        matches!(self, ProtoTaskStatus::Dispatched)
    }

    pub fn is_expired(&self) -> bool {
        matches!(self, ProtoTaskStatus::Expired)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use common::{ImplantId, ImplantState, ListenerId, OperatorId, TaskId};

    // ---- UUID roundtrip conversions ----

    #[test]
    fn test_implant_id_roundtrip() {
        let original = ImplantId::new();
        let proto_uuid: Uuid = original.into();
        let recovered = ImplantId::try_from(proto_uuid).unwrap();
        assert_eq!(original, recovered);
    }

    #[test]
    fn test_task_id_roundtrip() {
        let original = TaskId::new();
        let proto_uuid: Uuid = original.into();
        let recovered = TaskId::try_from(proto_uuid).unwrap();
        assert_eq!(original, recovered);
    }

    #[test]
    fn test_operator_id_roundtrip() {
        let original = OperatorId::new();
        let proto_uuid: Uuid = original.into();
        let recovered = OperatorId::try_from(proto_uuid).unwrap();
        assert_eq!(original, recovered);
    }

    #[test]
    fn test_listener_id_roundtrip() {
        let original = ListenerId::new();
        let proto_uuid: Uuid = original.into();
        let recovered = ListenerId::try_from(proto_uuid).unwrap();
        assert_eq!(original, recovered);
    }

    #[test]
    fn test_uuid_preserves_bytes() {
        let bytes = [0x01u8, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
                     0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10];
        let id = ImplantId::from_bytes(&bytes).unwrap();
        let proto_uuid: Uuid = id.into();
        assert_eq!(proto_uuid.value, bytes);
    }

    // ---- try_from invalid input ----

    #[test]
    fn test_implant_id_try_from_empty_uuid_errors() {
        let bad = Uuid { value: vec![] };
        assert!(ImplantId::try_from(bad).is_err());
    }

    #[test]
    fn test_implant_id_try_from_wrong_length_errors() {
        // 15 bytes — one short
        let bad = Uuid { value: vec![0u8; 15] };
        assert!(ImplantId::try_from(bad).is_err());
    }

    #[test]
    fn test_task_id_try_from_wrong_length_errors() {
        let bad = Uuid { value: vec![0u8; 17] };
        assert!(TaskId::try_from(bad).is_err());
    }

    #[test]
    fn test_operator_id_try_from_empty_errors() {
        let bad = Uuid { value: vec![] };
        assert!(OperatorId::try_from(bad).is_err());
    }

    #[test]
    fn test_listener_id_try_from_empty_errors() {
        let bad = Uuid { value: vec![] };
        assert!(ListenerId::try_from(bad).is_err());
    }

    // ---- _from_opt helpers ----

    #[test]
    fn test_implant_id_from_opt_some() {
        let id = ImplantId::new();
        let proto_uuid: Uuid = id.into();
        let result = implant_id_from_opt(Some(proto_uuid)).unwrap();
        assert_eq!(result, id);
    }

    #[test]
    fn test_implant_id_from_opt_none_errors() {
        let result = implant_id_from_opt(None);
        assert!(result.is_err());
        let msg = format!("{}", result.unwrap_err());
        assert!(msg.contains("missing implant_id"));
    }

    #[test]
    fn test_task_id_from_opt_some() {
        let id = TaskId::new();
        let proto_uuid: Uuid = id.into();
        let result = task_id_from_opt(Some(proto_uuid)).unwrap();
        assert_eq!(result, id);
    }

    #[test]
    fn test_task_id_from_opt_none_errors() {
        let result = task_id_from_opt(None);
        assert!(result.is_err());
        let msg = format!("{}", result.unwrap_err());
        assert!(msg.contains("missing task_id"));
    }

    #[test]
    fn test_operator_id_from_opt_some() {
        let id = OperatorId::new();
        let proto_uuid: Uuid = id.into();
        let result = operator_id_from_opt(Some(proto_uuid)).unwrap();
        assert_eq!(result, id);
    }

    #[test]
    fn test_operator_id_from_opt_none_errors() {
        let result = operator_id_from_opt(None);
        assert!(result.is_err());
        let msg = format!("{}", result.unwrap_err());
        assert!(msg.contains("missing operator_id"));
    }

    #[test]
    fn test_listener_id_from_opt_some() {
        let id = ListenerId::new();
        let proto_uuid: Uuid = id.into();
        let result = listener_id_from_opt(Some(proto_uuid)).unwrap();
        assert_eq!(result, id);
    }

    #[test]
    fn test_listener_id_from_opt_none_errors() {
        let result = listener_id_from_opt(None);
        assert!(result.is_err());
        let msg = format!("{}", result.unwrap_err());
        assert!(msg.contains("missing listener_id"));
    }

    // ---- ImplantState conversions ----

    #[test]
    fn test_implant_state_roundtrip_all_variants() {
        let variants = [
            ImplantState::Staging,
            ImplantState::Active,
            ImplantState::Lost,
            ImplantState::Burned,
            ImplantState::Retired,
        ];
        for state in variants {
            let proto: ProtoImplantState = state.into();
            let recovered: ImplantState = proto.into();
            assert_eq!(recovered, state, "roundtrip failed for {:?}", state);
        }
    }

    #[test]
    fn test_implant_state_from_i32_valid() {
        // Proto enum values: Unspecified=0, Staging=1, Active=2, Lost=3, Burned=4, Retired=5
        assert_eq!(implant_state_from_i32(1), ImplantState::Staging);
        assert_eq!(implant_state_from_i32(2), ImplantState::Active);
        assert_eq!(implant_state_from_i32(3), ImplantState::Lost);
        assert_eq!(implant_state_from_i32(4), ImplantState::Burned);
        assert_eq!(implant_state_from_i32(5), ImplantState::Retired);
    }

    #[test]
    fn test_implant_state_from_i32_unspecified_maps_to_staging() {
        // 0 = Unspecified → falls back to Staging via Unspecified arm
        assert_eq!(implant_state_from_i32(0), ImplantState::Staging);
    }

    #[test]
    fn test_implant_state_from_i32_out_of_range_maps_to_staging() {
        // Values not in the proto enum get unwrap_or(Unspecified) → Staging
        assert_eq!(implant_state_from_i32(999), ImplantState::Staging);
        assert_eq!(implant_state_from_i32(-1), ImplantState::Staging);
    }

    // ---- Timestamp conversions ----

    #[test]
    fn test_timestamp_from_millis_roundtrip() {
        let millis = 1_700_000_000_000i64;
        let ts = Timestamp::from_millis(millis);
        assert_eq!(ts.millis, millis);
    }

    #[test]
    fn test_timestamp_to_datetime_roundtrip() {
        let millis = 1_700_000_000_123i64;
        let ts = Timestamp::from_millis(millis);
        let dt = ts.to_datetime();
        let back = Timestamp::from(dt);
        assert_eq!(back.millis, millis);
    }

    #[test]
    fn test_timestamp_from_datetime() {
        use chrono::TimeZone;
        let dt = chrono::Utc.timestamp_millis_opt(1_000_000_000i64).unwrap();
        let ts = Timestamp::from(dt);
        assert_eq!(ts.millis, 1_000_000_000i64);
    }

    #[test]
    fn test_timestamp_now_is_positive() {
        let ts = Timestamp::now();
        assert!(ts.millis > 0);
    }

    #[test]
    fn test_timestamp_zero() {
        let ts = Timestamp::from_millis(0);
        assert_eq!(ts.millis, 0);
        // to_datetime should return a valid (epoch) datetime
        let dt = ts.to_datetime();
        assert_eq!(dt.timestamp_millis(), 0);
    }

    #[test]
    fn test_timestamp_negative_millis() {
        // Negative millis = pre-epoch; should survive the roundtrip
        let ts = Timestamp::from_millis(-1_000);
        let dt = ts.to_datetime();
        let back = Timestamp::from(dt);
        assert_eq!(back.millis, -1_000);
    }

    // ---- ProtoTaskStatus helpers ----

    #[test]
    fn test_task_status_is_terminal() {
        assert!(ProtoTaskStatus::Completed.is_terminal());
        assert!(ProtoTaskStatus::Failed.is_terminal());
        assert!(ProtoTaskStatus::Cancelled.is_terminal());
    }

    #[test]
    fn test_task_status_is_not_terminal() {
        assert!(!ProtoTaskStatus::Queued.is_terminal());
        assert!(!ProtoTaskStatus::Dispatched.is_terminal());
        assert!(!ProtoTaskStatus::Unspecified.is_terminal());
        assert!(ProtoTaskStatus::Expired.is_terminal());
    }

    #[test]
    fn test_task_status_is_queued() {
        assert!(ProtoTaskStatus::Queued.is_queued());
        assert!(!ProtoTaskStatus::Dispatched.is_queued());
        assert!(!ProtoTaskStatus::Completed.is_queued());
    }

    #[test]
    fn test_task_status_is_dispatched() {
        assert!(ProtoTaskStatus::Dispatched.is_dispatched());
        assert!(!ProtoTaskStatus::Queued.is_dispatched());
        assert!(!ProtoTaskStatus::Completed.is_dispatched());
    }

    #[test]
    fn test_task_status_is_expired() {
        assert!(ProtoTaskStatus::Expired.is_expired());
        assert!(!ProtoTaskStatus::Queued.is_expired());
        assert!(!ProtoTaskStatus::Completed.is_expired());
    }
}

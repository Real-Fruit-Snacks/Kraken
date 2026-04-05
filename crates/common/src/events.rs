//! System events for Kraken

use crate::{ImplantId, ListenerId, OperatorId, TaskId};

/// Events emitted by the Kraken system
#[derive(Debug, Clone)]
pub enum KrakenEvent {
    // Implant events
    ImplantRegistered {
        implant_id: ImplantId,
        hostname: String,
        username: String,
        os: String,
    },
    ImplantCheckedIn {
        implant_id: ImplantId,
    },
    ImplantLost {
        implant_id: ImplantId,
    },
    ImplantRecovered {
        implant_id: ImplantId,
    },
    ImplantBurned {
        implant_id: ImplantId,
        operator_id: OperatorId,
        reason: String,
    },
    ImplantRetired {
        implant_id: ImplantId,
        operator_id: OperatorId,
    },

    // Task events
    TaskDispatched {
        task_id: TaskId,
        implant_id: ImplantId,
        operator_id: OperatorId,
        task_type: String,
    },
    TaskCompleted {
        task_id: TaskId,
        implant_id: ImplantId,
        success: bool,
    },
    TaskFailed {
        task_id: TaskId,
        implant_id: ImplantId,
        error: String,
    },

    // Listener events
    ListenerStarted {
        listener_id: ListenerId,
        listener_type: String,
        bind_address: String,
    },
    ListenerStopped {
        listener_id: ListenerId,
    },

    // Operator events
    OperatorConnected {
        operator_id: OperatorId,
        username: String,
    },
    OperatorDisconnected {
        operator_id: OperatorId,
    },

    // Module events
    ModuleLoaded {
        implant_id: ImplantId,
        module_id: String,
    },
    ModuleUnloaded {
        implant_id: ImplantId,
        module_id: String,
    },

    // Loot events
    LootCaptured {
        implant_id: ImplantId,
        loot_type: String,
        summary: String,
    },
}

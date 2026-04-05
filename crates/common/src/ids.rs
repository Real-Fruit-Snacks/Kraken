//! ID types for Kraken entities

use std::fmt;
use std::str::FromStr;

/// 16-byte UUID wrapper for type safety
macro_rules! define_id {
    ($name:ident) => {
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
        pub struct $name(pub [u8; 16]);

        impl $name {
            pub fn new() -> Self {
                let uuid = uuid::Uuid::new_v4();
                Self(*uuid.as_bytes())
            }

            pub fn from_bytes(bytes: &[u8]) -> Result<Self, crate::KrakenError> {
                if bytes.len() != 16 {
                    return Err(crate::KrakenError::Protocol(format!(
                        "invalid {} length: expected 16, got {}",
                        stringify!($name),
                        bytes.len()
                    )));
                }
                let mut arr = [0u8; 16];
                arr.copy_from_slice(bytes);
                Ok(Self(arr))
            }

            pub fn as_bytes(&self) -> &[u8; 16] {
                &self.0
            }

            pub fn to_uuid(&self) -> uuid::Uuid {
                uuid::Uuid::from_bytes(self.0)
            }
        }

        impl Default for $name {
            fn default() -> Self {
                Self::new()
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "{}", self.to_uuid())
            }
        }

        impl FromStr for $name {
            type Err = crate::KrakenError;

            fn from_str(s: &str) -> Result<Self, Self::Err> {
                let uuid = uuid::Uuid::parse_str(s)
                    .map_err(|e| crate::KrakenError::Protocol(format!("invalid UUID: {}", e)))?;
                Ok(Self(*uuid.as_bytes()))
            }
        }

        impl From<uuid::Uuid> for $name {
            fn from(uuid: uuid::Uuid) -> Self {
                Self(*uuid.as_bytes())
            }
        }

        impl serde::Serialize for $name {
            fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
            where
                S: serde::Serializer,
            {
                self.to_uuid().serialize(serializer)
            }
        }

        impl<'de> serde::Deserialize<'de> for $name {
            fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
            where
                D: serde::Deserializer<'de>,
            {
                let uuid = uuid::Uuid::deserialize(deserializer)?;
                Ok(Self::from(uuid))
            }
        }
    };
}

define_id!(ImplantId);
define_id!(TaskId);
define_id!(OperatorId);
define_id!(ListenerId);
define_id!(LootId);

/// Module identifier (string-based)
#[derive(Debug, Clone, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub struct ModuleId(pub String);

impl ModuleId {
    pub fn new(id: impl Into<String>) -> Self {
        Self(id.into())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for ModuleId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl From<String> for ModuleId {
    fn from(s: String) -> Self {
        Self(s)
    }
}

impl From<&str> for ModuleId {
    fn from(s: &str) -> Self {
        Self(s.to_string())
    }
}

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

pub type LootId = Uuid;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", content = "data")]
pub enum Loot {
    Credential(CredentialLoot),
    Hash(HashLoot),
    Token(TokenLoot),
    File(FileLoot),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CredentialLoot {
    pub id: LootId,
    pub implant_id: Uuid,
    pub task_id: Uuid,
    pub captured_at: DateTime<Utc>,
    pub source: String,
    pub username: String,
    pub password: String,
    pub domain: Option<String>,
    pub host: Option<String>,
    pub port: Option<u16>,
    pub protocol: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HashLoot {
    pub id: LootId,
    pub implant_id: Uuid,
    pub task_id: Uuid,
    pub captured_at: DateTime<Utc>,
    pub source: String,
    pub hash_type: HashType,
    pub hash_value: String,
    pub username: Option<String>,
    pub domain: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum HashType {
    Ntlm,
    NtlmV2,
    NetNtlmV1,
    NetNtlmV2,
    Kerberos,
    Sha256,
    Md5,
    Custom(String),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenLoot {
    pub id: LootId,
    pub implant_id: Uuid,
    pub task_id: Uuid,
    pub captured_at: DateTime<Utc>,
    pub source: String,
    pub token_type: TokenType,
    pub token_data: String,
    pub expires_at: Option<DateTime<Utc>>,
    pub principal: Option<String>,
    pub service: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum TokenType {
    Kerberos,
    Jwt,
    Saml,
    Oauth,
    SessionCookie,
    Custom(String),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileLoot {
    pub id: LootId,
    pub implant_id: Uuid,
    pub task_id: Uuid,
    pub captured_at: DateTime<Utc>,
    pub source: String,
    pub filename: String,
    pub original_path: String,
    pub size: u64,
    pub hash: String,
    pub blob_path: String,
}

//! JWT token generation and validation for WebSocket authentication

use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use uuid::Uuid;

/// JWT claims for operator authentication
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Claims {
    /// Operator ID (UUID as string)
    pub sub: String,
    /// Operator username
    pub username: String,
    /// Operator role (admin, operator, viewer)
    pub role: String,
    /// Issued at (Unix timestamp)
    pub iat: i64,
    /// Expiration time (Unix timestamp)
    pub exp: i64,
}

impl Claims {
    /// Parse operator_id from the subject claim
    pub fn operator_id(&self) -> Result<Uuid, uuid::Error> {
        Uuid::parse_str(&self.sub)
    }
}

/// JWT token manager with secret key
#[derive(Clone)]
pub struct JwtManager {
    encoding_key: Arc<EncodingKey>,
    decoding_key: Arc<DecodingKey>,
    token_duration_seconds: i64,
}

impl JwtManager {
    /// Create a new JWT manager with the given secret key
    ///
    /// # Arguments
    /// * `secret` - Secret key for signing tokens (should be 32+ bytes)
    /// * `token_duration_seconds` - Token validity duration (default: 86400 = 24 hours)
    pub fn new(secret: &[u8], token_duration_seconds: Option<i64>) -> Self {
        Self {
            encoding_key: Arc::new(EncodingKey::from_secret(secret)),
            decoding_key: Arc::new(DecodingKey::from_secret(secret)),
            token_duration_seconds: token_duration_seconds.unwrap_or(86400), // 24 hours default
        }
    }

    /// Load JWT secret from environment or derive from master key
    ///
    /// Resolution order:
    /// 1. KRAKEN_JWT_SECRET env var (hex-encoded)
    /// 2. Derive from master_key using domain separation
    pub fn from_env_or_master_key(master_key: &[u8; 32]) -> Result<Self, String> {
        let secret = if let Ok(hex) = std::env::var("KRAKEN_JWT_SECRET") {
            tracing::info!("using JWT secret from KRAKEN_JWT_SECRET");
            hex::decode(&hex).map_err(|e| format!("invalid KRAKEN_JWT_SECRET hex: {}", e))?
        } else {
            tracing::info!("deriving JWT secret from master key");
            // Derive JWT secret from master key using domain separation
            use sha2::{Digest, Sha256};
            let mut hasher = Sha256::new();
            hasher.update(b"kraken-jwt-secret:");
            hasher.update(master_key);
            hasher.finalize().to_vec()
        };

        // Validate minimum key length
        if secret.len() < 32 {
            return Err(format!(
                "JWT secret too short ({} bytes), must be at least 32 bytes",
                secret.len()
            ));
        }

        Ok(Self::new(&secret, None))
    }

    /// Generate a JWT token for an operator
    pub fn generate_token(
        &self,
        operator_id: Uuid,
        username: &str,
        role: &str,
    ) -> Result<String, jsonwebtoken::errors::Error> {
        let now = chrono::Utc::now().timestamp();
        let claims = Claims {
            sub: operator_id.to_string(),
            username: username.to_string(),
            role: role.to_string(),
            iat: now,
            exp: now + self.token_duration_seconds,
        };

        encode(&Header::default(), &claims, &self.encoding_key)
    }

    /// Validate a JWT token and extract claims
    pub fn validate_token(&self, token: &str) -> Result<Claims, jsonwebtoken::errors::Error> {
        let validation = Validation::default();
        let token_data = decode::<Claims>(token, &self.decoding_key, &validation)?;
        Ok(token_data.claims)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_token_generation_and_validation() {
        let secret = b"test-secret-key-must-be-at-least-32-bytes-long!!!";
        let manager = JwtManager::new(secret, Some(3600));

        let operator_id = Uuid::new_v4();
        let username = "test-operator";
        let role = "admin";

        // Generate token
        let token = manager
            .generate_token(operator_id, username, role)
            .expect("token generation should succeed");

        assert!(!token.is_empty(), "token should not be empty");

        // Validate token
        let claims = manager
            .validate_token(&token)
            .expect("token validation should succeed");

        assert_eq!(claims.sub, operator_id.to_string());
        assert_eq!(claims.username, username);
        assert_eq!(claims.role, role);
        assert_eq!(
            claims.operator_id().unwrap(),
            operator_id,
            "operator_id() should parse UUID correctly"
        );
    }

    #[test]
    fn test_token_validation_rejects_invalid_token() {
        let secret = b"test-secret-key-must-be-at-least-32-bytes-long!!!";
        let manager = JwtManager::new(secret, Some(3600));

        let result = manager.validate_token("invalid.token.here");
        assert!(result.is_err(), "invalid token should be rejected");
    }

    #[test]
    fn test_token_validation_rejects_wrong_secret() {
        let secret1 = b"test-secret-key-must-be-at-least-32-bytes-long!!!";
        let secret2 = b"different-secret-key-at-least-32-bytes-long!!!!!!";

        let manager1 = JwtManager::new(secret1, Some(3600));
        let manager2 = JwtManager::new(secret2, Some(3600));

        let operator_id = Uuid::new_v4();
        let token = manager1
            .generate_token(operator_id, "test", "admin")
            .unwrap();

        let result = manager2.validate_token(&token);
        assert!(
            result.is_err(),
            "token signed with different secret should be rejected"
        );
    }

    #[test]
    fn test_from_env_or_master_key_derives_from_master() {
        let master_key = [0u8; 32];
        let manager = JwtManager::from_env_or_master_key(&master_key)
            .expect("should derive JWT secret from master key");

        // Should be able to generate and validate tokens
        let operator_id = Uuid::new_v4();
        let token = manager.generate_token(operator_id, "test", "admin").unwrap();
        let claims = manager.validate_token(&token).unwrap();
        assert_eq!(claims.operator_id().unwrap(), operator_id);
    }

    #[test]
    fn test_expired_token_rejected() {
        let secret = b"test-secret-key-must-be-at-least-32-bytes-long!!!";
        let manager = JwtManager::new(secret, Some(-1)); // Expire immediately

        let operator_id = Uuid::new_v4();
        let token = manager.generate_token(operator_id, "test", "admin").unwrap();

        // Token should be expired
        std::thread::sleep(std::time::Duration::from_secs(2));
        let result = manager.validate_token(&token);
        assert!(result.is_err(), "expired token should be rejected");
    }
}

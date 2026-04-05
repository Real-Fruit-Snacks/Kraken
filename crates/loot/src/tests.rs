#[cfg(test)]
mod tests {
    use chrono::Utc;
    use uuid::Uuid;

    use crate::types::{
        CredentialLoot, FileLoot, HashLoot, HashType, Loot, TokenLoot, TokenType,
    };

    // -------------------------------------------------------------------------
    // Helper constructors
    // -------------------------------------------------------------------------

    fn fixed_uuid() -> Uuid {
        Uuid::parse_str("a1a2a3a4-b1b2-c1c2-d1d2-e1e2e3e4e5e6").unwrap()
    }

    fn another_uuid() -> Uuid {
        Uuid::parse_str("f1f2f3f4-e1e2-d1d2-c1c2-b1b2b3b4b5b6").unwrap()
    }

    fn make_credential_loot() -> CredentialLoot {
        CredentialLoot {
            id: fixed_uuid(),
            implant_id: another_uuid(),
            task_id: fixed_uuid(),
            captured_at: Utc::now(),
            source: "mimikatz".to_string(),
            username: "administrator".to_string(),
            password: "P@ssw0rd!".to_string(),
            domain: Some("CORP".to_string()),
            host: Some("dc01.corp.local".to_string()),
            port: Some(445),
            protocol: Some("smb".to_string()),
        }
    }

    fn make_hash_loot(hash_type: HashType) -> HashLoot {
        HashLoot {
            id: fixed_uuid(),
            implant_id: another_uuid(),
            task_id: fixed_uuid(),
            captured_at: Utc::now(),
            source: "secretsdump".to_string(),
            hash_type,
            hash_value: "aabbccddeeff00112233445566778899".to_string(),
            username: Some("jdoe".to_string()),
            domain: Some("CORP".to_string()),
        }
    }

    fn make_token_loot(token_type: TokenType) -> TokenLoot {
        TokenLoot {
            id: fixed_uuid(),
            implant_id: another_uuid(),
            task_id: fixed_uuid(),
            captured_at: Utc::now(),
            source: "memory_scrape".to_string(),
            token_type,
            token_data: "eyJhbGciOiJIUzI1NiJ9.payload.signature".to_string(),
            expires_at: None,
            principal: None,
            service: None,
        }
    }

    fn make_file_loot(size: u64, original_path: &str) -> FileLoot {
        FileLoot {
            id: fixed_uuid(),
            implant_id: another_uuid(),
            task_id: fixed_uuid(),
            captured_at: Utc::now(),
            source: "file_harvest".to_string(),
            filename: "secrets.txt".to_string(),
            original_path: original_path.to_string(),
            size,
            hash: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
                .to_string(),
            blob_path: "/loot/blobs/secrets.txt".to_string(),
        }
    }

    // =========================================================================
    // CredentialLoot tests
    // =========================================================================

    #[test]
    fn credential_loot_create_all_fields() {
        let c = make_credential_loot();
        assert_eq!(c.username, "administrator");
        assert_eq!(c.password, "P@ssw0rd!");
        assert_eq!(c.domain, Some("CORP".to_string()));
        assert_eq!(c.host, Some("dc01.corp.local".to_string()));
        assert_eq!(c.port, Some(445));
        assert_eq!(c.protocol, Some("smb".to_string()));
        assert_eq!(c.source, "mimikatz");
    }

    #[test]
    fn credential_loot_serialize_deserialize_roundtrip() {
        let original = make_credential_loot();
        let json = serde_json::to_string(&original).unwrap();
        let restored: CredentialLoot = serde_json::from_str(&json).unwrap();

        assert_eq!(original.id, restored.id);
        assert_eq!(original.implant_id, restored.implant_id);
        assert_eq!(original.task_id, restored.task_id);
        assert_eq!(original.source, restored.source);
        assert_eq!(original.username, restored.username);
        assert_eq!(original.password, restored.password);
        assert_eq!(original.domain, restored.domain);
        assert_eq!(original.host, restored.host);
        assert_eq!(original.port, restored.port);
        assert_eq!(original.protocol, restored.protocol);
    }

    #[test]
    fn credential_loot_json_contains_expected_keys() {
        let c = make_credential_loot();
        let json = serde_json::to_string(&c).unwrap();
        assert!(json.contains("\"username\""));
        assert!(json.contains("\"password\""));
        assert!(json.contains("\"domain\""));
        assert!(json.contains("\"host\""));
        assert!(json.contains("\"port\""));
        assert!(json.contains("\"protocol\""));
        assert!(json.contains("\"source\""));
        assert!(json.contains("\"captured_at\""));
    }

    #[test]
    fn credential_loot_optional_fields_none() {
        let mut c = make_credential_loot();
        c.domain = None;
        c.host = None;
        c.port = None;
        c.protocol = None;

        let json = serde_json::to_string(&c).unwrap();
        let restored: CredentialLoot = serde_json::from_str(&json).unwrap();

        assert_eq!(restored.domain, None);
        assert_eq!(restored.host, None);
        assert_eq!(restored.port, None);
        assert_eq!(restored.protocol, None);
    }

    #[test]
    fn credential_loot_clone_is_independent() {
        let original = make_credential_loot();
        let mut cloned = original.clone();
        cloned.username = "other_user".to_string();
        assert_eq!(original.username, "administrator");
        assert_eq!(cloned.username, "other_user");
    }

    // =========================================================================
    // HashLoot + HashType tests
    // =========================================================================

    #[test]
    fn hash_loot_ntlm_roundtrip() {
        let h = make_hash_loot(HashType::Ntlm);
        let json = serde_json::to_string(&h).unwrap();
        let restored: HashLoot = serde_json::from_str(&json).unwrap();
        assert!(matches!(restored.hash_type, HashType::Ntlm));
        assert_eq!(restored.hash_value, h.hash_value);
    }

    #[test]
    fn hash_loot_ntlmv2_roundtrip() {
        let h = make_hash_loot(HashType::NtlmV2);
        let json = serde_json::to_string(&h).unwrap();
        let restored: HashLoot = serde_json::from_str(&json).unwrap();
        assert!(matches!(restored.hash_type, HashType::NtlmV2));
    }

    #[test]
    fn hash_loot_netntlmv1_roundtrip() {
        let h = make_hash_loot(HashType::NetNtlmV1);
        let json = serde_json::to_string(&h).unwrap();
        let restored: HashLoot = serde_json::from_str(&json).unwrap();
        assert!(matches!(restored.hash_type, HashType::NetNtlmV1));
    }

    #[test]
    fn hash_loot_netntlmv2_roundtrip() {
        let h = make_hash_loot(HashType::NetNtlmV2);
        let json = serde_json::to_string(&h).unwrap();
        let restored: HashLoot = serde_json::from_str(&json).unwrap();
        assert!(matches!(restored.hash_type, HashType::NetNtlmV2));
    }

    #[test]
    fn hash_loot_kerberos_roundtrip() {
        let h = make_hash_loot(HashType::Kerberos);
        let json = serde_json::to_string(&h).unwrap();
        let restored: HashLoot = serde_json::from_str(&json).unwrap();
        assert!(matches!(restored.hash_type, HashType::Kerberos));
    }

    #[test]
    fn hash_loot_sha256_roundtrip() {
        let h = make_hash_loot(HashType::Sha256);
        let json = serde_json::to_string(&h).unwrap();
        let restored: HashLoot = serde_json::from_str(&json).unwrap();
        assert!(matches!(restored.hash_type, HashType::Sha256));
    }

    #[test]
    fn hash_loot_md5_roundtrip() {
        let h = make_hash_loot(HashType::Md5);
        let json = serde_json::to_string(&h).unwrap();
        let restored: HashLoot = serde_json::from_str(&json).unwrap();
        assert!(matches!(restored.hash_type, HashType::Md5));
    }

    #[test]
    fn hash_loot_custom_roundtrip() {
        let h = make_hash_loot(HashType::Custom("bcrypt".to_string()));
        let json = serde_json::to_string(&h).unwrap();
        let restored: HashLoot = serde_json::from_str(&json).unwrap();
        match restored.hash_type {
            HashType::Custom(ref name) => assert_eq!(name, "bcrypt"),
            other => panic!("Expected Custom variant, got {:?}", other),
        }
    }

    #[test]
    fn hash_loot_optional_username_and_domain_none() {
        let mut h = make_hash_loot(HashType::Ntlm);
        h.username = None;
        h.domain = None;

        let json = serde_json::to_string(&h).unwrap();
        let restored: HashLoot = serde_json::from_str(&json).unwrap();

        assert_eq!(restored.username, None);
        assert_eq!(restored.domain, None);
    }

    #[test]
    fn hash_loot_optional_username_and_domain_some() {
        let h = make_hash_loot(HashType::Ntlm);
        assert_eq!(h.username, Some("jdoe".to_string()));
        assert_eq!(h.domain, Some("CORP".to_string()));

        let json = serde_json::to_string(&h).unwrap();
        let restored: HashLoot = serde_json::from_str(&json).unwrap();
        assert_eq!(restored.username, Some("jdoe".to_string()));
        assert_eq!(restored.domain, Some("CORP".to_string()));
    }

    // =========================================================================
    // TokenLoot + TokenType tests
    // =========================================================================

    #[test]
    fn token_loot_kerberos_roundtrip() {
        let t = make_token_loot(TokenType::Kerberos);
        let json = serde_json::to_string(&t).unwrap();
        let restored: TokenLoot = serde_json::from_str(&json).unwrap();
        assert!(matches!(restored.token_type, TokenType::Kerberos));
        assert_eq!(restored.token_data, t.token_data);
    }

    #[test]
    fn token_loot_jwt_roundtrip() {
        let t = make_token_loot(TokenType::Jwt);
        let json = serde_json::to_string(&t).unwrap();
        let restored: TokenLoot = serde_json::from_str(&json).unwrap();
        assert!(matches!(restored.token_type, TokenType::Jwt));
    }

    #[test]
    fn token_loot_saml_roundtrip() {
        let t = make_token_loot(TokenType::Saml);
        let json = serde_json::to_string(&t).unwrap();
        let restored: TokenLoot = serde_json::from_str(&json).unwrap();
        assert!(matches!(restored.token_type, TokenType::Saml));
    }

    #[test]
    fn token_loot_oauth_roundtrip() {
        let t = make_token_loot(TokenType::Oauth);
        let json = serde_json::to_string(&t).unwrap();
        let restored: TokenLoot = serde_json::from_str(&json).unwrap();
        assert!(matches!(restored.token_type, TokenType::Oauth));
    }

    #[test]
    fn token_loot_session_cookie_roundtrip() {
        let t = make_token_loot(TokenType::SessionCookie);
        let json = serde_json::to_string(&t).unwrap();
        let restored: TokenLoot = serde_json::from_str(&json).unwrap();
        assert!(matches!(restored.token_type, TokenType::SessionCookie));
    }

    #[test]
    fn token_loot_custom_roundtrip() {
        let t = make_token_loot(TokenType::Custom("bearer".to_string()));
        let json = serde_json::to_string(&t).unwrap();
        let restored: TokenLoot = serde_json::from_str(&json).unwrap();
        match restored.token_type {
            TokenType::Custom(ref name) => assert_eq!(name, "bearer"),
            other => panic!("Expected Custom variant, got {:?}", other),
        }
    }

    #[test]
    fn token_loot_optional_fields_none() {
        let t = make_token_loot(TokenType::Jwt);
        assert_eq!(t.expires_at, None);
        assert_eq!(t.principal, None);
        assert_eq!(t.service, None);

        let json = serde_json::to_string(&t).unwrap();
        let restored: TokenLoot = serde_json::from_str(&json).unwrap();
        assert_eq!(restored.expires_at, None);
        assert_eq!(restored.principal, None);
        assert_eq!(restored.service, None);
    }

    #[test]
    fn token_loot_optional_fields_some() {
        let expiry = Utc::now() + chrono::Duration::hours(8);
        let mut t = make_token_loot(TokenType::Kerberos);
        t.expires_at = Some(expiry);
        t.principal = Some("jdoe@CORP.LOCAL".to_string());
        t.service = Some("cifs/dc01.corp.local".to_string());

        let json = serde_json::to_string(&t).unwrap();
        let restored: TokenLoot = serde_json::from_str(&json).unwrap();

        assert!(restored.expires_at.is_some());
        assert_eq!(restored.principal, Some("jdoe@CORP.LOCAL".to_string()));
        assert_eq!(restored.service, Some("cifs/dc01.corp.local".to_string()));
    }

    // =========================================================================
    // FileLoot tests
    // =========================================================================

    #[test]
    fn file_loot_zero_size() {
        let f = make_file_loot(0, "/etc/empty");
        assert_eq!(f.size, 0);
        let json = serde_json::to_string(&f).unwrap();
        let restored: FileLoot = serde_json::from_str(&json).unwrap();
        assert_eq!(restored.size, 0);
    }

    #[test]
    fn file_loot_small_file() {
        let f = make_file_loot(1024, "/etc/passwd");
        assert_eq!(f.size, 1024);
        let json = serde_json::to_string(&f).unwrap();
        let restored: FileLoot = serde_json::from_str(&json).unwrap();
        assert_eq!(restored.size, 1024);
        assert_eq!(restored.original_path, "/etc/passwd");
    }

    #[test]
    fn file_loot_large_file() {
        let large_size: u64 = 10 * 1024 * 1024 * 1024; // 10 GiB
        let f = make_file_loot(large_size, "/var/data/huge.db");
        let json = serde_json::to_string(&f).unwrap();
        let restored: FileLoot = serde_json::from_str(&json).unwrap();
        assert_eq!(restored.size, large_size);
    }

    #[test]
    fn file_loot_u64_max_size() {
        let f = make_file_loot(u64::MAX, "/dev/bigfile");
        let json = serde_json::to_string(&f).unwrap();
        let restored: FileLoot = serde_json::from_str(&json).unwrap();
        assert_eq!(restored.size, u64::MAX);
    }

    #[test]
    fn file_loot_windows_path() {
        let f = make_file_loot(512, r"C:\Users\Administrator\Documents\passwords.txt");
        let json = serde_json::to_string(&f).unwrap();
        let restored: FileLoot = serde_json::from_str(&json).unwrap();
        assert_eq!(
            restored.original_path,
            r"C:\Users\Administrator\Documents\passwords.txt"
        );
    }

    #[test]
    fn file_loot_unc_path() {
        let f = make_file_loot(256, r"\\server\share\file.txt");
        let json = serde_json::to_string(&f).unwrap();
        let restored: FileLoot = serde_json::from_str(&json).unwrap();
        assert_eq!(restored.original_path, r"\\server\share\file.txt");
    }

    #[test]
    fn file_loot_roundtrip_preserves_all_fields() {
        let f = make_file_loot(4096, "/home/user/.ssh/id_rsa");
        let json = serde_json::to_string(&f).unwrap();
        let restored: FileLoot = serde_json::from_str(&json).unwrap();

        assert_eq!(restored.id, f.id);
        assert_eq!(restored.implant_id, f.implant_id);
        assert_eq!(restored.task_id, f.task_id);
        assert_eq!(restored.source, f.source);
        assert_eq!(restored.filename, f.filename);
        assert_eq!(restored.original_path, f.original_path);
        assert_eq!(restored.size, f.size);
        assert_eq!(restored.hash, f.hash);
        assert_eq!(restored.blob_path, f.blob_path);
    }

    // =========================================================================
    // Loot enum (tagged serialization) tests
    // =========================================================================

    #[test]
    fn loot_credential_variant_has_type_tag() {
        let loot = Loot::Credential(make_credential_loot());
        let json = serde_json::to_string(&loot).unwrap();
        assert!(json.contains("\"type\":\"Credential\""), "json: {}", json);
        assert!(json.contains("\"data\""), "json: {}", json);
    }

    #[test]
    fn loot_hash_variant_has_type_tag() {
        let loot = Loot::Hash(make_hash_loot(HashType::Ntlm));
        let json = serde_json::to_string(&loot).unwrap();
        assert!(json.contains("\"type\":\"Hash\""), "json: {}", json);
        assert!(json.contains("\"data\""), "json: {}", json);
    }

    #[test]
    fn loot_token_variant_has_type_tag() {
        let loot = Loot::Token(make_token_loot(TokenType::Jwt));
        let json = serde_json::to_string(&loot).unwrap();
        assert!(json.contains("\"type\":\"Token\""), "json: {}", json);
        assert!(json.contains("\"data\""), "json: {}", json);
    }

    #[test]
    fn loot_file_variant_has_type_tag() {
        let loot = Loot::File(make_file_loot(1024, "/tmp/stolen"));
        let json = serde_json::to_string(&loot).unwrap();
        assert!(json.contains("\"type\":\"File\""), "json: {}", json);
        assert!(json.contains("\"data\""), "json: {}", json);
    }

    #[test]
    fn loot_credential_roundtrip() {
        let loot = Loot::Credential(make_credential_loot());
        let json = serde_json::to_string(&loot).unwrap();
        let restored: Loot = serde_json::from_str(&json).unwrap();
        assert!(matches!(restored, Loot::Credential(_)));
    }

    #[test]
    fn loot_hash_roundtrip() {
        let loot = Loot::Hash(make_hash_loot(HashType::Sha256));
        let json = serde_json::to_string(&loot).unwrap();
        let restored: Loot = serde_json::from_str(&json).unwrap();
        assert!(matches!(restored, Loot::Hash(_)));
    }

    #[test]
    fn loot_token_roundtrip() {
        let loot = Loot::Token(make_token_loot(TokenType::Saml));
        let json = serde_json::to_string(&loot).unwrap();
        let restored: Loot = serde_json::from_str(&json).unwrap();
        assert!(matches!(restored, Loot::Token(_)));
    }

    #[test]
    fn loot_file_roundtrip() {
        let loot = Loot::File(make_file_loot(8192, "/etc/shadow"));
        let json = serde_json::to_string(&loot).unwrap();
        let restored: Loot = serde_json::from_str(&json).unwrap();
        assert!(matches!(restored, Loot::File(_)));
    }

    #[test]
    fn loot_deserialize_wrong_type_tag_errors() {
        let bad_json = r#"{"type":"Unknown","data":{}}"#;
        let result: Result<Loot, _> = serde_json::from_str(bad_json);
        assert!(result.is_err(), "Expected error for unknown variant");
    }

    #[test]
    fn loot_deserialize_missing_type_tag_errors() {
        let bad_json = r#"{"username":"admin","password":"secret"}"#;
        let result: Result<Loot, _> = serde_json::from_str(bad_json);
        assert!(result.is_err(), "Expected error when type tag is absent");
    }

    #[test]
    fn loot_clone_credential() {
        let loot = Loot::Credential(make_credential_loot());
        let cloned = loot.clone();
        let json1 = serde_json::to_string(&loot).unwrap();
        let json2 = serde_json::to_string(&cloned).unwrap();
        assert_eq!(json1, json2);
    }

    // =========================================================================
    // Loot ID (UUID) tests
    // =========================================================================

    #[test]
    fn loot_id_is_serialized_as_hyphenated_uuid_string() {
        let c = make_credential_loot();
        let json = serde_json::to_string(&c).unwrap();
        // UUID should appear as a hyphenated lowercase string
        assert!(json.contains("a1a2a3a4-b1b2-c1c2-d1d2-e1e2e3e4e5e6"));
    }

    #[test]
    fn loot_id_deserialized_uuid_matches() {
        let c = make_credential_loot();
        let json = serde_json::to_string(&c).unwrap();
        let restored: CredentialLoot = serde_json::from_str(&json).unwrap();
        assert_eq!(restored.id, fixed_uuid());
    }
}

// =========================================================================
// Property-based tests
// =========================================================================

#[cfg(test)]
mod proptests {
    use crate::types::{
        CredentialLoot, FileLoot, HashLoot, HashType, Loot, TokenLoot, TokenType,
    };
    use chrono::{TimeZone, Utc};
    use proptest::prelude::*;
    use uuid::Uuid;

    // -------------------------------------------------------------------------
    // Arbitrary generators for loot types
    // -------------------------------------------------------------------------

    fn arb_uuid() -> impl Strategy<Value = Uuid> {
        prop::array::uniform16(any::<u8>()).prop_map(Uuid::from_bytes)
    }

    fn arb_timestamp() -> impl Strategy<Value = chrono::DateTime<Utc>> {
        // Generate timestamps between 2020-01-01 and 2030-01-01
        (1577836800i64..1893456000i64).prop_map(|ts| Utc.timestamp_opt(ts, 0).unwrap())
    }

    fn arb_hash_type() -> impl Strategy<Value = HashType> {
        prop_oneof![
            Just(HashType::Ntlm),
            Just(HashType::NtlmV2),
            Just(HashType::NetNtlmV1),
            Just(HashType::NetNtlmV2),
            Just(HashType::Kerberos),
            Just(HashType::Sha256),
            Just(HashType::Md5),
            "[a-z]{3,10}".prop_map(HashType::Custom),
        ]
    }

    fn arb_token_type() -> impl Strategy<Value = TokenType> {
        prop_oneof![
            Just(TokenType::Kerberos),
            Just(TokenType::Jwt),
            Just(TokenType::Saml),
            Just(TokenType::Oauth),
            Just(TokenType::SessionCookie),
            "[a-z]{3,10}".prop_map(TokenType::Custom),
        ]
    }

    fn arb_credential_loot() -> impl Strategy<Value = CredentialLoot> {
        (
            arb_uuid(),
            arb_uuid(),
            arb_uuid(),
            arb_timestamp(),
            "[a-zA-Z0-9_]{1,20}",      // source
            "[a-zA-Z0-9_]{1,30}",      // username
            "[a-zA-Z0-9!@#$%]{1,50}", // password
            proptest::option::of("[A-Z]{2,10}"),     // domain
            proptest::option::of("[a-z0-9.]{1,30}"), // host
            proptest::option::of(1u16..65535u16),    // port
            proptest::option::of("[a-z]{2,10}"),     // protocol
        )
            .prop_map(
                |(id, implant_id, task_id, captured_at, source, username, password, domain, host, port, protocol)| {
                    CredentialLoot {
                        id,
                        implant_id,
                        task_id,
                        captured_at,
                        source,
                        username,
                        password,
                        domain,
                        host,
                        port,
                        protocol,
                    }
                },
            )
    }

    fn arb_hash_loot() -> impl Strategy<Value = HashLoot> {
        (
            arb_uuid(),
            arb_uuid(),
            arb_uuid(),
            arb_timestamp(),
            "[a-zA-Z0-9_]{1,20}",                // source
            arb_hash_type(),
            "[a-fA-F0-9]{32,128}",               // hash_value
            proptest::option::of("[a-z]{1,20}"), // username
            proptest::option::of("[A-Z]{2,10}"), // domain
        )
            .prop_map(
                |(id, implant_id, task_id, captured_at, source, hash_type, hash_value, username, domain)| {
                    HashLoot {
                        id,
                        implant_id,
                        task_id,
                        captured_at,
                        source,
                        hash_type,
                        hash_value,
                        username,
                        domain,
                    }
                },
            )
    }

    fn arb_token_loot() -> impl Strategy<Value = TokenLoot> {
        (
            arb_uuid(),
            arb_uuid(),
            arb_uuid(),
            arb_timestamp(),
            "[a-zA-Z0-9_]{1,20}",                       // source
            arb_token_type(),
            "[a-zA-Z0-9._-]{10,100}",                   // token_data
            proptest::option::of(arb_timestamp()),      // expires_at
            proptest::option::of("[a-z@.]{1,30}"),      // principal
            proptest::option::of("[a-z/]{1,30}"),       // service
        )
            .prop_map(
                |(id, implant_id, task_id, captured_at, source, token_type, token_data, expires_at, principal, service)| {
                    TokenLoot {
                        id,
                        implant_id,
                        task_id,
                        captured_at,
                        source,
                        token_type,
                        token_data,
                        expires_at,
                        principal,
                        service,
                    }
                },
            )
    }

    fn arb_file_loot() -> impl Strategy<Value = FileLoot> {
        (
            arb_uuid(),
            arb_uuid(),
            arb_uuid(),
            arb_timestamp(),
            "[a-zA-Z0-9_]{1,20}",     // source
            "[a-zA-Z0-9_.]{1,50}",    // filename
            "[/a-zA-Z0-9_.]{1,100}",  // original_path
            any::<u64>(),             // size
            "[a-f0-9]{64}",           // hash (SHA256)
            "[/a-zA-Z0-9_.]{1,50}",   // blob_path
        )
            .prop_map(
                |(id, implant_id, task_id, captured_at, source, filename, original_path, size, hash, blob_path)| {
                    FileLoot {
                        id,
                        implant_id,
                        task_id,
                        captured_at,
                        source,
                        filename,
                        original_path,
                        size,
                        hash,
                        blob_path,
                    }
                },
            )
    }

    fn arb_loot() -> impl Strategy<Value = Loot> {
        prop_oneof![
            arb_credential_loot().prop_map(Loot::Credential),
            arb_hash_loot().prop_map(Loot::Hash),
            arb_token_loot().prop_map(Loot::Token),
            arb_file_loot().prop_map(Loot::File),
        ]
    }

    // -------------------------------------------------------------------------
    // Property tests
    // -------------------------------------------------------------------------

    proptest! {
        /// CredentialLoot survives JSON roundtrip
        #[test]
        fn credential_loot_json_roundtrip(cred in arb_credential_loot()) {
            let json = serde_json::to_string(&cred).expect("serialize");
            let restored: CredentialLoot = serde_json::from_str(&json).expect("deserialize");

            prop_assert_eq!(cred.id, restored.id);
            prop_assert_eq!(cred.implant_id, restored.implant_id);
            prop_assert_eq!(cred.task_id, restored.task_id);
            prop_assert_eq!(cred.source, restored.source);
            prop_assert_eq!(cred.username, restored.username);
            prop_assert_eq!(cred.password, restored.password);
            prop_assert_eq!(cred.domain, restored.domain);
            prop_assert_eq!(cred.host, restored.host);
            prop_assert_eq!(cred.port, restored.port);
            prop_assert_eq!(cred.protocol, restored.protocol);
        }

        /// HashLoot survives JSON roundtrip
        #[test]
        fn hash_loot_json_roundtrip(hash in arb_hash_loot()) {
            let json = serde_json::to_string(&hash).expect("serialize");
            let restored: HashLoot = serde_json::from_str(&json).expect("deserialize");

            prop_assert_eq!(hash.id, restored.id);
            prop_assert_eq!(hash.implant_id, restored.implant_id);
            prop_assert_eq!(hash.hash_value, restored.hash_value);
            prop_assert_eq!(hash.username, restored.username);
            prop_assert_eq!(hash.domain, restored.domain);
        }

        /// TokenLoot survives JSON roundtrip
        #[test]
        fn token_loot_json_roundtrip(token in arb_token_loot()) {
            let json = serde_json::to_string(&token).expect("serialize");
            let restored: TokenLoot = serde_json::from_str(&json).expect("deserialize");

            prop_assert_eq!(token.id, restored.id);
            prop_assert_eq!(token.implant_id, restored.implant_id);
            prop_assert_eq!(token.token_data, restored.token_data);
            prop_assert_eq!(token.principal, restored.principal);
            prop_assert_eq!(token.service, restored.service);
        }

        /// FileLoot survives JSON roundtrip
        #[test]
        fn file_loot_json_roundtrip(file in arb_file_loot()) {
            let json = serde_json::to_string(&file).expect("serialize");
            let restored: FileLoot = serde_json::from_str(&json).expect("deserialize");

            prop_assert_eq!(file.id, restored.id);
            prop_assert_eq!(file.implant_id, restored.implant_id);
            prop_assert_eq!(file.filename, restored.filename);
            prop_assert_eq!(file.original_path, restored.original_path);
            prop_assert_eq!(file.size, restored.size);
            prop_assert_eq!(file.hash, restored.hash);
            prop_assert_eq!(file.blob_path, restored.blob_path);
        }

        /// Loot enum survives JSON roundtrip with proper type tagging
        #[test]
        fn loot_enum_json_roundtrip(loot in arb_loot()) {
            let json = serde_json::to_string(&loot).expect("serialize");

            // Verify type tag exists
            prop_assert!(json.contains("\"type\":"));
            prop_assert!(json.contains("\"data\":"));

            let restored: Loot = serde_json::from_str(&json).expect("deserialize");

            // Verify variant matches
            match (&loot, &restored) {
                (Loot::Credential(a), Loot::Credential(b)) => {
                    prop_assert_eq!(&a.id, &b.id);
                    prop_assert_eq!(&a.username, &b.username);
                }
                (Loot::Hash(a), Loot::Hash(b)) => {
                    prop_assert_eq!(&a.id, &b.id);
                    prop_assert_eq!(&a.hash_value, &b.hash_value);
                }
                (Loot::Token(a), Loot::Token(b)) => {
                    prop_assert_eq!(&a.id, &b.id);
                    prop_assert_eq!(&a.token_data, &b.token_data);
                }
                (Loot::File(a), Loot::File(b)) => {
                    prop_assert_eq!(&a.id, &b.id);
                    prop_assert_eq!(&a.filename, &b.filename);
                }
                _ => prop_assert!(false, "variant mismatch"),
            }
        }

        /// JSON output is valid UTF-8 and parseable
        #[test]
        fn loot_json_is_valid_utf8(loot in arb_loot()) {
            let json = serde_json::to_string(&loot).expect("serialize");
            prop_assert!(json.is_ascii() || json.chars().all(|c| c.len_utf8() <= 4));

            // Should be valid JSON
            let value: serde_json::Value = serde_json::from_str(&json).expect("parse as Value");
            prop_assert!(value.is_object());
        }

        /// File size u64::MAX serializes correctly
        #[test]
        fn file_loot_large_size_roundtrip(size in (u64::MAX - 1000)..=u64::MAX) {
            let file = FileLoot {
                id: Uuid::new_v4(),
                implant_id: Uuid::new_v4(),
                task_id: Uuid::new_v4(),
                captured_at: Utc::now(),
                source: "test".to_string(),
                filename: "test.bin".to_string(),
                original_path: "/test".to_string(),
                size,
                hash: "a".repeat(64),
                blob_path: "/blob".to_string(),
            };

            let json = serde_json::to_string(&file).expect("serialize");
            let restored: FileLoot = serde_json::from_str(&json).expect("deserialize");
            prop_assert_eq!(file.size, restored.size);
        }

        /// Port numbers roundtrip correctly
        #[test]
        fn credential_port_roundtrip(port in 1u16..=65535u16) {
            let cred = CredentialLoot {
                id: Uuid::new_v4(),
                implant_id: Uuid::new_v4(),
                task_id: Uuid::new_v4(),
                captured_at: Utc::now(),
                source: "test".to_string(),
                username: "user".to_string(),
                password: "pass".to_string(),
                domain: None,
                host: None,
                port: Some(port),
                protocol: None,
            };

            let json = serde_json::to_string(&cred).expect("serialize");
            let restored: CredentialLoot = serde_json::from_str(&json).expect("deserialize");
            prop_assert_eq!(Some(port), restored.port);
        }
    }
}

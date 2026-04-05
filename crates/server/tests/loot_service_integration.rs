//! Integration tests for LootService gRPC
//!
//! Each test spins up a real gRPC server bound to a random port and communicates
//! with it via the generated LootServiceClient stub.  The server uses an
//! in-memory SQLite database so every test is fully isolated.

use std::net::SocketAddr;
use std::sync::Arc;

use crypto::{ServerCrypto, SymmetricKey};
use protocol::{
    loot_entry, store_loot_request, CredentialLoot as ProtoCredentialLoot,
    DeleteLootRequest, ExportLootRequest, GetLootRequest, HashLoot as ProtoHashLoot,
    ListLootRequest, LootServiceClient, LootServiceServer, LootType,
    SearchLootRequest, StoreLootRequest, TokenLoot as ProtoTokenLoot, Uuid as ProtoUuid,
};
use tokio_stream::wrappers::TcpListenerStream;
use uuid::Uuid;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Start a LootService gRPC server on a random OS-assigned port.
/// Returns the bound address; the server runs in a background task.
/// Also inserts a test implant to satisfy FK constraints on loot table.
async fn setup_loot_server() -> (Arc<server::ServerState>, SocketAddr) {
    let db = db::Database::connect_memory().await.unwrap();
    db.migrate().await.unwrap();

    // Insert a test implant to satisfy foreign key constraints
    let test_implant_id = Uuid::nil().as_bytes().to_vec();
    sqlx::query(
        r#"INSERT INTO implants (id, name, state, hostname, username, os_name, os_version, os_arch,
           process_id, process_name, is_elevated, checkin_interval, jitter_percent, registered_at, last_seen)
           VALUES (?, 'test-implant', 'active', 'testhost', 'testuser', 'Linux', '5.0', 'x86_64',
           1234, 'test', 0, 10, 0, 0, 0)"#
    )
    .bind(&test_implant_id)
    .execute(db.pool())
    .await
    .expect("failed to insert test implant");

    let master_key = SymmetricKey([0u8; 32]);
    let crypto = ServerCrypto::new(master_key);
    let signing_key = module_store::ModuleSigner::generate_pkcs8().unwrap();
    let module_store = std::sync::Arc::new(
        module_store::ModuleStore::new(std::sync::Arc::new(db.clone()), &signing_key).unwrap(),
    );
    let audit_key = b"test-audit-key-for-integration!";
    let state = server::ServerState::new(db, crypto, module_store, audit_key.to_vec());

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    let loot_svc = LootServiceServer::new(server::grpc::LootServiceImpl::new(Arc::clone(&state)));

    tokio::spawn(async move {
        tonic::transport::Server::builder()
            .add_service(loot_svc)
            .serve_with_incoming(TcpListenerStream::new(listener))
            .await
            .expect("LootService gRPC server failed");
    });

    (state, addr)
}

/// Open a tonic channel to the given address.
async fn connect(addr: SocketAddr) -> tonic::transport::Channel {
    let endpoint = format!("http://{}", addr);
    tonic::transport::Channel::from_shared(endpoint)
        .unwrap()
        .connect()
        .await
        .unwrap()
}

/// Build a fake 16-byte implant UUID (all zeros — valid for test purposes).
fn fake_implant_id() -> ProtoUuid {
    ProtoUuid {
        value: Uuid::nil().as_bytes().to_vec(),
    }
}

// ---------------------------------------------------------------------------
// 1. StoreLoot – credential
// ---------------------------------------------------------------------------

/// StoreLoot with credential data must return a non-empty loot_id.
#[tokio::test]
async fn test_store_loot_credential() {
    let (_state, addr) = setup_loot_server().await;
    let mut client = LootServiceClient::new(connect(addr).await);

    let resp = client
        .store_loot(StoreLootRequest {
            implant_id: Some(fake_implant_id()),
            loot_type: LootType::Credential as i32,
            source: "mimikatz".to_string(),
            data: Some(store_loot_request::Data::Credential(
                ProtoCredentialLoot {
                    username: "administrator".to_string(),
                    password: "P@ssw0rd!".to_string(),
                    domain: Some("CORP".to_string()),
                    realm: None,
                    host: Some("DC01".to_string()),
                },
            )),
        })
        .await
        .expect("store_loot RPC failed");

    let loot_id = resp.into_inner().loot_id.expect("response has no loot_id");
    assert_eq!(loot_id.value.len(), 16, "loot_id must be 16 bytes");
}

// ---------------------------------------------------------------------------
// 2. StoreLoot – hash
// ---------------------------------------------------------------------------

/// StoreLoot with NTLM hash data must return a valid loot_id.
#[tokio::test]
async fn test_store_loot_hash() {
    let (_state, addr) = setup_loot_server().await;
    let mut client = LootServiceClient::new(connect(addr).await);

    let resp = client
        .store_loot(StoreLootRequest {
            implant_id: Some(fake_implant_id()),
            loot_type: LootType::Hash as i32,
            source: "secretsdump".to_string(),
            data: Some(store_loot_request::Data::Hash(ProtoHashLoot {
                username: "jdoe".to_string(),
                hash: "aad3b435b51404eeaad3b435b51404ee".to_string(),
                hash_type: "NTLM".to_string(),
                domain: Some("CORP".to_string()),
            })),
        })
        .await
        .expect("store_loot (hash) RPC failed");

    let loot_id = resp.into_inner().loot_id.expect("response has no loot_id");
    assert_eq!(loot_id.value.len(), 16, "loot_id must be 16 bytes");
}

// ---------------------------------------------------------------------------
// 3. StoreLoot – token
// ---------------------------------------------------------------------------

/// StoreLoot with token data must return a valid loot_id.
#[tokio::test]
async fn test_store_loot_token() {
    let (_state, addr) = setup_loot_server().await;
    let mut client = LootServiceClient::new(connect(addr).await);

    let resp = client
        .store_loot(StoreLootRequest {
            implant_id: Some(fake_implant_id()),
            loot_type: LootType::Token as i32,
            source: "browser-harvest".to_string(),
            data: Some(store_loot_request::Data::Token(ProtoTokenLoot {
                token_type: "JWT".to_string(),
                token_value: "eyJhbGciOiJIUzI1NiJ9.test.sig".to_string(),
                service: Some("internal-api".to_string()),
                expires_at: None,
            })),
        })
        .await
        .expect("store_loot (token) RPC failed");

    let loot_id = resp.into_inner().loot_id.expect("response has no loot_id");
    assert_eq!(loot_id.value.len(), 16, "loot_id must be 16 bytes");
}

// ---------------------------------------------------------------------------
// 4. GetLoot – round-trip with credential
// ---------------------------------------------------------------------------

/// After StoreLoot the entry must be retrievable with GetLoot and the
/// returned fields must match what was stored.
#[tokio::test]
async fn test_get_loot_returns_stored_entry() {
    let (_state, addr) = setup_loot_server().await;
    let mut client = LootServiceClient::new(connect(addr).await);

    // Store first
    let store_resp = client
        .store_loot(StoreLootRequest {
            implant_id: Some(fake_implant_id()),
            loot_type: LootType::Credential as i32,
            source: "lsass".to_string(),
            data: Some(store_loot_request::Data::Credential(
                ProtoCredentialLoot {
                    username: "svc-backup".to_string(),
                    password: "hunter2".to_string(),
                    domain: None,
                    realm: None,
                    host: None,
                },
            )),
        })
        .await
        .expect("store_loot RPC failed");

    let loot_id = store_resp
        .into_inner()
        .loot_id
        .expect("no loot_id in store response");

    // Retrieve
    let get_resp = client
        .get_loot(GetLootRequest {
            loot_id: Some(loot_id.clone()),
        })
        .await
        .expect("get_loot RPC failed");

    let entry = get_resp.into_inner();

    // ID round-trips
    let returned_id = entry.id.expect("returned entry has no id");
    assert_eq!(returned_id.value, loot_id.value, "loot_id mismatch");

    // Source preserved
    assert_eq!(entry.source, "lsass");

    // Loot type
    assert_eq!(entry.loot_type, LootType::Credential as i32);

    // Credential fields
    match entry.data.expect("entry has no data") {
        loot_entry::Data::Credential(c) => {
            assert_eq!(c.username, "svc-backup");
            assert_eq!(c.password, "hunter2");
        }
        other => panic!("expected Credential variant, got {:?}", other),
    }
}

// ---------------------------------------------------------------------------
// 5. GetLoot – not found
// ---------------------------------------------------------------------------

/// GetLoot for a non-existent ID must return NOT_FOUND.
#[tokio::test]
async fn test_get_loot_not_found() {
    let (_state, addr) = setup_loot_server().await;
    let mut client = LootServiceClient::new(connect(addr).await);

    let nonexistent = ProtoUuid {
        value: Uuid::new_v4().as_bytes().to_vec(),
    };

    let err = client
        .get_loot(GetLootRequest {
            loot_id: Some(nonexistent),
        })
        .await
        .expect_err("expected NOT_FOUND error");

    assert_eq!(
        err.code(),
        tonic::Code::NotFound,
        "expected NOT_FOUND, got {:?}",
        err.code()
    );
}

// ---------------------------------------------------------------------------
// 6. ListLoot – type filtering
// ---------------------------------------------------------------------------

/// ListLoot with a type_filter must return only entries of that type.
#[tokio::test]
async fn test_list_loot_type_filter() {
    let (_state, addr) = setup_loot_server().await;
    let mut client = LootServiceClient::new(connect(addr).await);

    // Store one credential and one hash
    client
        .store_loot(StoreLootRequest {
            implant_id: Some(fake_implant_id()),
            loot_type: LootType::Credential as i32,
            source: "cred-module".to_string(),
            data: Some(store_loot_request::Data::Credential(
                ProtoCredentialLoot {
                    username: "alice".to_string(),
                    password: "secret".to_string(),
                    domain: None,
                    realm: None,
                    host: None,
                },
            )),
        })
        .await
        .expect("store credential failed");

    client
        .store_loot(StoreLootRequest {
            implant_id: Some(fake_implant_id()),
            loot_type: LootType::Hash as i32,
            source: "hash-module".to_string(),
            data: Some(store_loot_request::Data::Hash(ProtoHashLoot {
                username: "bob".to_string(),
                hash: "deadbeefdeadbeef".to_string(),
                hash_type: "NTLM".to_string(),
                domain: None,
            })),
        })
        .await
        .expect("store hash failed");

    // Filter for credentials only
    let list_resp = client
        .list_loot(ListLootRequest {
            implant_id: None,
            type_filter: Some(LootType::Credential as i32),
            limit: None,
            offset: None,
        })
        .await
        .expect("list_loot RPC failed");

    let body = list_resp.into_inner();
    assert_eq!(
        body.entries.len(),
        1,
        "expected exactly 1 credential entry, got {}",
        body.entries.len()
    );
    assert_eq!(body.entries[0].loot_type, LootType::Credential as i32);

    // Filter for hashes only
    let hash_resp = client
        .list_loot(ListLootRequest {
            implant_id: None,
            type_filter: Some(LootType::Hash as i32),
            limit: None,
            offset: None,
        })
        .await
        .expect("list_loot (hash) RPC failed");

    let hash_body = hash_resp.into_inner();
    assert_eq!(
        hash_body.entries.len(),
        1,
        "expected exactly 1 hash entry, got {}",
        hash_body.entries.len()
    );
    assert_eq!(hash_body.entries[0].loot_type, LootType::Hash as i32);
}

// ---------------------------------------------------------------------------
// 7. ListLoot – pagination (limit / offset)
// ---------------------------------------------------------------------------

/// ListLoot with limit=2 and offset=1 must return the correct page of entries.
#[tokio::test]
async fn test_list_loot_pagination() {
    let (_state, addr) = setup_loot_server().await;
    let mut client = LootServiceClient::new(connect(addr).await);

    // Insert 4 credential entries
    for i in 0..4u32 {
        client
            .store_loot(StoreLootRequest {
                implant_id: Some(fake_implant_id()),
                loot_type: LootType::Credential as i32,
                source: format!("source-{}", i),
                data: Some(store_loot_request::Data::Credential(
                    ProtoCredentialLoot {
                        username: format!("user{}", i),
                        password: "pw".to_string(),
                        domain: None,
                        realm: None,
                        host: None,
                    },
                )),
            })
            .await
            .unwrap_or_else(|e| panic!("store_loot {} failed: {}", i, e));
    }

    // Page 1: offset=0, limit=2
    let page1 = client
        .list_loot(ListLootRequest {
            implant_id: None,
            type_filter: None,
            limit: Some(2),
            offset: Some(0),
        })
        .await
        .expect("list_loot page1 failed")
        .into_inner();

    assert_eq!(page1.entries.len(), 2, "page1 should have 2 entries");
    assert_eq!(page1.total_count, 4, "total_count should be 4");

    // Page 2: offset=2, limit=2
    let page2 = client
        .list_loot(ListLootRequest {
            implant_id: None,
            type_filter: None,
            limit: Some(2),
            offset: Some(2),
        })
        .await
        .expect("list_loot page2 failed")
        .into_inner();

    assert_eq!(page2.entries.len(), 2, "page2 should have 2 entries");

    // Page 3: offset=4, limit=2 — past the end
    let page3 = client
        .list_loot(ListLootRequest {
            implant_id: None,
            type_filter: None,
            limit: Some(2),
            offset: Some(4),
        })
        .await
        .expect("list_loot page3 failed")
        .into_inner();

    assert_eq!(page3.entries.len(), 0, "page3 should be empty");
}

// ---------------------------------------------------------------------------
// 8. DeleteLoot – removes the entry
// ---------------------------------------------------------------------------

/// After DeleteLoot the entry must no longer be retrievable via GetLoot.
#[tokio::test]
async fn test_delete_loot_removes_entry() {
    let (_state, addr) = setup_loot_server().await;
    let mut client = LootServiceClient::new(connect(addr).await);

    // Store an entry
    let loot_id = client
        .store_loot(StoreLootRequest {
            implant_id: Some(fake_implant_id()),
            loot_type: LootType::Credential as i32,
            source: "test-delete".to_string(),
            data: Some(store_loot_request::Data::Credential(
                ProtoCredentialLoot {
                    username: "victim".to_string(),
                    password: "topsecret".to_string(),
                    domain: None,
                    realm: None,
                    host: None,
                },
            )),
        })
        .await
        .expect("store_loot failed")
        .into_inner()
        .loot_id
        .expect("no loot_id");

    // Delete it
    let del_resp = client
        .delete_loot(DeleteLootRequest {
            loot_id: Some(loot_id.clone()),
        })
        .await
        .expect("delete_loot RPC failed")
        .into_inner();

    assert!(del_resp.success, "delete_loot should report success=true");

    // Must no longer exist
    let err = client
        .get_loot(GetLootRequest {
            loot_id: Some(loot_id),
        })
        .await
        .expect_err("expected NOT_FOUND after delete");

    assert_eq!(
        err.code(),
        tonic::Code::NotFound,
        "expected NOT_FOUND after delete, got {:?}",
        err.code()
    );
}

// ---------------------------------------------------------------------------
// 9. DeleteLoot – deleting non-existent ID returns success=false
// ---------------------------------------------------------------------------

/// DeleteLoot on an unknown ID must return success=false (not an error status).
#[tokio::test]
async fn test_delete_loot_nonexistent() {
    let (_state, addr) = setup_loot_server().await;
    let mut client = LootServiceClient::new(connect(addr).await);

    let resp = client
        .delete_loot(DeleteLootRequest {
            loot_id: Some(ProtoUuid {
                value: Uuid::new_v4().as_bytes().to_vec(),
            }),
        })
        .await
        .expect("delete_loot RPC failed")
        .into_inner();

    assert!(!resp.success, "deleting nonexistent entry should return success=false");
}

// ---------------------------------------------------------------------------
// 10. ExportLoot – JSON format
// ---------------------------------------------------------------------------

/// ExportLoot with format="json" must return valid JSON containing the stored
/// entries, a non-empty data payload, and the filename loot_export.json.
#[tokio::test]
async fn test_export_loot_json() {
    let (_state, addr) = setup_loot_server().await;
    let mut client = LootServiceClient::new(connect(addr).await);

    // Store two entries
    for i in 0..2u32 {
        client
            .store_loot(StoreLootRequest {
                implant_id: Some(fake_implant_id()),
                loot_type: LootType::Credential as i32,
                source: format!("export-src-{}", i),
                data: Some(store_loot_request::Data::Credential(
                    ProtoCredentialLoot {
                        username: format!("export-user{}", i),
                        password: "pw".to_string(),
                        domain: None,
                        realm: None,
                        host: None,
                    },
                )),
            })
            .await
            .unwrap();
    }

    let resp = client
        .export_loot(ExportLootRequest {
            implant_id: None,
            type_filter: None,
            format: "json".to_string(),
        })
        .await
        .expect("export_loot (json) RPC failed")
        .into_inner();

    assert_eq!(resp.filename, "loot_export.json");
    assert!(!resp.data.is_empty(), "export data must not be empty");

    // Must parse as a JSON array
    let parsed: serde_json::Value =
        serde_json::from_slice(&resp.data).expect("export data is not valid JSON");
    let arr = parsed.as_array().expect("expected JSON array");
    assert_eq!(arr.len(), 2, "expected 2 entries in JSON export, got {}", arr.len());
}

// ---------------------------------------------------------------------------
// 11. ExportLoot – CSV format
// ---------------------------------------------------------------------------

/// ExportLoot with format="csv" must return CSV with a header row plus one
/// data row per entry, and filename loot_export.csv.
#[tokio::test]
async fn test_export_loot_csv() {
    let (_state, addr) = setup_loot_server().await;
    let mut client = LootServiceClient::new(connect(addr).await);

    // Store one credential entry
    client
        .store_loot(StoreLootRequest {
            implant_id: Some(fake_implant_id()),
            loot_type: LootType::Credential as i32,
            source: "csv-test".to_string(),
            data: Some(store_loot_request::Data::Credential(
                ProtoCredentialLoot {
                    username: "csvuser".to_string(),
                    password: "csvpw".to_string(),
                    domain: None,
                    realm: None,
                    host: None,
                },
            )),
        })
        .await
        .unwrap();

    let resp = client
        .export_loot(ExportLootRequest {
            implant_id: None,
            type_filter: None,
            format: "csv".to_string(),
        })
        .await
        .expect("export_loot (csv) RPC failed")
        .into_inner();

    assert_eq!(resp.filename, "loot_export.csv");
    assert!(!resp.data.is_empty(), "export data must not be empty");

    let csv_text = std::str::from_utf8(&resp.data).expect("CSV data is not valid UTF-8");
    let lines: Vec<&str> = csv_text.lines().collect();

    // Header + 1 data row
    assert!(
        lines.len() >= 2,
        "expected at least 2 CSV lines (header + data), got {}",
        lines.len()
    );
    assert!(
        lines[0].starts_with("id,implant_id,loot_type"),
        "first line should be CSV header, got: {}",
        lines[0]
    );
    // Data row contains the loot_type "credential"
    assert!(
        lines[1].contains("credential"),
        "data row should contain loot type 'credential', got: {}",
        lines[1]
    );
}

// ---------------------------------------------------------------------------
// 12. ListLoot – empty database returns empty list
// ---------------------------------------------------------------------------

/// ListLoot on a fresh server must return an empty list and total_count=0.
#[tokio::test]
async fn test_list_loot_empty() {
    let (_state, addr) = setup_loot_server().await;
    let mut client = LootServiceClient::new(connect(addr).await);

    let resp = client
        .list_loot(ListLootRequest {
            implant_id: None,
            type_filter: None,
            limit: None,
            offset: None,
        })
        .await
        .expect("list_loot RPC failed")
        .into_inner();

    assert!(resp.entries.is_empty(), "expected empty entry list");
    assert_eq!(resp.total_count, 0, "expected total_count=0");
}

// ---------------------------------------------------------------------------
// 13. StoreLoot – missing implant_id returns INVALID_ARGUMENT
// ---------------------------------------------------------------------------

/// StoreLoot without an implant_id must be rejected with INVALID_ARGUMENT.
#[tokio::test]
async fn test_store_loot_missing_implant_id() {
    let (_state, addr) = setup_loot_server().await;
    let mut client = LootServiceClient::new(connect(addr).await);

    let err = client
        .store_loot(StoreLootRequest {
            implant_id: None,
            loot_type: LootType::Credential as i32,
            source: "test".to_string(),
            data: Some(store_loot_request::Data::Credential(
                ProtoCredentialLoot {
                    username: "u".to_string(),
                    password: "p".to_string(),
                    domain: None,
                    realm: None,
                    host: None,
                },
            )),
        })
        .await
        .expect_err("expected INVALID_ARGUMENT");

    assert_eq!(
        err.code(),
        tonic::Code::InvalidArgument,
        "expected INVALID_ARGUMENT, got {:?}",
        err.code()
    );
}

// ---------------------------------------------------------------------------
// 14. StoreLoot – missing loot data returns INVALID_ARGUMENT
// ---------------------------------------------------------------------------

/// StoreLoot without the data oneof must be rejected with INVALID_ARGUMENT.
#[tokio::test]
async fn test_store_loot_missing_data() {
    let (_state, addr) = setup_loot_server().await;
    let mut client = LootServiceClient::new(connect(addr).await);

    let err = client
        .store_loot(StoreLootRequest {
            implant_id: Some(fake_implant_id()),
            loot_type: LootType::Credential as i32,
            source: "test".to_string(),
            data: None,
        })
        .await
        .expect_err("expected INVALID_ARGUMENT");

    assert_eq!(
        err.code(),
        tonic::Code::InvalidArgument,
        "expected INVALID_ARGUMENT, got {:?}",
        err.code()
    );
}

// ---------------------------------------------------------------------------
// 19. SearchLoot – basic FTS5 match
// ---------------------------------------------------------------------------

/// SearchLoot must return entries whose indexed fields match the query.
#[tokio::test]
async fn test_search_loot_basic() {
    let (_state, addr) = setup_loot_server().await;
    let mut client = LootServiceClient::new(connect(addr).await);

    // Store a credential with a distinctive username
    client
        .store_loot(StoreLootRequest {
            implant_id: Some(fake_implant_id()),
            loot_type: LootType::Credential as i32,
            source: "mimikatz".to_string(),
            data: Some(store_loot_request::Data::Credential(
                ProtoCredentialLoot {
                    username: "jdoe".to_string(),
                    password: "secret".to_string(),
                    domain: Some("ACME".to_string()),
                    realm: None,
                    host: Some("fileserver.acme.local".to_string()),
                },
            )),
        })
        .await
        .expect("store credential failed");

    // Store a hash that should NOT match "jdoe"
    client
        .store_loot(StoreLootRequest {
            implant_id: Some(fake_implant_id()),
            loot_type: LootType::Hash as i32,
            source: "secretsdump".to_string(),
            data: Some(store_loot_request::Data::Hash(ProtoHashLoot {
                username: "administrator".to_string(),
                hash: "aad3b435b51404eeaad3b435b51404ee".to_string(),
                hash_type: "NTLM".to_string(),
                domain: Some("CORP".to_string()),
            })),
        })
        .await
        .expect("store hash failed");

    // Search by username — only jdoe should match
    let resp = client
        .search_loot(SearchLootRequest {
            query: "jdoe".to_string(),
            limit: 100,
        })
        .await
        .expect("search_loot RPC failed")
        .into_inner();

    assert_eq!(resp.total_count, 1, "expected 1 result for 'jdoe'");
    assert_eq!(resp.entries.len(), 1);
    match &resp.entries[0].data {
        Some(loot_entry::Data::Credential(c)) => {
            assert_eq!(c.username, "jdoe");
        }
        other => panic!("expected Credential, got {:?}", other),
    }
}

// ---------------------------------------------------------------------------
// 20. SearchLoot – domain search across multiple entries
// ---------------------------------------------------------------------------

/// SearchLoot on a domain token must return all entries sharing that domain.
#[tokio::test]
async fn test_search_loot_domain() {
    let (_state, addr) = setup_loot_server().await;
    let mut client = LootServiceClient::new(connect(addr).await);

    // Two entries with domain ACME, one with CORP
    for i in 0..2u32 {
        client
            .store_loot(StoreLootRequest {
                implant_id: Some(fake_implant_id()),
                loot_type: LootType::Credential as i32,
                source: "harvest".to_string(),
                data: Some(store_loot_request::Data::Credential(
                    ProtoCredentialLoot {
                        username: format!("acme-user{}", i),
                        password: "pw".to_string(),
                        domain: Some("ACME".to_string()),
                        realm: None,
                        host: None,
                    },
                )),
            })
            .await
            .unwrap();
    }

    client
        .store_loot(StoreLootRequest {
            implant_id: Some(fake_implant_id()),
            loot_type: LootType::Credential as i32,
            source: "harvest".to_string(),
            data: Some(store_loot_request::Data::Credential(
                ProtoCredentialLoot {
                    username: "corp-user".to_string(),
                    password: "pw".to_string(),
                    domain: Some("CORP".to_string()),
                    realm: None,
                    host: None,
                },
            )),
        })
        .await
        .unwrap();

    let resp = client
        .search_loot(SearchLootRequest {
            query: "ACME".to_string(),
            limit: 100,
        })
        .await
        .expect("search_loot (domain) RPC failed")
        .into_inner();

    assert_eq!(resp.total_count, 2, "expected 2 ACME results");
    assert!(
        resp.entries.iter().all(|e| matches!(
            &e.data,
            Some(loot_entry::Data::Credential(c)) if c.domain.as_deref() == Some("ACME")
        )),
        "all results should have domain ACME"
    );
}

// ---------------------------------------------------------------------------
// 21. SearchLoot – no match returns empty list
// ---------------------------------------------------------------------------

/// SearchLoot with a query that matches nothing must return an empty list.
#[tokio::test]
async fn test_search_loot_no_match() {
    let (_state, addr) = setup_loot_server().await;
    let mut client = LootServiceClient::new(connect(addr).await);

    client
        .store_loot(StoreLootRequest {
            implant_id: Some(fake_implant_id()),
            loot_type: LootType::Credential as i32,
            source: "harvest".to_string(),
            data: Some(store_loot_request::Data::Credential(
                ProtoCredentialLoot {
                    username: "alice".to_string(),
                    password: "pw".to_string(),
                    domain: None,
                    realm: None,
                    host: None,
                },
            )),
        })
        .await
        .unwrap();

    let resp = client
        .search_loot(SearchLootRequest {
            query: "nonexistent_xyz_12345".to_string(),
            limit: 100,
        })
        .await
        .expect("search_loot (no match) RPC failed")
        .into_inner();

    assert_eq!(resp.total_count, 0, "expected 0 results for unmatched query");
    assert!(resp.entries.is_empty());
}

// ---------------------------------------------------------------------------
// 22. SearchLoot – empty query returns INVALID_ARGUMENT
// ---------------------------------------------------------------------------

/// SearchLoot with an empty query string must be rejected.
#[tokio::test]
async fn test_search_loot_empty_query() {
    let (_state, addr) = setup_loot_server().await;
    let mut client = LootServiceClient::new(connect(addr).await);

    let err = client
        .search_loot(SearchLootRequest {
            query: "".to_string(),
            limit: 100,
        })
        .await
        .expect_err("expected INVALID_ARGUMENT for empty query");

    assert_eq!(
        err.code(),
        tonic::Code::InvalidArgument,
        "expected INVALID_ARGUMENT, got {:?}",
        err.code()
    );
}

// ---------------------------------------------------------------------------
// 23. SearchLoot – limit is respected
// ---------------------------------------------------------------------------

/// SearchLoot with limit=1 must return at most 1 result even when more match.
#[tokio::test]
async fn test_search_loot_limit() {
    let (_state, addr) = setup_loot_server().await;
    let mut client = LootServiceClient::new(connect(addr).await);

    // Insert 3 entries that all match "CORP"
    for i in 0..3u32 {
        client
            .store_loot(StoreLootRequest {
                implant_id: Some(fake_implant_id()),
                loot_type: LootType::Credential as i32,
                source: "harvest".to_string(),
                data: Some(store_loot_request::Data::Credential(
                    ProtoCredentialLoot {
                        username: format!("corp-user{}", i),
                        password: "pw".to_string(),
                        domain: Some("CORP".to_string()),
                        realm: None,
                        host: None,
                    },
                )),
            })
            .await
            .unwrap();
    }

    let resp = client
        .search_loot(SearchLootRequest {
            query: "CORP".to_string(),
            limit: 1,
        })
        .await
        .expect("search_loot (limit) RPC failed")
        .into_inner();

    assert_eq!(resp.entries.len(), 1, "limit=1 must return at most 1 entry");
}

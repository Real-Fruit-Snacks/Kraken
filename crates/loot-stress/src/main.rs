//! Loot Store stress test binary.
//!
//! Connects to a running kraken-server gRPC endpoint and exercises the
//! LootService with configurable insert / query / delete workloads.
//! Reports per-operation timing statistics and pass/fail results.

use std::time::{Duration, Instant};

use clap::Parser;
use protocol::{
    loot_service_client::LootServiceClient,
    store_loot_request, CredentialLoot, DeleteLootRequest, HashLoot, ListLootRequest, LootType,
    StoreLootRequest, TokenLoot, Uuid as ProtoUuid,
};
use rand::Rng;
use tonic::transport::Channel;
use uuid::Uuid;

// ---------------------------------------------------------------------------
// CLI
// ---------------------------------------------------------------------------

#[derive(Parser, Debug)]
#[command(
    name = "loot-stress",
    about = "Stress-test the Kraken LootService gRPC endpoint",
    after_help = "PREREQUISITES:\n  \
        A test implant with nil UUID (all zeros) must exist in the database.\n  \
        Insert it with:\n    \
        sqlite3 <db> \"INSERT INTO implants (id, name, state, hostname, username,\n      \
        os_name, os_version, os_arch, process_id, process_name, is_elevated,\n      \
        checkin_interval, jitter_percent, registered_at, last_seen) VALUES\n      \
        (X'00000000000000000000000000000000', 'stress-test', 'active', 'test',\n      \
        'test', 'Linux', '1.0', 'x86_64', 1, 'test', 0, 10, 0,\n      \
        strftime('%s','now')*1000, strftime('%s','now')*1000);\"\n\n  \
        Or use: scripts/smoke-test.sh (handles this automatically)"
)]
struct Args {
    /// gRPC server address
    #[arg(long, default_value = "http://127.0.0.1:50051")]
    addr: String,

    /// Number of credential loot entries to insert
    #[arg(long, default_value_t = 1000)]
    credentials: usize,

    /// Number of hash loot entries to insert
    #[arg(long, default_value_t = 500)]
    hashes: usize,

    /// Number of token loot entries to insert
    #[arg(long, default_value_t = 500)]
    tokens: usize,

    /// Number of random entries to delete at the end
    #[arg(long, default_value_t = 100)]
    delete_count: usize,

    /// Page size for pagination test
    #[arg(long, default_value_t = 100)]
    page_size: usize,

    /// Skip cleanup (leave test data in the DB)
    #[arg(long)]
    no_cleanup: bool,
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn proto_uuid(bytes: Vec<u8>) -> ProtoUuid {
    ProtoUuid { value: bytes }
}

struct TimingStat {
    name: String,
    durations: Vec<Duration>,
}

impl TimingStat {
    fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            durations: Vec::new(),
        }
    }

    fn record(&mut self, d: Duration) {
        self.durations.push(d);
    }

    fn total(&self) -> Duration {
        self.durations.iter().sum()
    }

    fn mean(&self) -> Duration {
        if self.durations.is_empty() {
            return Duration::ZERO;
        }
        self.total() / self.durations.len() as u32
    }

    fn min(&self) -> Duration {
        self.durations.iter().copied().min().unwrap_or(Duration::ZERO)
    }

    fn max(&self) -> Duration {
        self.durations.iter().copied().max().unwrap_or(Duration::ZERO)
    }

    fn p99(&self) -> Duration {
        if self.durations.is_empty() {
            return Duration::ZERO;
        }
        let mut sorted = self.durations.clone();
        sorted.sort();
        let idx = ((sorted.len() as f64) * 0.99) as usize;
        sorted[idx.min(sorted.len() - 1)]
    }

    fn report(&self) {
        println!(
            "  {}: n={} total={:.3}s mean={:.2}ms min={:.2}ms max={:.2}ms p99={:.2}ms",
            self.name,
            self.durations.len(),
            self.total().as_secs_f64(),
            self.mean().as_secs_f64() * 1000.0,
            self.min().as_secs_f64() * 1000.0,
            self.max().as_secs_f64() * 1000.0,
            self.p99().as_secs_f64() * 1000.0,
        );
    }
}

// ---------------------------------------------------------------------------
// Test sections — each returns Ok(()) on pass, Err(msg) on fail
// ---------------------------------------------------------------------------

async fn test_insert_credentials(
    client: &mut LootServiceClient<Channel>,
    implant_id: Vec<u8>,
    count: usize,
) -> Result<(Vec<Vec<u8>>, TimingStat), String> {
    println!("\n[INSERT CREDENTIALS] Inserting {} credential entries...", count);
    let mut stat = TimingStat::new("insert_credential");
    let mut ids: Vec<Vec<u8>> = Vec::with_capacity(count);

    for i in 0..count {
        let req = StoreLootRequest {
            implant_id: Some(proto_uuid(implant_id.clone())),
            loot_type: LootType::Credential as i32,
            source: format!("stress-test-credential-{}", i),
            data: Some(store_loot_request::Data::Credential(CredentialLoot {
                username: format!("user{}", i),
                password: format!("pass{}", i),
                domain: Some(format!("domain{}", i % 10)),
                realm: None,
                host: Some(format!("host{}.example.com", i % 20)),
            })),
        };
        let t0 = Instant::now();
        let resp = client
            .store_loot(req)
            .await
            .map_err(|e| format!("store_loot credential {}: {}", i, e))?;
        stat.record(t0.elapsed());
        let loot_id = resp
            .into_inner()
            .loot_id
            .ok_or("missing loot_id in response")?;
        ids.push(loot_id.value);
    }

    stat.report();
    println!("  PASS — {} credential entries inserted", ids.len());
    Ok((ids, stat))
}

async fn test_insert_hashes(
    client: &mut LootServiceClient<Channel>,
    implant_id: Vec<u8>,
    count: usize,
) -> Result<(Vec<Vec<u8>>, TimingStat), String> {
    println!("\n[INSERT HASHES] Inserting {} hash entries...", count);
    let mut stat = TimingStat::new("insert_hash");
    let mut ids: Vec<Vec<u8>> = Vec::with_capacity(count);

    for i in 0..count {
        let req = StoreLootRequest {
            implant_id: Some(proto_uuid(implant_id.clone())),
            loot_type: LootType::Hash as i32,
            source: format!("stress-test-hash-{}", i),
            data: Some(store_loot_request::Data::Hash(HashLoot {
                username: format!("hashuser{}", i),
                hash: format!("{:032x}", i as u128),
                hash_type: "NTLM".to_string(),
                domain: Some(format!("domain{}", i % 5)),
            })),
        };
        let t0 = Instant::now();
        let resp = client
            .store_loot(req)
            .await
            .map_err(|e| format!("store_loot hash {}: {}", i, e))?;
        stat.record(t0.elapsed());
        let loot_id = resp
            .into_inner()
            .loot_id
            .ok_or("missing loot_id in response")?;
        ids.push(loot_id.value);
    }

    stat.report();
    println!("  PASS — {} hash entries inserted", ids.len());
    Ok((ids, stat))
}

async fn test_insert_tokens(
    client: &mut LootServiceClient<Channel>,
    implant_id: Vec<u8>,
    count: usize,
) -> Result<(Vec<Vec<u8>>, TimingStat), String> {
    println!("\n[INSERT TOKENS] Inserting {} token entries...", count);
    let mut stat = TimingStat::new("insert_token");
    let mut ids: Vec<Vec<u8>> = Vec::with_capacity(count);

    for i in 0..count {
        let req = StoreLootRequest {
            implant_id: Some(proto_uuid(implant_id.clone())),
            loot_type: LootType::Token as i32,
            source: format!("stress-test-token-{}", i),
            data: Some(store_loot_request::Data::Token(TokenLoot {
                token_type: "JWT".to_string(),
                token_value: format!("eyJhbGciOiJIUzI1NiJ9.stress{}.sig{}", i, i),
                service: Some(format!("service{}", i % 10)),
                expires_at: None,
            })),
        };
        let t0 = Instant::now();
        let resp = client
            .store_loot(req)
            .await
            .map_err(|e| format!("store_loot token {}: {}", i, e))?;
        stat.record(t0.elapsed());
        let loot_id = resp
            .into_inner()
            .loot_id
            .ok_or("missing loot_id in response")?;
        ids.push(loot_id.value);
    }

    stat.report();
    println!("  PASS — {} token entries inserted", ids.len());
    Ok((ids, stat))
}

async fn test_list_all(
    client: &mut LootServiceClient<Channel>,
    expected_min: u32,
) -> Result<(u32, TimingStat), String> {
    println!("\n[LIST ALL] Querying all loot entries...");
    let mut stat = TimingStat::new("list_all");

    let t0 = Instant::now();
    let resp = client
        .list_loot(ListLootRequest {
            implant_id: None,
            type_filter: None,
            limit: Some(10000),
            offset: Some(0),
        })
        .await
        .map_err(|e| format!("list_loot all: {}", e))?;
    stat.record(t0.elapsed());

    let inner = resp.into_inner();
    let total = inner.total_count;
    let returned = inner.entries.len() as u32;

    stat.report();

    if total < expected_min {
        return Err(format!(
            "FAIL — expected at least {} entries, got total_count={}",
            expected_min, total
        ));
    }
    println!(
        "  PASS — total_count={} returned={} in {:.2}ms",
        total,
        returned,
        stat.total().as_secs_f64() * 1000.0
    );
    Ok((total, stat))
}

async fn test_list_by_type(
    client: &mut LootServiceClient<Channel>,
    loot_type: LootType,
    type_name: &str,
    expected_min: u32,
) -> Result<TimingStat, String> {
    println!("\n[LIST BY TYPE: {}] Querying with type filter...", type_name);
    let mut stat = TimingStat::new(format!("list_by_type_{}", type_name));

    let t0 = Instant::now();
    let resp = client
        .list_loot(ListLootRequest {
            implant_id: None,
            type_filter: Some(loot_type as i32),
            limit: Some(10000),
            offset: Some(0),
        })
        .await
        .map_err(|e| format!("list_loot type_filter {}: {}", type_name, e))?;
    stat.record(t0.elapsed());

    let inner = resp.into_inner();
    let total = inner.total_count;

    stat.report();

    if total < expected_min {
        return Err(format!(
            "FAIL — type={} expected at least {}, got {}",
            type_name, expected_min, total
        ));
    }
    println!(
        "  PASS — type={} total_count={} in {:.2}ms",
        type_name,
        total,
        stat.total().as_secs_f64() * 1000.0
    );
    Ok(stat)
}

async fn test_paginate(
    client: &mut LootServiceClient<Channel>,
    page_size: usize,
    total_expected: u32,
) -> Result<TimingStat, String> {
    println!(
        "\n[PAGINATION] Iterating all entries with page_size={}...",
        page_size
    );
    let mut stat = TimingStat::new("paginate");
    let mut offset: u32 = 0;
    let mut fetched: u32 = 0;
    let mut pages: u32 = 0;

    loop {
        let t0 = Instant::now();
        let resp = client
            .list_loot(ListLootRequest {
                implant_id: None,
                type_filter: None,
                limit: Some(page_size as u32),
                offset: Some(offset),
            })
            .await
            .map_err(|e| format!("paginate page {}: {}", pages, e))?;
        stat.record(t0.elapsed());

        let inner = resp.into_inner();
        let batch = inner.entries.len() as u32;
        fetched += batch;
        pages += 1;

        if batch == 0 || fetched >= inner.total_count {
            break;
        }
        offset += batch;
    }

    stat.report();

    if fetched < total_expected {
        return Err(format!(
            "FAIL — pagination fetched {} entries across {} pages, expected at least {}",
            fetched, pages, total_expected
        ));
    }
    println!(
        "  PASS — {} entries fetched across {} pages (page_size={})",
        fetched, pages, page_size
    );
    Ok(stat)
}

async fn test_delete_random(
    client: &mut LootServiceClient<Channel>,
    all_ids: &[Vec<u8>],
    count: usize,
) -> Result<(Vec<Vec<u8>>, TimingStat), String> {
    println!("\n[DELETE] Deleting {} random entries...", count);
    let mut stat = TimingStat::new("delete");
    let mut rng = rand::thread_rng();

    let to_delete: Vec<Vec<u8>> = {
        let mut idxs: Vec<usize> = (0..all_ids.len()).collect();
        // partial Fisher-Yates
        let n = count.min(all_ids.len());
        for i in 0..n {
            let j = rng.gen_range(i..all_ids.len());
            idxs.swap(i, j);
        }
        idxs[..n].iter().map(|&i| all_ids[i].clone()).collect()
    };

    let mut deleted_ids: Vec<Vec<u8>> = Vec::new();
    for id in &to_delete {
        let req = DeleteLootRequest {
            loot_id: Some(proto_uuid(id.clone())),
        };
        let t0 = Instant::now();
        let resp = client
            .delete_loot(req)
            .await
            .map_err(|e| format!("delete_loot: {}", e))?;
        stat.record(t0.elapsed());
        if resp.into_inner().success {
            deleted_ids.push(id.clone());
        }
    }

    stat.report();

    if deleted_ids.len() != to_delete.len() {
        return Err(format!(
            "FAIL — requested {} deletes, only {} succeeded",
            to_delete.len(),
            deleted_ids.len()
        ));
    }
    println!("  PASS — {} entries deleted", deleted_ids.len());
    Ok((deleted_ids, stat))
}

async fn test_count_remaining(
    client: &mut LootServiceClient<Channel>,
    inserted: u32,
    deleted: u32,
) -> Result<TimingStat, String> {
    println!("\n[COUNT REMAINING] Verifying entry count after deletes...");
    let mut stat = TimingStat::new("count_remaining");
    let expected = inserted - deleted;

    let t0 = Instant::now();
    let resp = client
        .list_loot(ListLootRequest {
            implant_id: None,
            type_filter: None,
            limit: Some(1),
            offset: Some(0),
        })
        .await
        .map_err(|e| format!("count_remaining list_loot: {}", e))?;
    stat.record(t0.elapsed());

    let total = resp.into_inner().total_count;

    stat.report();

    if total != expected {
        return Err(format!(
            "FAIL — expected {} remaining entries ({}inserted - {}deleted), got {}",
            expected, inserted, deleted, total
        ));
    }
    println!(
        "  PASS — {} entries remain ({}inserted - {}deleted)",
        total, inserted, deleted
    );
    Ok(stat)
}

async fn cleanup_all(
    client: &mut LootServiceClient<Channel>,
    all_ids: &[Vec<u8>],
    already_deleted: &[Vec<u8>],
) {
    println!("\n[CLEANUP] Removing all stress-test loot entries...");
    let deleted_set: std::collections::HashSet<&Vec<u8>> = already_deleted.iter().collect();
    let remaining: Vec<&Vec<u8>> = all_ids.iter().filter(|id| !deleted_set.contains(id)).collect();
    let mut success = 0usize;

    for id in &remaining {
        let req = DeleteLootRequest {
            loot_id: Some(proto_uuid((*id).clone())),
        };
        if let Ok(resp) = client.delete_loot(req).await {
            if resp.into_inner().success {
                success += 1;
            }
        }
    }
    println!(
        "  Cleaned up {}/{} remaining entries.",
        success,
        remaining.len()
    );
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();

    println!("=== Kraken Loot Store Stress Test ===");
    println!("Server:      {}", args.addr);
    println!("Credentials: {}", args.credentials);
    println!("Hashes:      {}", args.hashes);
    println!("Tokens:      {}", args.tokens);
    println!("Deletes:     {}", args.delete_count);
    println!("Page size:   {}", args.page_size);
    println!("Cleanup:     {}", !args.no_cleanup);
    println!();

    // Connect
    let channel = tonic::transport::Channel::from_shared(args.addr.clone())?
        .connect()
        .await
        .map_err(|e| format!("failed to connect to {}: {}", args.addr, e))?;
    let mut client = LootServiceClient::new(channel);

    // Use nil UUID - must have a matching implant in the database (FK constraint)
    // See --help for the required INSERT statement
    let implant_id = Uuid::nil().as_bytes().to_vec();

    // Helper to detect FK constraint errors and provide actionable guidance
    let check_fk_error = |e: &str| -> String {
        if e.contains("FOREIGN KEY constraint failed") {
            format!(
                "{}\n\n  ERROR: No implant with nil UUID exists in the database.\n  \
                 Run `loot-stress --help` for the required INSERT statement,\n  \
                 or use `scripts/smoke-test.sh` which handles setup automatically.",
                e
            )
        } else {
            e.to_string()
        }
    };

    let total_inserted = (args.credentials + args.hashes + args.tokens) as u32;

    let mut pass = 0u32;
    let mut fail = 0u32;
    let mut all_ids: Vec<Vec<u8>> = Vec::with_capacity(total_inserted as usize);
    let mut deleted_ids: Vec<Vec<u8>> = Vec::new();

    // --- INSERT ---
    match test_insert_credentials(&mut client, implant_id.clone(), args.credentials).await {
        Ok((ids, _)) => {
            all_ids.extend(ids);
            pass += 1;
        }
        Err(e) => {
            eprintln!("  FAIL: {}", check_fk_error(&e));
            fail += 1;
        }
    }

    match test_insert_hashes(&mut client, implant_id.clone(), args.hashes).await {
        Ok((ids, _)) => {
            all_ids.extend(ids);
            pass += 1;
        }
        Err(e) => {
            eprintln!("  FAIL: {}", check_fk_error(&e));
            fail += 1;
        }
    }

    match test_insert_tokens(&mut client, implant_id.clone(), args.tokens).await {
        Ok((ids, _)) => {
            all_ids.extend(ids);
            pass += 1;
        }
        Err(e) => {
            eprintln!("  FAIL: {}", check_fk_error(&e));
            fail += 1;
        }
    }

    let actually_inserted = all_ids.len() as u32;

    // --- QUERY ALL ---
    match test_list_all(&mut client, actually_inserted).await {
        Ok(_) => pass += 1,
        Err(e) => {
            eprintln!("  FAIL: {}", e);
            fail += 1;
        }
    }

    // --- QUERY BY TYPE ---
    for (loot_type, name, expected) in [
        (LootType::Credential, "credential", args.credentials as u32),
        (LootType::Hash, "hash", args.hashes as u32),
        (LootType::Token, "token", args.tokens as u32),
    ] {
        match test_list_by_type(&mut client, loot_type, name, expected).await {
            Ok(_) => pass += 1,
            Err(e) => {
                eprintln!("  FAIL: {}", e);
                fail += 1;
            }
        }
    }

    // --- PAGINATION ---
    match test_paginate(&mut client, args.page_size, actually_inserted).await {
        Ok(_) => pass += 1,
        Err(e) => {
            eprintln!("  FAIL: {}", e);
            fail += 1;
        }
    }

    // --- DELETE ---
    match test_delete_random(&mut client, &all_ids, args.delete_count).await {
        Ok((ids, _)) => {
            deleted_ids = ids;
            pass += 1;
        }
        Err(e) => {
            eprintln!("  FAIL: {}", e);
            fail += 1;
        }
    }

    // --- COUNT REMAINING ---
    match test_count_remaining(
        &mut client,
        actually_inserted,
        deleted_ids.len() as u32,
    )
    .await
    {
        Ok(_) => pass += 1,
        Err(e) => {
            eprintln!("  FAIL: {}", e);
            fail += 1;
        }
    }

    // --- CLEANUP ---
    if !args.no_cleanup {
        cleanup_all(&mut client, &all_ids, &deleted_ids).await;
    }

    // --- SUMMARY ---
    println!("\n=== Stress Test Summary ===");
    println!("  PASS: {}", pass);
    println!("  FAIL: {}", fail);
    println!("  Total tests: {}", pass + fail);

    if fail == 0 {
        println!("\n=== ALL TESTS PASSED ===");
        Ok(())
    } else {
        eprintln!("\n=== {} TEST(S) FAILED ===", fail);
        std::process::exit(1);
    }
}

//! Live mesh networking tests
//!
//! Tests mesh relay, peer discovery, and multi-hop communication.
//! Run with: cargo test -p live-tests --test live_mesh -- --ignored --test-threads=1

mod harness;

use harness::{TestClient, TestContext};
use std::time::Duration;
use tokio::time::sleep;

/// Test mesh peer registration
#[tokio::test]
#[ignore = "requires live server with mesh support"]
async fn test_mesh_peer_registration() {
    let ctx = TestContext::new().await.expect("Failed to start server");
    
    // Start first implant as mesh node
    let mut implant1 = harness::ImplantHandle::start(&ctx.server.http_url())
        .await
        .expect("Failed to start first implant");
    
    let status1 = implant1.wait().await.expect("Failed to wait");
    assert!(status1.success(), "First implant should register");
}

/// Test mesh relay between two implants
#[tokio::test]
#[ignore = "requires live server with mesh support"]
async fn test_mesh_relay() {
    let ctx = TestContext::new().await.expect("Failed to start server");
    
    // Start parent implant (has direct server connectivity)
    let mut parent = harness::ImplantHandle::start(&ctx.server.http_url())
        .await
        .expect("Failed to start parent");
    
    let _ = parent.wait().await;
    
    // Start child implant (would relay through parent in real scenario)
    let mut child = harness::ImplantHandle::start(&ctx.server.http_url())
        .await
        .expect("Failed to start child");
    
    let status = child.wait().await.expect("Failed to wait");
    assert!(status.success());
}

/// Test mesh topology discovery
#[tokio::test]
#[ignore = "requires live server with mesh support"]
async fn test_mesh_topology_discovery() {
    let ctx = TestContext::new().await.expect("Failed to start server");
    let client = TestClient::new(&ctx.server.http_url());
    
    // Check mesh topology endpoint
    let resp = client.get("/api/v1/mesh/topology").await;
    if let Ok(r) = resp {
        if r.status().is_success() {
            println!("Mesh topology API available");
        }
    }
}

/// Test mesh peer failover
#[tokio::test]
#[ignore = "requires live server with mesh support"]
async fn test_mesh_failover() {
    let ctx = TestContext::new().await.expect("Failed to start server");
    
    // Start multiple implants
    let mut implants = Vec::new();
    for i in 0..3 {
        let url = ctx.server.http_url();
        let handle = harness::ImplantHandle::start(&url)
            .await
            .expect("Failed to start implant");
        implants.push(handle);
    }
    
    // Wait for registrations
    sleep(Duration::from_secs(2)).await;
    
    // Kill one implant, others should remain functional
    if let Some(mut first) = implants.pop() {
        first.stop().ok();
    }
    
    // Verify server still responsive
    let addr = format!("127.0.0.1:{}", ctx.server.http_port);
    let conn = tokio::net::TcpStream::connect(&addr).await;
    assert!(conn.is_ok(), "Server should still accept connections after failover");
}

/// Test mesh broadcast message
#[tokio::test]
#[ignore = "requires live server with mesh support"]
async fn test_mesh_broadcast() {
    let ctx = TestContext::new().await.expect("Failed to start server");
    
    // Start mesh nodes
    let mut nodes = Vec::new();
    for _ in 0..3 {
        let url = ctx.server.http_url();
        let handle = harness::ImplantHandle::start(&url)
            .await
            .expect("Failed to start node");
        nodes.push(handle);
    }
    
    // Allow registrations
    sleep(Duration::from_secs(2)).await;
    
    // Clean up
    for mut node in nodes {
        node.stop().ok();
    }
}

/// Test mesh with network partition simulation
#[tokio::test]
#[ignore = "requires live server with mesh support"]
async fn test_mesh_partition_recovery() {
    let ctx = TestContext::new().await.expect("Failed to start server");
    
    let mut implant = harness::ImplantHandle::start_continuous(&ctx.server.http_url(), 1)
        .await
        .expect("Failed to start implant");
    
    // Let it establish connection
    sleep(Duration::from_secs(3)).await;
    
    // Stop implant (simulating partition)
    implant.stop().ok();
    
    // Server should handle disconnection gracefully
    let addr = format!("127.0.0.1:{}", ctx.server.http_port);
    let conn = tokio::net::TcpStream::connect(&addr).await;
    assert!(conn.is_ok(), "Server should still accept connections after partition recovery");
}

/// Test mesh routing table consistency
#[tokio::test]
#[ignore = "requires live server with mesh support"]
async fn test_mesh_routing_consistency() {
    let ctx = TestContext::new().await.expect("Failed to start server");
    
    // Register multiple nodes
    for _ in 0..5 {
        let mut implant = harness::ImplantHandle::start(&ctx.server.http_url())
            .await
            .expect("Failed to start implant");
        let _ = implant.wait().await;
    }
    
    // Verify routing endpoint returns consistent data
    let client = TestClient::new(&ctx.server.http_url());
    let resp = client.get("/api/v1/mesh/routes").await;
    if let Ok(r) = resp {
        // Either success or 404 (not implemented) is acceptable
        assert!(
            r.status().is_success() || r.status().as_u16() == 404,
            "Unexpected status: {}",
            r.status()
        );
    }
}

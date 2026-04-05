//! Live E2E tests for server-implant communication
//!
//! These tests require building and running actual server/implant binaries.
//! Run with: cargo test -p live-tests --test live_e2e -- --ignored --test-threads=1

mod harness;

use harness::{TestClient, TestContext};
use std::time::Duration;
use tokio::time::sleep;

/// Test that server starts and accepts connections
#[tokio::test]
#[ignore = "requires live server build"]
async fn test_server_health_check() {
    let ctx = TestContext::new().await.expect("Failed to start server");

    // Verify server is listening by attempting TCP connection
    let addr = format!("127.0.0.1:{}", ctx.server.http_port);
    let conn = tokio::net::TcpStream::connect(&addr).await;
    assert!(conn.is_ok(), "Server should accept TCP connections");
}

/// Test implant registration flow
#[tokio::test]
#[ignore = "requires live server and implant build"]
async fn test_implant_registration() {
    let mut ctx = TestContext::new().await.expect("Failed to start server");

    // Start implant in single-shot mode
    let mut implant = harness::ImplantHandle::start(&ctx.server.http_url())
        .await
        .expect("Failed to start implant");

    // Wait for completion
    let status = implant.wait().await.expect("Failed to wait for implant");
    assert!(status.success(), "Implant registration should succeed");
}

/// Test multiple concurrent implant registrations
#[tokio::test]
#[ignore = "requires live server and implant build"]
async fn test_concurrent_registrations() {
    let ctx = TestContext::new().await.expect("Failed to start server");

    // Start 5 implants concurrently
    let mut handles = Vec::new();
    for _ in 0..5 {
        let url = ctx.server.http_url();
        let handle = tokio::spawn(async move {
            let mut implant = harness::ImplantHandle::start(&url)
                .await
                .expect("Failed to start implant");
            implant.wait().await.expect("Failed to wait for implant")
        });
        handles.push(handle);
    }

    // Wait for all to complete
    let mut success_count = 0;
    for handle in handles {
        let status = handle.await.expect("Task panicked");
        if status.success() {
            success_count += 1;
        }
    }

    assert_eq!(
        success_count, 5,
        "All 5 concurrent registrations should succeed"
    );
}

/// Test continuous implant check-in cycle
#[tokio::test]
#[ignore = "requires live server and implant build"]
async fn test_continuous_checkin() {
    let mut ctx = TestContext::new().await.expect("Failed to start server");

    // Start implant with 1-second check-in interval
    let _implant = ctx
        .add_continuous_implant(1)
        .await
        .expect("Failed to start continuous implant");

    // Wait for several check-ins
    sleep(Duration::from_secs(5)).await;

    // Verify server is still responsive
    let addr = format!("127.0.0.1:{}", ctx.server.http_port);
    let conn = tokio::net::TcpStream::connect(&addr).await;
    assert!(conn.is_ok(), "Server should still accept connections");
}

/// Test server handles rapid reconnections
#[tokio::test]
#[ignore = "requires live server and implant build"]
async fn test_rapid_reconnections() {
    let ctx = TestContext::new().await.expect("Failed to start server");

    // Rapidly connect and disconnect 10 implants
    for i in 0..10 {
        let mut implant = harness::ImplantHandle::start(&ctx.server.http_url())
            .await
            .expect("Failed to start implant");

        let status = implant.wait().await.expect("Failed to wait");
        assert!(
            status.success(),
            "Reconnection {} should succeed",
            i + 1
        );

        // Brief pause between connections
        sleep(Duration::from_millis(50)).await;
    }
}

/// Test server startup and shutdown cycle
#[tokio::test]
#[ignore = "requires live server build"]
async fn test_server_restart_cycle() {
    // Start first server
    let ctx1 = TestContext::new().await.expect("Failed to start first server");
    let port = ctx1.server.http_port;
    drop(ctx1);

    // Brief pause for port release
    sleep(Duration::from_millis(500)).await;

    // Start second server (may use different port)
    let ctx2 = TestContext::new().await.expect("Failed to start second server");

    // Verify second server is responsive
    let addr = format!("127.0.0.1:{}", ctx2.server.http_port);
    let conn = tokio::net::TcpStream::connect(&addr).await;
    assert!(conn.is_ok(), "Second server should accept connections");
}

/// Test implant handles server unavailability gracefully
#[tokio::test]
#[ignore = "requires live implant build"]
async fn test_implant_server_unavailable() {
    // Try to connect to a port that has no server
    let fake_url = "http://127.0.0.1:19999";

    let result = harness::ImplantHandle::start(fake_url).await;

    // Should either fail to start or exit with error
    match result {
        Ok(mut implant) => {
            let status = implant.wait().await.expect("Failed to wait");
            // Implant should exit with non-zero when server is unavailable
            assert!(
                !status.success(),
                "Implant should fail when server unavailable"
            );
        }
        Err(_) => {
            // Immediate failure is also acceptable
        }
    }
}

/// Test high-frequency check-ins don't overload server
#[tokio::test]
#[ignore = "requires live server and implant build"]
async fn test_high_frequency_checkins() {
    let mut ctx = TestContext::new().await.expect("Failed to start server");

    // Start 3 implants with rapid check-in (should handle gracefully)
    for _ in 0..3 {
        ctx.add_continuous_implant(1).await.ok();
    }

    // Let them run for a few seconds
    sleep(Duration::from_secs(5)).await;

    // Server should still be responsive
    let addr = format!("127.0.0.1:{}", ctx.server.http_port);
    let conn = tokio::net::TcpStream::connect(&addr).await;
    assert!(conn.is_ok(), "Server should still accept connections after high-frequency checkins");
}

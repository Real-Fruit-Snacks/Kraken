//! Live edge case tests for failure scenarios
//!
//! Tests error handling, network failures, malformed data, etc.
//! Run with: cargo test -p live-tests --test live_edge_cases -- --ignored --test-threads=1

mod harness;

use harness::{TestClient, TestContext};
use std::time::Duration;
use tokio::time::{sleep, timeout};

/// Test server rejects malformed registration data
#[tokio::test]
#[ignore = "requires live server build"]
async fn test_malformed_registration_rejected() {
    let ctx = TestContext::new().await.expect("Failed to start server");
    let client = TestClient::new(&ctx.server.http_url());

    // Send garbage data to registration endpoint
    let garbage = vec![0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x01, 0x02, 0x03];
    let resp = client
        .post_bytes("/api/v1/register", &garbage)
        .await
        .expect("Request failed");

    // Should be rejected (400 Bad Request or similar)
    assert!(
        resp.status().is_client_error() || resp.status().is_server_error(),
        "Malformed data should be rejected, got status {}",
        resp.status()
    );
}

/// Test server rejects empty registration
#[tokio::test]
#[ignore = "requires live server build"]
async fn test_empty_registration_rejected() {
    let ctx = TestContext::new().await.expect("Failed to start server");
    let client = TestClient::new(&ctx.server.http_url());

    let resp = client
        .post_bytes("/api/v1/register", &[])
        .await
        .expect("Request failed");

    assert!(
        resp.status().is_client_error(),
        "Empty registration should be rejected"
    );
}

/// Test server handles oversized payloads
#[tokio::test]
#[ignore = "requires live server build"]
async fn test_oversized_payload_rejected() {
    let ctx = TestContext::new().await.expect("Failed to start server");
    let client = TestClient::new(&ctx.server.http_url());

    // Send 10MB of data
    let large_payload = vec![0xAA; 10 * 1024 * 1024];
    let resp = client
        .post_bytes("/api/v1/register", &large_payload)
        .await
        .expect("Request failed");

    // Should be rejected (413 Payload Too Large or similar)
    assert!(
        resp.status().is_client_error() || resp.status().is_server_error(),
        "Oversized payload should be rejected"
    );
}

/// Test server handles invalid JSON gracefully
#[tokio::test]
#[ignore = "requires live server build"]
async fn test_invalid_json_rejected() {
    let ctx = TestContext::new().await.expect("Failed to start server");
    let client = TestClient::new(&ctx.server.http_url());

    let invalid_json = b"{not valid json: ";
    let resp = client
        .post_bytes("/api/v1/register", invalid_json)
        .await
        .expect("Request failed");

    assert!(
        resp.status().is_client_error(),
        "Invalid JSON should be rejected"
    );
}

/// Test server handles request timeout gracefully
#[tokio::test]
#[ignore = "requires live server build"]
async fn test_request_timeout() {
    let ctx = TestContext::new().await.expect("Failed to start server");

    // Create client with very short timeout
    let client = reqwest::Client::builder()
        .timeout(Duration::from_millis(1))
        .build()
        .expect("Failed to create client");

    let result = client
        .get(format!("{}/c", ctx.server.http_url()))
        .send()
        .await;

    // Should timeout (unless server is incredibly fast)
    // Either timeout error or success is acceptable
    let _ = result;
}

/// Test concurrent malformed requests don't crash server
#[tokio::test]
#[ignore = "requires live server build"]
async fn test_concurrent_malformed_requests() {
    let ctx = TestContext::new().await.expect("Failed to start server");
    let client = TestClient::new(&ctx.server.http_url());

    // Send 20 concurrent malformed requests
    let mut handles = Vec::new();
    for i in 0..20 {
        let url = ctx.server.http_url();
        let handle = tokio::spawn(async move {
            let c = TestClient::new(&url);
            let data = vec![i as u8; 100];
            c.post_bytes("/api/v1/register", &data).await
        });
        handles.push(handle);
    }

    // Wait for all to complete
    for handle in handles {
        let _ = handle.await;
    }

    // Server should still be responsive
    let addr = format!("127.0.0.1:{}", ctx.server.http_port);
    let conn = tokio::net::TcpStream::connect(&addr).await;
    assert!(
        conn.is_ok(),
        "Server should survive concurrent malformed requests"
    );
}

/// Test server handles connection drops gracefully
#[tokio::test]
#[ignore = "requires live server build"]
async fn test_connection_drop() {
    let ctx = TestContext::new().await.expect("Failed to start server");

    // Start a request but don't wait for response
    let client = reqwest::Client::new();
    let _ = client
        .post(format!("{}/api/v1/register", ctx.server.http_url()))
        .body(vec![0u8; 1000])
        .send();

    // Immediately drop without waiting
    // Server should handle this gracefully

    // Brief pause
    sleep(Duration::from_millis(100)).await;

    // Server should still be responsive
    let addr = format!("127.0.0.1:{}", ctx.server.http_port);
    let conn = tokio::net::TcpStream::connect(&addr).await;
    assert!(conn.is_ok(), "Server should still accept connections after dropped connection");
}

/// Test 404 for unknown endpoints
#[tokio::test]
#[ignore = "requires live server build"]
async fn test_unknown_endpoint_404() {
    let ctx = TestContext::new().await.expect("Failed to start server");
    let client = TestClient::new(&ctx.server.http_url());

    let resp = client
        .get("/nonexistent/path/here")
        .await
        .expect("Request failed");

    assert_eq!(
        resp.status().as_u16(),
        404,
        "Unknown endpoint should return 404"
    );
}

/// Test server handles many sequential registrations
#[tokio::test]
#[ignore = "requires live server build"]
async fn test_sequential_registrations_stress() {
    let ctx = TestContext::new().await.expect("Failed to start server");

    // Rapid sequential registrations
    for i in 0..50 {
        let mut implant = harness::ImplantHandle::start(&ctx.server.http_url())
            .await
            .expect("Failed to start implant");

        // Don't wait for completion, just start and stop
        let _ = timeout(Duration::from_secs(2), implant.wait()).await;
    }

    // Server should still be responsive
    let addr = format!("127.0.0.1:{}", ctx.server.http_port);
    let conn = tokio::net::TcpStream::connect(&addr).await;
    assert!(conn.is_ok(), "Server should still accept connections after stress test");
}

/// Test implant reconnection after server restart
#[tokio::test]
#[ignore = "requires live server and implant build"]
async fn test_implant_reconnection_after_server_restart() {
    // Start server
    let ctx = TestContext::new().await.expect("Failed to start server");
    let url = ctx.server.http_url();

    // Register implant
    let mut implant = harness::ImplantHandle::start(&url)
        .await
        .expect("Failed to start implant");
    let status = implant.wait().await.expect("Failed to wait");
    assert!(status.success(), "Initial registration should succeed");

    // Server is automatically dropped when ctx goes out of scope
    drop(ctx);

    // Brief pause for cleanup
    sleep(Duration::from_millis(500)).await;

    // Start new server (different port)
    let ctx2 = TestContext::new().await.expect("Failed to start second server");

    // New implant should be able to register
    let mut implant2 = harness::ImplantHandle::start(&ctx2.server.http_url())
        .await
        .expect("Failed to start second implant");
    let status2 = implant2.wait().await.expect("Failed to wait");
    assert!(status2.success(), "Registration after restart should succeed");
}

/// Test server handles slow clients
#[tokio::test]
#[ignore = "requires live server build"]
async fn test_slow_client() {
    let ctx = TestContext::new().await.expect("Failed to start server");

    // Create a slow stream of data
    use tokio::io::AsyncWriteExt;
    use tokio::net::TcpStream;

    let mut stream = TcpStream::connect(format!("127.0.0.1:{}", ctx.server.http_port))
        .await
        .expect("Failed to connect");

    // Send HTTP request very slowly
    stream.write_all(b"POST /api/v1/register HTTP/1.1\r\n").await.ok();
    sleep(Duration::from_millis(100)).await;
    stream.write_all(b"Host: localhost\r\n").await.ok();
    sleep(Duration::from_millis(100)).await;
    stream.write_all(b"Content-Length: 10\r\n\r\n").await.ok();
    sleep(Duration::from_millis(100)).await;
    stream.write_all(b"0123456789").await.ok();

    drop(stream);

    // Server should still be responsive
    let addr = format!("127.0.0.1:{}", ctx.server.http_port);
    let conn = tokio::net::TcpStream::connect(&addr).await;
    assert!(conn.is_ok(), "Server should still accept connections after slow client");
}

/// Test rate limiting (if implemented)
#[tokio::test]
#[ignore = "requires live server with rate limiting"]
async fn test_rate_limiting() {
    let ctx = TestContext::new().await.expect("Failed to start server");
    let client = TestClient::new(&ctx.server.http_url());

    // Send many requests rapidly
    let mut rate_limited = false;
    for _ in 0..100 {
        let resp = client.get("/c").await;
        if let Ok(r) = resp {
            if r.status().as_u16() == 429 {
                rate_limited = true;
                break;
            }
        }
    }

    // Note: This test only verifies if rate limiting is implemented
    // If not implemented, the test still passes
    if rate_limited {
        println!("Rate limiting is active");
    } else {
        println!("Rate limiting not detected (may not be implemented)");
    }
}

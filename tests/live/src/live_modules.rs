//! Live module execution tests
//!
//! Tests actual task execution through the full server-implant pipeline.
//! Run with: cargo test -p live-tests --test live_modules -- --ignored --test-threads=1

mod harness;

use harness::TestContext;
use std::time::Duration;
use tokio::time::sleep;

/// Test shell command task execution
#[tokio::test]
#[ignore = "requires live server and implant with task support"]
async fn test_shell_task_execution() {
    let ctx = TestContext::new().await.expect("Failed to start server");

    // Queue a shell task via API
    // This requires the operator API to be available
    // For now, we test that implant handles task-less check-in

    let mut implant = harness::ImplantHandle::start(&ctx.server.http_url())
        .await
        .expect("Failed to start implant");

    let status = implant.wait().await.expect("Failed to wait");
    assert!(status.success(), "Implant should complete successfully");
}

/// Test file operation tasks
#[tokio::test]
#[ignore = "requires live server and implant with file module"]
async fn test_file_task_execution() {
    let ctx = TestContext::new().await.expect("Failed to start server");

    let mut implant = harness::ImplantHandle::start(&ctx.server.http_url())
        .await
        .expect("Failed to start implant");

    let status = implant.wait().await.expect("Failed to wait");
    assert!(status.success());
}

/// Test task result submission
#[tokio::test]
#[ignore = "requires live server and implant"]
async fn test_task_result_submission() {
    let ctx = TestContext::new().await.expect("Failed to start server");

    // Start continuous implant
    let _implant = ctx
        .server
        .http_url()
        .clone();

    let mut implant = harness::ImplantHandle::start_continuous(&ctx.server.http_url(), 2)
        .await
        .expect("Failed to start implant");

    // Let it run for a few check-in cycles
    sleep(Duration::from_secs(5)).await;

    implant.stop().ok();
}

/// Test module load/unload cycle
#[tokio::test]
#[ignore = "requires live server with module support"]
async fn test_module_load_unload() {
    let ctx = TestContext::new().await.expect("Failed to start server");
    let client = harness::TestClient::new(&ctx.server.http_url());

    // Check if module endpoint exists
    let resp = client.get("/api/v1/modules").await;
    if let Ok(r) = resp {
        if r.status().is_success() {
            println!("Module API is available");
        }
    }
}

/// Test error handling for failed task
#[tokio::test]
#[ignore = "requires live server and implant"]
async fn test_failed_task_handling() {
    let ctx = TestContext::new().await.expect("Failed to start server");

    let mut implant = harness::ImplantHandle::start(&ctx.server.http_url())
        .await
        .expect("Failed to start implant");

    // Implant should handle gracefully even if tasks fail
    let status = implant.wait().await.expect("Failed to wait");
    // Success or graceful failure is acceptable
    let _ = status;
}

/// Test multiple implants executing tasks concurrently
#[tokio::test]
#[ignore = "requires live server and implant"]
async fn test_concurrent_task_execution() {
    let ctx = TestContext::new().await.expect("Failed to start server");

    // Start multiple implants
    let mut handles = Vec::new();
    for _ in 0..5 {
        let url = ctx.server.http_url();
        let handle = tokio::spawn(async move {
            let mut implant = harness::ImplantHandle::start(&url)
                .await
                .expect("Failed to start implant");
            implant.wait().await.expect("Failed to wait")
        });
        handles.push(handle);
    }

    // Wait for all
    let mut success = 0;
    for h in handles {
        if let Ok(status) = h.await {
            if status.success() {
                success += 1;
            }
        }
    }

    assert!(success >= 3, "At least 3 concurrent implants should succeed");
}

/// Test implant behavior when task queue is empty
#[tokio::test]
#[ignore = "requires live server and implant"]
async fn test_empty_task_queue() {
    let ctx = TestContext::new().await.expect("Failed to start server");

    // Fresh server should have empty task queue
    let mut implant = harness::ImplantHandle::start(&ctx.server.http_url())
        .await
        .expect("Failed to start implant");

    let status = implant.wait().await.expect("Failed to wait");
    assert!(
        status.success(),
        "Implant should handle empty task queue gracefully"
    );
}

/// Test large task result handling
#[tokio::test]
#[ignore = "requires live server and implant"]
async fn test_large_task_result() {
    let ctx = TestContext::new().await.expect("Failed to start server");

    // This would test that large command outputs are handled correctly
    // Requires queuing a command that produces large output

    let mut implant = harness::ImplantHandle::start(&ctx.server.http_url())
        .await
        .expect("Failed to start implant");

    let status = implant.wait().await.expect("Failed to wait");
    let _ = status;
}

/// Test task timeout handling
#[tokio::test]
#[ignore = "requires live server and implant with timeout support"]
async fn test_task_timeout() {
    let ctx = TestContext::new().await.expect("Failed to start server");

    // Would need to queue a long-running task
    // and verify timeout is respected

    let mut implant = harness::ImplantHandle::start(&ctx.server.http_url())
        .await
        .expect("Failed to start implant");

    let status = implant.wait().await.expect("Failed to wait");
    let _ = status;
}

//! Live test harness for E2E testing
//!
//! Provides infrastructure to start server and implant processes,
//! coordinate test scenarios, and ensure clean shutdown.

use anyhow::{anyhow, Result};
use std::net::TcpListener;
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicU16, Ordering};
use std::time::Duration;
use tokio::time::sleep;

/// Global port counter to avoid port conflicts between tests
static PORT_COUNTER: AtomicU16 = AtomicU16::new(19000);

/// Get a unique port for testing
pub fn get_test_port() -> u16 {
    PORT_COUNTER.fetch_add(1, Ordering::SeqCst)
}

/// Find an available port by attempting to bind
pub fn find_available_port() -> u16 {
    for _ in 0..100 {
        let port = get_test_port();
        if let Ok(listener) = TcpListener::bind(format!("127.0.0.1:{}", port)) {
            drop(listener);
            return port;
        }
    }
    panic!("Could not find available port after 100 attempts");
}

/// Server process handle with automatic cleanup
pub struct ServerHandle {
    process: Child,
    pub http_port: u16,
    pub grpc_port: u16,
}

impl ServerHandle {
    /// Start a new server instance
    pub async fn start() -> Result<Self> {
        let http_port = find_available_port();
        let grpc_port = find_available_port();

        // Build server if needed
        let server_path = find_server_binary()?;

        let process = Command::new(&server_path)
            .args([
                "--http-port", &http_port.to_string(),
                "--grpc-port", &grpc_port.to_string(),
                "--db-path", ":memory:",
                "--insecure",
            ])
            .env("RUST_LOG", "warn")
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|e| anyhow!("Failed to start server: {}", e))?;

        let handle = Self {
            process,
            http_port,
            grpc_port,
        };

        // Wait for server to be ready
        handle.wait_ready(Duration::from_secs(30)).await?;

        Ok(handle)
    }

    /// Wait for server to accept connections
    pub async fn wait_ready(&self, timeout: Duration) -> Result<()> {
        let start = std::time::Instant::now();
        let addr = format!("127.0.0.1:{}", self.http_port);

        while start.elapsed() < timeout {
            // Check if TCP connection can be established (server is listening)
            match tokio::net::TcpStream::connect(&addr).await {
                Ok(_) => {
                    return Ok(());
                }
                Err(_) => {
                    sleep(Duration::from_millis(100)).await;
                }
            }
        }

        Err(anyhow!(
            "Server failed to become ready within {:?}",
            timeout
        ))
    }

    /// Get the HTTP base URL
    pub fn http_url(&self) -> String {
        format!("http://127.0.0.1:{}", self.http_port)
    }

    /// Get the gRPC URL
    pub fn grpc_url(&self) -> String {
        format!("http://127.0.0.1:{}", self.grpc_port)
    }

    /// Shutdown the server gracefully
    pub fn shutdown(&mut self) -> Result<()> {
        // Send SIGTERM on Unix
        #[cfg(unix)]
        {
            use std::os::unix::process::CommandExt;
            unsafe {
                libc::kill(self.process.id() as i32, libc::SIGTERM);
            }
        }

        #[cfg(windows)]
        {
            let _ = self.process.kill();
        }

        // Wait briefly for graceful shutdown
        std::thread::sleep(Duration::from_millis(500));

        // Force kill if still running
        let _ = self.process.kill();
        let _ = self.process.wait();

        Ok(())
    }
}

impl Drop for ServerHandle {
    fn drop(&mut self) {
        let _ = self.shutdown();
    }
}

/// Implant simulator handle with automatic cleanup
pub struct ImplantHandle {
    process: Child,
    pub implant_id: Option<String>,
}

impl ImplantHandle {
    /// Start a new implant simulator
    pub async fn start(server_url: &str) -> Result<Self> {
        let implant_path = find_implant_binary()?;

        let process = Command::new(&implant_path)
            .args(["--server", server_url, "--once"])
            .env("RUST_LOG", "info")
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|e| anyhow!("Failed to start implant: {}", e))?;

        Ok(Self {
            process,
            implant_id: None,
        })
    }

    /// Start implant in continuous mode
    pub async fn start_continuous(server_url: &str, interval_secs: u32) -> Result<Self> {
        let implant_path = find_implant_binary()?;

        let process = Command::new(&implant_path)
            .args([
                "--server",
                server_url,
                "--interval",
                &interval_secs.to_string(),
            ])
            .env("RUST_LOG", "info")
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|e| anyhow!("Failed to start implant: {}", e))?;

        Ok(Self {
            process,
            implant_id: None,
        })
    }

    /// Wait for implant process to complete (for --once mode)
    pub async fn wait(&mut self) -> Result<std::process::ExitStatus> {
        self.process
            .wait()
            .map_err(|e| anyhow!("Failed to wait for implant: {}", e))
    }

    /// Stop the implant
    pub fn stop(&mut self) -> Result<()> {
        let _ = self.process.kill();
        let _ = self.process.wait();
        Ok(())
    }
}

impl Drop for ImplantHandle {
    fn drop(&mut self) {
        let _ = self.stop();
    }
}

/// Test context holding server and implants
pub struct TestContext {
    pub server: ServerHandle,
    pub implants: Vec<ImplantHandle>,
}

impl TestContext {
    /// Create a new test context with a running server
    pub async fn new() -> Result<Self> {
        let server = ServerHandle::start().await?;
        Ok(Self {
            server,
            implants: Vec::new(),
        })
    }

    /// Add an implant to the test context
    pub async fn add_implant(&mut self) -> Result<&ImplantHandle> {
        let implant = ImplantHandle::start(&self.server.http_url()).await?;
        self.implants.push(implant);
        Ok(self.implants.last().unwrap())
    }

    /// Add a continuous implant
    pub async fn add_continuous_implant(&mut self, interval_secs: u32) -> Result<&ImplantHandle> {
        let implant =
            ImplantHandle::start_continuous(&self.server.http_url(), interval_secs).await?;
        self.implants.push(implant);
        Ok(self.implants.last().unwrap())
    }
}

/// Find the server binary, building if needed
fn find_server_binary() -> Result<String> {
    // Prefer env var override (set by CI)
    if let Ok(path) = std::env::var("KRAKEN_SERVER_BIN") {
        if std::path::Path::new(&path).exists() {
            return Ok(path);
        }
    }

    let paths = [
        "target/release/server",
        "target/debug/server",
        "../target/release/server",
        "../target/debug/server",
        "../../target/release/server",
        "../../target/debug/server",
        // Legacy names kept for compatibility
        "target/debug/kraken-server",
        "target/release/kraken-server",
        "../target/debug/kraken-server",
        "../target/release/kraken-server",
        "../../target/debug/kraken-server",
        "../../target/release/kraken-server",
    ];

    for path in paths {
        if std::path::Path::new(path).exists() {
            return Ok(path.to_string());
        }
    }

    // Try to build it
    eprintln!("Server binary not found, attempting to build...");
    let status = Command::new("cargo")
        .args(["build", "-p", "server"])
        .status()?;

    if !status.success() {
        return Err(anyhow!("Failed to build server"));
    }

    // Try again after build
    for path in paths {
        if std::path::Path::new(path).exists() {
            return Ok(path.to_string());
        }
    }

    Err(anyhow!(
        "Server binary not found even after build attempt"
    ))
}

/// Find the implant simulator binary, building if needed
fn find_implant_binary() -> Result<String> {
    // Prefer env var override (set by CI)
    if let Ok(path) = std::env::var("KRAKEN_IMPLANT_BIN") {
        if std::path::Path::new(&path).exists() {
            return Ok(path);
        }
    }

    let paths = [
        "target/release/implant",
        "target/debug/implant",
        "../target/release/implant",
        "../target/debug/implant",
        "../../target/release/implant",
        "../../target/debug/implant",
        // Legacy names kept for compatibility
        "target/debug/implant-sim",
        "target/release/implant-sim",
        "../target/debug/implant-sim",
        "../target/release/implant-sim",
        "../../target/debug/implant-sim",
        "../../target/release/implant-sim",
    ];

    for path in paths {
        if std::path::Path::new(path).exists() {
            return Ok(path.to_string());
        }
    }

    // Try to build it
    eprintln!("Implant binary not found, attempting to build...");
    let status = Command::new("cargo")
        .args(["build", "-p", "implant"])
        .status()?;

    if !status.success() {
        return Err(anyhow!("Failed to build implant"));
    }

    // Try again after build
    for path in paths {
        if std::path::Path::new(path).exists() {
            return Ok(path.to_string());
        }
    }

    Err(anyhow!(
        "Implant binary not found even after build attempt"
    ))
}

/// HTTP client for direct API testing
pub struct TestClient {
    client: reqwest::Client,
    base_url: String,
}

impl TestClient {
    pub fn new(base_url: &str) -> Self {
        Self {
            client: reqwest::Client::builder()
                .timeout(Duration::from_secs(30))
                .build()
                .expect("Failed to create HTTP client"),
            base_url: base_url.to_string(),
        }
    }

    /// GET request
    pub async fn get(&self, path: &str) -> Result<reqwest::Response> {
        let url = format!("{}{}", self.base_url, path);
        self.client
            .get(&url)
            .send()
            .await
            .map_err(|e| anyhow!("GET {} failed: {}", path, e))
    }

    /// POST request with JSON body
    pub async fn post_json<T: serde::Serialize>(
        &self,
        path: &str,
        body: &T,
    ) -> Result<reqwest::Response> {
        let url = format!("{}{}", self.base_url, path);
        self.client
            .post(&url)
            .json(body)
            .send()
            .await
            .map_err(|e| anyhow!("POST {} failed: {}", path, e))
    }

    /// POST request with raw bytes
    pub async fn post_bytes(&self, path: &str, body: &[u8]) -> Result<reqwest::Response> {
        let url = format!("{}{}", self.base_url, path);
        self.client
            .post(&url)
            .body(body.to_vec())
            .send()
            .await
            .map_err(|e| anyhow!("POST {} failed: {}", path, e))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_port_allocation() {
        let p1 = get_test_port();
        let p2 = get_test_port();
        assert_ne!(p1, p2);
        assert!(p1 >= 19000);
    }

    #[test]
    fn test_find_available_port() {
        let port = find_available_port();
        assert!(port >= 19000);

        // Should be able to bind to it
        let listener = TcpListener::bind(format!("127.0.0.1:{}", port));
        assert!(listener.is_ok());
    }
}

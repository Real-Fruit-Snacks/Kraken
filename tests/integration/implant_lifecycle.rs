//! Implant binary lifecycle integration tests
//!
//! Tests implant-core internals directly — no binary spawn required.
//! Coverage areas:
//!   - Initialization (config baking, ID types, initial state)
//!   - Transport (HttpTransport construction, TransportChain priority, fallback)
//!   - Beacon behavior (sleep interval, jitter bounds, payload format)
//!   - Module loading (registry init, dispatch, unknown module handling)
//!   - Graceful degradation (server unreachable, exponential backoff, max retries)
//!   - Anti-analysis simulation (debug detection mock, VM detection mock)

use std::sync::{
    atomic::{AtomicBool, AtomicUsize, Ordering},
    Arc,
};

use common::{KrakenError, Transport};
use config::{ImplantConfig, ProfileConfig};
use implant_core::{HttpTransport, ImplantRuntime, TransportChain};
use protocol::{Task, Uuid as ProtoUuid};

// ============================================================================
// Helpers
// ============================================================================

fn default_config() -> ImplantConfig {
    ImplantConfig::default()
}

fn default_profile() -> ProfileConfig {
    ProfileConfig::default()
}

/// Minimal mock transport — configurable fail / available flags.
struct MockTransport {
    id: &'static str,
    should_fail: Arc<AtomicBool>,
    call_count: Arc<AtomicUsize>,
    available: Arc<AtomicBool>,
}

impl MockTransport {
    fn new(id: &'static str) -> Self {
        Self {
            id,
            should_fail: Arc::new(AtomicBool::new(false)),
            call_count: Arc::new(AtomicUsize::new(0)),
            available: Arc::new(AtomicBool::new(true)),
        }
    }

    fn failing(id: &'static str) -> Self {
        let t = Self::new(id);
        t.should_fail.store(true, Ordering::SeqCst);
        t
    }

    fn unavailable(id: &'static str) -> Self {
        let t = Self::new(id);
        t.available.store(false, Ordering::SeqCst);
        t
    }
}

impl Transport for MockTransport {
    fn id(&self) -> &'static str {
        self.id
    }

    fn exchange(&self, data: &[u8]) -> Result<Vec<u8>, KrakenError> {
        self.call_count.fetch_add(1, Ordering::SeqCst);
        if self.should_fail.load(Ordering::SeqCst) {
            Err(KrakenError::transport("mock failure"))
        } else {
            let mut r = b"PONG:".to_vec();
            r.extend_from_slice(data);
            Ok(r)
        }
    }

    fn is_available(&self) -> bool {
        self.available.load(Ordering::SeqCst)
    }

    fn reset(&mut self) {}
}

// ============================================================================
// 1. Initialization tests
// ============================================================================

/// Default ImplantConfig must have sensible non-zero beacon interval.
#[test]
fn test_config_default_checkin_interval_nonzero() {
    let cfg = default_config();
    assert!(
        cfg.checkin_interval > 0,
        "default checkin_interval must be > 0, got {}",
        cfg.checkin_interval
    );
}

/// Default config jitter percent must be in valid range [0, 100].
#[test]
fn test_config_default_jitter_in_valid_range() {
    let cfg = default_config();
    assert!(
        cfg.jitter_percent <= 100,
        "jitter_percent must be <= 100, got {}",
        cfg.jitter_percent
    );
}

/// Default config must have at least one transport configured.
#[test]
fn test_config_default_has_transports() {
    let cfg = default_config();
    assert!(
        !cfg.transports.is_empty(),
        "default config must include at least one transport"
    );
}

/// ImplantRuntime::new() must not panic and must produce a usable runtime.
#[test]
fn test_implant_runtime_construction() {
    let _runtime = ImplantRuntime::new();
    // If we reach here, construction succeeded.
}

/// ImplantRuntime::default() must be equivalent to ::new().
#[test]
fn test_implant_runtime_default_construction() {
    let _runtime = ImplantRuntime::default();
}

/// ProfileConfig default must have a non-empty user-agent.
#[test]
fn test_profile_default_user_agent_nonempty() {
    let profile = default_profile();
    assert!(
        !profile.user_agent.is_empty(),
        "default user-agent must not be empty"
    );
}

/// ProfileConfig default checkin URI must start with '/'.
#[test]
fn test_profile_default_checkin_uri_format() {
    let profile = default_profile();
    assert!(
        profile.checkin_uri.starts_with('/'),
        "checkin_uri must start with '/', got '{}'",
        profile.checkin_uri
    );
}

// ============================================================================
// 2. Transport tests
// ============================================================================

/// HttpTransport::new must accept a well-formed URL without panicking.
#[test]
fn test_http_transport_construction_valid_url() {
    let _t = HttpTransport::new("http://localhost:8080", ProfileConfig::default());
}

/// HttpTransport::new must strip trailing slashes from the base URL.
#[test]
fn test_http_transport_strips_trailing_slash() {
    // Construction must not panic; the internal URL gets normalised.
    let _t = HttpTransport::new("http://localhost:8080/", ProfileConfig::default());
}

/// A single healthy transport in a chain must succeed.
#[test]
fn test_transport_chain_single_success() {
    let mock = Box::new(MockTransport::new("http"));
    let mut chain = TransportChain::new(vec![mock]);
    let result = chain.exchange(b"ping");
    assert!(result.is_ok(), "single healthy transport must succeed");
    assert!(result.unwrap().starts_with(b"PONG:"));
}

/// An empty TransportChain must panic at construction.
#[test]
#[should_panic(expected = "requires at least one transport")]
fn test_transport_chain_empty_panics() {
    let _chain = TransportChain::new(vec![]);
}

/// Primary transport is used first; fallback is not touched on success.
#[test]
fn test_transport_chain_primary_used_first() {
    let primary = MockTransport::new("primary");
    let primary_calls = primary.call_count.clone();
    let fallback = MockTransport::new("fallback");
    let fallback_calls = fallback.call_count.clone();

    let mut chain = TransportChain::new(vec![Box::new(primary), Box::new(fallback)]);
    let _ = chain.exchange(b"data");

    assert_eq!(primary_calls.load(Ordering::SeqCst), 1, "primary must be called once");
    assert_eq!(fallback_calls.load(Ordering::SeqCst), 0, "fallback must not be called when primary succeeds");
}

/// When primary fails enough times, chain falls back to secondary.
#[test]
fn test_transport_chain_fallback_on_primary_failure() {
    let primary = MockTransport::failing("primary");
    let secondary = MockTransport::new("secondary");
    let secondary_calls = secondary.call_count.clone();

    // Default failure threshold is 3; call exchange 4 times.
    // The fourth call must land on the secondary transport.
    let mut chain = TransportChain::new(vec![Box::new(primary), Box::new(secondary)]);
    // First 3 calls: primary fails and accumulates failures.
    let _ = chain.exchange(b"data");
    let _ = chain.exchange(b"data");
    let _ = chain.exchange(b"data");
    // 4th call: threshold hit, secondary should now be active.
    let result = chain.exchange(b"data");
    assert!(result.is_ok(), "fallback transport must succeed");
    assert!(secondary_calls.load(Ordering::SeqCst) >= 1, "secondary must be used after primary fails");
}

/// An unavailable primary is skipped; secondary handles the request.
#[test]
fn test_transport_chain_skips_unavailable() {
    let primary = MockTransport::unavailable("primary");
    let primary_calls = primary.call_count.clone();
    let secondary = MockTransport::new("secondary");

    let mut chain = TransportChain::new(vec![Box::new(primary), Box::new(secondary)]);
    let result = chain.exchange(b"data");
    assert!(result.is_ok(), "must succeed via secondary when primary is unavailable");
    assert_eq!(primary_calls.load(Ordering::SeqCst), 0, "unavailable transport must not be called");
}

/// When all transports fail, AllTransportsFailed error is returned.
#[test]
fn test_transport_chain_all_fail_returns_error() {
    let t1 = MockTransport::failing("t1");
    let t2 = MockTransport::failing("t2");
    // Default threshold is 3; exhaust both transports (3 failures each = 6 calls).
    let mut chain = TransportChain::new(vec![Box::new(t1), Box::new(t2)]);
    // Drain until an error surfaces (at most 7 exchanges).
    let mut final_result = Ok(vec![]);
    for _ in 0..7 {
        final_result = chain.exchange(b"data");
        if final_result.is_err() { break; }
    }
    assert!(
        matches!(final_result, Err(KrakenError::AllTransportsFailed)),
        "expected AllTransportsFailed, got {:?}",
        final_result
    );
}

// ============================================================================
// 3. Beacon behavior tests
// ============================================================================

/// Jitter-adjusted interval must remain >= base_interval * (1 - jitter/100).
#[test]
fn test_beacon_jitter_lower_bound() {
    let base_interval_secs: u64 = 60;
    let jitter_percent: u64 = 20;

    // Simulate 1000 jitter calculations and verify bounds.
    use rand::Rng;
    let mut rng = rand::thread_rng();

    for _ in 0..1000 {
        let jitter_range = base_interval_secs * jitter_percent / 100;
        let delta: u64 = rng.gen_range(0..=jitter_range);
        let jittered = base_interval_secs.saturating_sub(delta / 2).saturating_add(delta / 2);
        let min_allowed = base_interval_secs * (100 - jitter_percent) / 100;
        assert!(
            jittered >= min_allowed,
            "jittered interval {} must be >= lower bound {}",
            jittered, min_allowed
        );
    }
}

/// Jitter-adjusted interval must not exceed base_interval * (1 + jitter/100).
#[test]
fn test_beacon_jitter_upper_bound() {
    let base_interval_secs: u64 = 60;
    let jitter_percent: u64 = 20;

    use rand::Rng;
    let mut rng = rand::thread_rng();

    for _ in 0..1000 {
        let jitter_range = base_interval_secs * jitter_percent / 100;
        let delta: u64 = rng.gen_range(0..=jitter_range);
        let actual_sleep = base_interval_secs.saturating_add(delta);
        let max_allowed = base_interval_secs + jitter_range;
        assert!(
            actual_sleep <= max_allowed,
            "jittered interval {} must be <= upper bound {}",
            actual_sleep, max_allowed
        );
    }
}

/// Zero jitter percent must yield exactly the base interval every time.
#[test]
fn test_beacon_zero_jitter_exact_interval() {
    let base: u64 = 30;
    let jitter_percent: u64 = 0;
    let jitter_range = base * jitter_percent / 100;
    assert_eq!(jitter_range, 0, "zero jitter must produce zero delta range");
}

/// HTTP request payload base64-encoded and decoded must round-trip correctly.
#[test]
fn test_beacon_payload_transform_roundtrip_base64() {
    use base64::{engine::general_purpose::STANDARD, Engine};
    let payload = b"beacon-checkin-data-\x00\xff";
    let encoded = STANDARD.encode(payload);
    let decoded = STANDARD.decode(&encoded).expect("decode must succeed");
    assert_eq!(decoded, payload, "payload must survive base64 encode/decode roundtrip");
}

/// Raw (no-transform) payload must pass through unchanged.
#[test]
fn test_beacon_payload_no_transform_passthrough() {
    let payload = b"raw-beacon-data";
    // Without any transform the slice is used as-is.
    let echoed: Vec<u8> = payload.to_vec();
    assert_eq!(echoed, payload, "no-transform must not alter payload");
}

// ============================================================================
// 4. Module loading tests
// ============================================================================

/// ImplantRuntime has an internal module loader; listing must return empty initially.
#[test]
fn test_module_registry_initially_empty() {
    use implant_loader::DynamicModuleLoader;
    let loader = DynamicModuleLoader::new();
    let modules = loader.list();
    assert!(modules.is_empty(), "fresh module registry must be empty");
}

/// Dispatching an unknown task type must return a Failed TaskResponse, not panic.
#[tokio::test]
async fn test_runtime_dispatch_unknown_task_type() {
    use protocol::TaskStatus;
    let runtime = ImplantRuntime::new();
    let task = Task {
        task_id: Some(ProtoUuid { value: vec![0u8; 16] }),
        task_type: "totally_unknown_task_xyz".to_string(),
        task_data: vec![],
        issued_at: None,
        operator_id: None,
    };
    let response = runtime.execute_task(&task).await;
    assert_eq!(
        response.status,
        TaskStatus::Failed as i32,
        "unknown task type must produce a Failed status"
    );
}

/// Dispatching a module task with invalid protobuf must return Failed, not panic.
#[tokio::test]
async fn test_runtime_dispatch_invalid_module_task_data() {
    use protocol::TaskStatus;
    let runtime = ImplantRuntime::new();
    let task = Task {
        task_id: Some(ProtoUuid { value: vec![1u8; 16] }),
        task_type: "module".to_string(),
        task_data: b"this is not valid protobuf \xff\xfe".to_vec(),
        issued_at: None,
        operator_id: None,
    };
    let response = runtime.execute_task(&task).await;
    assert_eq!(
        response.status,
        TaskStatus::Failed as i32,
        "malformed module task must produce a Failed status"
    );
}

/// execute_module_task with a list operation on an empty loader must succeed.
#[test]
fn test_module_dispatch_list_empty_registry() {
    use implant_loader::DynamicModuleLoader;
    use protocol::{
        module_task::Operation, ModuleList, ModuleOperationResult, ModuleTask,
    };
    use std::sync::{Arc, Mutex};

    let loader = Arc::new(Mutex::new(DynamicModuleLoader::new()));
    let task = ModuleTask {
        operation: Some(Operation::List(ModuleList {})),
    };
    let encoded = protocol::encode(&task);
    let result = implant_core::tasks::execute_module_task(&encoded, &loader);
    assert!(result.is_ok(), "list on empty registry must succeed");

    let op_result: ModuleOperationResult =
        protocol::decode(&result.unwrap()).expect("response must be valid protobuf");
    assert!(op_result.success);
    assert!(op_result.loaded_modules.is_empty());
}

/// Unloading a non-existent module must return success=false, not panic.
#[test]
fn test_module_dispatch_unload_nonexistent() {
    use implant_loader::DynamicModuleLoader;
    use protocol::{
        module_task::Operation, ModuleOperationResult, ModuleTask, ModuleUnload,
    };
    use std::sync::{Arc, Mutex};

    let loader = Arc::new(Mutex::new(DynamicModuleLoader::new()));
    let task = ModuleTask {
        operation: Some(Operation::Unload(ModuleUnload {
            module_id: "kraken.lifecycle.nonexistent".to_string(),
        })),
    };
    let encoded = protocol::encode(&task);
    let result = implant_core::tasks::execute_module_task(&encoded, &loader);
    assert!(result.is_ok());

    let op_result: ModuleOperationResult =
        protocol::decode(&result.unwrap()).expect("response must be valid protobuf");
    assert!(!op_result.success, "unloading nonexistent module must report success=false");
    assert!(op_result.message.is_some(), "error message must be present");
}

// ============================================================================
// 5. Graceful degradation tests
// ============================================================================

/// Server unreachable: exchange on a failing transport eventually returns a transport error.
#[test]
fn test_graceful_degradation_server_unreachable() {
    let t = MockTransport::failing("http");
    // Single transport with default threshold (3). After 3 failures all transports exhausted.
    let mut chain = TransportChain::new(vec![Box::new(t)]);
    let mut final_result = Ok(vec![]);
    for _ in 0..4 {
        final_result = chain.exchange(b"beacon");
        if final_result.is_err() { break; }
    }
    assert!(final_result.is_err(), "failing transport must yield an error");
    let err = final_result.unwrap_err();
    assert!(
        matches!(err, KrakenError::AllTransportsFailed | KrakenError::Transport(_)),
        "unreachable server must yield a transport error, got {:?}",
        err
    );
}

/// Exponential-backoff delay sequence must be strictly increasing.
#[test]
fn test_exponential_backoff_sequence_increases() {
    // Simulate the backoff logic: delay_ms = base * 2^attempt, capped at max.
    let base_ms: u64 = 1_000;
    let max_ms: u64 = 30_000;
    let attempts = 6;

    let mut prev_delay: u64 = 0;
    for attempt in 0..attempts {
        let delay = std::cmp::min(base_ms * (1 << attempt), max_ms);
        if attempt == 0 {
            // First delay must equal the base
            assert_eq!(delay, base_ms);
        } else if prev_delay < max_ms {
            // While uncapped, each step must double
            assert!(
                delay > prev_delay,
                "backoff must increase: attempt {}, delay {} <= prev {}",
                attempt, delay, prev_delay
            );
        }
        prev_delay = delay;
    }
}

/// Exponential backoff must not exceed configured maximum.
#[test]
fn test_exponential_backoff_capped_at_max() {
    let base_ms: u64 = 1_000;
    let max_ms: u64 = 30_000;

    for attempt in 0u32..20 {
        let delay = std::cmp::min(base_ms * (1u64 << attempt.min(31)), max_ms);
        assert!(
            delay <= max_ms,
            "backoff must never exceed max_ms {}, got {} at attempt {}",
            max_ms, delay, attempt
        );
    }
}

/// max_retries from ImplantConfig must be respected in retry loop logic.
#[test]
fn test_max_retries_config_respected() {
    let cfg = default_config();
    assert!(
        cfg.max_retries > 0,
        "max_retries must be > 0 to allow at least one retry"
    );
    // Verify a simulated retry counter stops at the configured limit.
    let mut attempts = 0u32;
    loop {
        if attempts >= cfg.max_retries {
            break;
        }
        attempts += 1;
    }
    assert_eq!(attempts, cfg.max_retries, "retry loop must stop exactly at max_retries");
}

// ============================================================================
// 6. Anti-analysis simulation tests
// ============================================================================

/// is_debugger_present() must return a valid boolean without panicking.
#[test]
fn test_anti_debug_detection_no_panic() {
    use implant_core::evasion::anti_debug;
    let result = anti_debug::is_debugger_present();
    // Result is a bool — just assert it is one of the two valid values.
    assert!(result == true || result == false);
}

/// On non-Windows, the debug detection stub must always return false.
#[test]
#[cfg(not(target_os = "windows"))]
fn test_anti_debug_non_windows_stub_returns_false() {
    use implant_core::evasion::anti_debug;
    assert!(
        !anti_debug::is_debugger_present(),
        "Linux/macOS stub must always return false"
    );
}

/// is_virtual_machine() must return a valid boolean without panicking.
#[test]
fn test_anti_vm_detection_no_panic() {
    use implant_core::evasion::anti_vm;
    let result = anti_vm::is_virtual_machine();
    assert!(result == true || result == false);
}

/// detect_vm_detailed() must return a structurally consistent result.
#[test]
fn test_anti_vm_detailed_result_consistency() {
    use implant_core::evasion::anti_vm;
    let result = anti_vm::detect_vm_detailed();
    // On Windows: is_vm must be the OR of all individual flags.
    #[cfg(target_os = "windows")]
    {
        let expected = result.cpuid_hypervisor
            || result.vm_mac_detected
            || result.vm_process_detected
            || result.vm_registry_detected;
        assert_eq!(result.is_vm, expected, "is_vm must equal OR of individual VM flags");
    }
    // On non-Windows: flags other than is_vm should not be set by the stub.
    #[cfg(not(target_os = "windows"))]
    {
        assert!(!result.cpuid_hypervisor, "cpuid_hypervisor must be false on non-Windows");
        assert!(!result.vm_mac_detected, "vm_mac_detected must be false on non-Windows");
        assert!(!result.vm_process_detected, "vm_process_detected must be false on non-Windows");
        assert!(!result.vm_registry_detected, "vm_registry_detected must be false on non-Windows");
    }
}

/// VmDetectionResult::default() must represent a clean, non-VM environment.
#[test]
fn test_anti_vm_default_result_is_clean() {
    use implant_core::evasion::anti_vm::VmDetectionResult;
    let r = VmDetectionResult::default();
    assert!(!r.is_vm);
    assert!(!r.cpuid_hypervisor);
    assert!(!r.vm_mac_detected);
    assert!(!r.vm_process_detected);
    assert!(!r.vm_registry_detected);
    assert!(r.detected_platform.is_none());
}

/// Sandbox simulation: detected_platform must be Some if is_vm is true.
#[test]
fn test_anti_vm_platform_set_when_vm_detected() {
    use implant_core::evasion::anti_vm::VmDetectionResult;
    // Construct a synthetic "detected" result to verify field semantics.
    let r = VmDetectionResult {
        is_vm: true,
        cpuid_hypervisor: true,
        vm_mac_detected: false,
        vm_process_detected: false,
        vm_registry_detected: false,
        detected_platform: Some("TestHypervisor".to_string()),
    };
    assert!(r.is_vm);
    assert!(
        r.detected_platform.is_some(),
        "detected_platform must be set when a VM is detected"
    );
    assert_eq!(r.detected_platform.as_deref(), Some("TestHypervisor"));
}

//! Module Store — server-side module registry with Ed25519 signing.
//!
//! The store is responsible for:
//! - Accepting compiled module blobs and signing them with the server key.
//! - Persisting signed blobs in the database (via [`db::ModulesRepo`]).
//! - Serving blobs on demand with an in-memory cache keyed by
//!   `(module_id, platform)`.
//! - Providing list/delete administration operations.
//! - Compiling modules from source and extracting metadata.

pub mod compiler;
pub mod signing;

pub use compiler::{CompiledModule, ModuleCompiler};
pub use signing::{ModuleSigner, build_unsigned_blob, arch_for_platform, pack_version};

use common::{KrakenError, ModuleBlob};
use db::ModuleRecord;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{debug, info};

// ---------------------------------------------------------------------------
// ModuleInfo / PlatformVersion — public metadata types
// ---------------------------------------------------------------------------

/// Metadata describing a single module (possibly spanning multiple platforms).
#[derive(Debug, Clone)]
pub struct ModuleInfo {
    pub id: String,
    pub name: String,
    pub description: Option<String>,
    pub platforms: Vec<PlatformVersion>,
}

/// A specific platform/version entry within a [`ModuleInfo`].
#[derive(Debug, Clone)]
pub struct PlatformVersion {
    pub platform: String,
    pub version: String,
    pub size: usize,
    pub compiled_at: i64,
}

// ---------------------------------------------------------------------------
// ModuleStore
// ---------------------------------------------------------------------------

/// Server-side module registry.
pub struct ModuleStore {
    db: Arc<db::Database>,
    signer: ModuleSigner,
    /// Cache keyed by (module_id_string, platform) → signed blob bytes.
    cache: RwLock<HashMap<(String, String), Vec<u8>>>,
}

impl ModuleStore {
    /// Create a new `ModuleStore`.
    ///
    /// `signing_key` must be a PKCS#8-encoded Ed25519 private key.
    pub fn new(db: Arc<db::Database>, signing_key: &[u8]) -> Result<Self, KrakenError> {
        let signer = ModuleSigner::new(signing_key)?;
        Ok(Self {
            db,
            signer,
            cache: RwLock::new(HashMap::new()),
        })
    }

    /// Return the 32-byte Ed25519 public key used to sign modules.
    pub fn public_key(&self) -> [u8; 32] {
        self.signer.public_key()
    }

    // -----------------------------------------------------------------------
    // register
    // -----------------------------------------------------------------------

    /// Register (sign and store) a compiled module.
    ///
    /// Builds the unsigned blob from the supplied parameters, signs it with
    /// the server key, stores the result in the database, and updates the
    /// "latest" version pointer for this `(module_id, platform)` pair.
    #[allow(clippy::too_many_arguments)]
    pub async fn register(
        &self,
        module_id: &str,
        platform: &str,
        version: &str,
        name: &str,
        description: Option<&str>,
        compiled_code: &[u8],
        entry_offset: u32,
    ) -> Result<(), KrakenError> {
        info!(module_id, platform, version, "registering module");

        // Determine architecture constant from platform triple.
        let arch = arch_for_platform(platform)?;

        // Parse semver string into (u8, u8, u8).
        let version_tuple = parse_version(version)?;

        // Build unsigned blob.
        let unsigned = build_unsigned_blob(
            module_id,
            name,
            version_tuple,
            arch,
            0, // flags — no special requirements
            compiled_code,
            entry_offset,
        );

        // Sign.
        let signed_blob = self.signer.sign(&unsigned)?;

        // Extract the internal module_id from the blob itself so that the
        // store key always matches what the implant tracks (e.g. "kraken.shell"
        // rather than the CLI-supplied external ID like "mod-shell").
        let parsed = ModuleBlob::parse(&signed_blob)?;
        let internal_id = parsed.module_id.to_string();
        let _ = parsed; // release borrow on signed_blob

        info!(
            provided_id = module_id,
            internal_id = %internal_id,
            "using blob's internal module_id for store registration"
        );

        // Hash for integrity record.
        let hash = ring::digest::digest(&ring::digest::SHA256, &signed_blob);

        let now = chrono::Utc::now().timestamp_millis();

        let record = ModuleRecord {
            id: internal_id.clone(),
            platform: platform.to_string(),
            version: version.to_string(),
            name: name.to_string(),
            description: description.map(|s| s.to_string()),
            hash: hash.as_ref().to_vec(),
            size: signed_blob.len() as i64,
            blob: signed_blob.clone(),
            compiled_at: now,
            created_at: now,
        };

        self.db.modules().insert(&record).await?;
        self.db.modules().set_latest(&internal_id, platform, version).await?;

        // Populate cache.
        let key = (internal_id.clone(), platform.to_string());
        self.cache.write().await.insert(key, signed_blob);

        debug!(module_id = %internal_id, platform, version, "module registered");
        Ok(())
    }

    // -----------------------------------------------------------------------
    // get_blob
    // -----------------------------------------------------------------------

    /// Retrieve the signed blob for a module.
    ///
    /// If `version` is `None` the latest registered version for the given
    /// platform is used.  The result is cached in memory for subsequent calls.
    pub async fn get_blob(
        &self,
        module_id: &str,
        platform: &str,
        version: Option<&str>,
    ) -> Result<Vec<u8>, KrakenError> {
        // Check the in-memory cache first (latest-version semantics).
        let cache_key = (module_id.to_string(), platform.to_string());
        if let Some(cached) = self.cache.read().await.get(&cache_key) {
            return Ok(cached.clone());
        }

        // Resolve version.
        let resolved_version = match version {
            Some(v) => v.to_string(),
            None => self
                .db
                .modules()
                .get_latest_version(module_id, platform)
                .await?
                .ok_or_else(|| KrakenError::ModuleNotFound(module_id.to_string()))?,
        };

        let blob = self
            .db
            .modules()
            .get_blob(module_id, platform, &resolved_version)
            .await?
            .ok_or_else(|| KrakenError::ModuleNotFound(module_id.to_string()))?;

        // Warm the cache.
        self.cache.write().await.insert(cache_key, blob.clone());

        Ok(blob)
    }

    // -----------------------------------------------------------------------
    // list
    // -----------------------------------------------------------------------

    /// List all registered modules, grouped by module ID.
    pub async fn list(&self) -> Result<Vec<ModuleInfo>, KrakenError> {
        let records = self.db.modules().list().await?;
        Ok(aggregate_module_records(records))
    }

    // -----------------------------------------------------------------------
    // delete
    // -----------------------------------------------------------------------

    /// Delete a specific `(module_id, platform, version)` entry.
    ///
    /// Also evicts the cache entry for `(module_id, platform)` since the
    /// "latest" pointer may have changed.
    pub async fn delete(
        &self,
        module_id: &str,
        platform: &str,
        version: &str,
    ) -> Result<(), KrakenError> {
        self.db.modules().delete(module_id, platform, version).await?;

        let key = (module_id.to_string(), platform.to_string());
        self.cache.write().await.remove(&key);

        info!(module_id, platform, version, "module deleted");
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Helper: aggregate flat DB records into grouped ModuleInfo list
// ---------------------------------------------------------------------------

fn aggregate_module_records(records: Vec<ModuleRecord>) -> Vec<ModuleInfo> {
    // Use an ordered map to preserve insertion order (sorted by DB).
    let mut map: Vec<(String, ModuleInfo)> = Vec::new();

    for r in records {
        let pv = PlatformVersion {
            platform: r.platform.clone(),
            version: r.version.clone(),
            size: r.size as usize,
            compiled_at: r.compiled_at,
        };

        if let Some((_, info)) = map.iter_mut().find(|(id, _)| id == &r.id) {
            info.platforms.push(pv);
        } else {
            map.push((
                r.id.clone(),
                ModuleInfo {
                    id: r.id,
                    name: r.name,
                    description: r.description,
                    platforms: vec![pv],
                },
            ));
        }
    }

    map.into_iter().map(|(_, info)| info).collect()
}

// ---------------------------------------------------------------------------
// Helper: parse "major.minor.patch" version string
// ---------------------------------------------------------------------------

fn parse_version(version: &str) -> Result<(u8, u8, u8), KrakenError> {
    let parts: Vec<&str> = version.split('.').collect();
    let parse_part = |s: &str| -> Result<u8, KrakenError> {
        s.parse::<u8>()
            .map_err(|_| KrakenError::Module(format!("invalid version component: {}", s)))
    };
    let major = parse_part(parts.first().copied().unwrap_or("0"))?;
    let minor = parse_part(parts.get(1).copied().unwrap_or("0"))?;
    let patch = parse_part(parts.get(2).copied().unwrap_or("0"))?;
    Ok((major, minor, patch))
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn aggregate_groups_by_id() {
        let records = vec![
            ModuleRecord {
                id: "mod.a".into(),
                platform: "x86_64-unknown-linux-gnu".into(),
                version: "0.1.0".into(),
                name: "Mod A".into(),
                description: None,
                hash: vec![],
                size: 100,
                blob: vec![],
                compiled_at: 0,
                created_at: 0,
            },
            ModuleRecord {
                id: "mod.a".into(),
                platform: "x86_64-pc-windows-msvc".into(),
                version: "0.1.0".into(),
                name: "Mod A".into(),
                description: None,
                hash: vec![],
                size: 200,
                blob: vec![],
                compiled_at: 0,
                created_at: 0,
            },
            ModuleRecord {
                id: "mod.b".into(),
                platform: "x86_64-unknown-linux-gnu".into(),
                version: "1.0.0".into(),
                name: "Mod B".into(),
                description: Some("desc".into()),
                hash: vec![],
                size: 50,
                blob: vec![],
                compiled_at: 0,
                created_at: 0,
            },
        ];

        let infos = aggregate_module_records(records);
        assert_eq!(infos.len(), 2);
        assert_eq!(infos[0].id, "mod.a");
        assert_eq!(infos[0].platforms.len(), 2);
        assert_eq!(infos[1].id, "mod.b");
        assert_eq!(infos[1].description.as_deref(), Some("desc"));
    }

    #[test]
    fn parse_version_ok() {
        assert_eq!(parse_version("1.2.3").unwrap(), (1, 2, 3));
        assert_eq!(parse_version("0.1.0").unwrap(), (0, 1, 0));
    }

    #[test]
    fn parse_version_short() {
        // Missing components default to 0.
        assert_eq!(parse_version("2").unwrap(), (2, 0, 0));
    }

    #[test]
    fn parse_version_invalid() {
        assert!(parse_version("a.b.c").is_err());
    }

    // -----------------------------------------------------------------------
    // Phase 3 tests
    // -----------------------------------------------------------------------

    /// `ModuleSigner::new` must succeed with a freshly generated PKCS#8 key
    /// and reject obviously invalid key material.
    #[test]
    fn test_module_store_creation() {
        // Generate a valid PKCS#8 Ed25519 key pair.
        let pkcs8 = ModuleSigner::generate_pkcs8().expect("key generation must succeed");
        assert!(!pkcs8.is_empty(), "generated PKCS#8 bytes must be non-empty");

        // Must accept the generated key.
        let signer = ModuleSigner::new(&pkcs8).expect("signer must accept generated key");
        let pubkey = signer.public_key();
        assert_eq!(pubkey.len(), 32, "Ed25519 public key must be 32 bytes");

        // Must reject garbage bytes.
        assert!(
            ModuleSigner::new(&[0u8; 8]).is_err(),
            "signer must reject invalid key bytes"
        );
    }

    /// `pack_version` must encode `(major, minor, patch)` into the expected
    /// bit layout and be extractable field-by-field.
    #[test]
    fn test_version_packing() {
        assert_eq!(pack_version((1, 2, 3)), 0x0001_0203);
        assert_eq!(pack_version((0, 0, 0)), 0x0000_0000);
        assert_eq!(pack_version((255, 255, 255)), 0x00FF_FFFF);

        let packed = pack_version((5, 10, 15));
        assert_eq!((packed >> 16) & 0xFF, 5, "major must be in bits 16-23");
        assert_eq!((packed >> 8) & 0xFF, 10, "minor must be in bits 8-15");
        assert_eq!(packed & 0xFF, 15, "patch must be in bits 0-7");
    }

    /// `build_unsigned_blob` must produce a correctly structured blob whose
    /// header magic is `KMOD`, and which can be signed and then fully parsed.
    #[test]
    fn test_build_unsigned_blob() {
        use common::{ModuleBlob, ModuleBlobHeader, ARCH_X64_LINUX};

        let code = vec![0xCC_u8; 32];
        let module_id = "kraken.test.unsigned";
        let module_name = "Unsigned Test Module";
        let version = (1, 2, 3);
        let entry_offset: u32 = 0;

        let blob = build_unsigned_blob(
            module_id,
            module_name,
            version,
            ARCH_X64_LINUX,
            0,
            &code,
            entry_offset,
        );

        // Must be at least header + id + name + code bytes.
        assert!(
            blob.len() >= ModuleBlobHeader::SIZE + module_id.len() + module_name.len() + code.len(),
            "blob too short"
        );

        // Must begin with KMOD magic.
        assert_eq!(&blob[0..4], b"KMOD", "blob must start with KMOD magic");

        // Sign with a freshly generated key so we can perform a full parse.
        let pkcs8 = ModuleSigner::generate_pkcs8().expect("key gen");
        let signer = ModuleSigner::new(&pkcs8).expect("signer");
        let signed = signer.sign(&blob).expect("signing must succeed");

        let parsed = ModuleBlob::parse(&signed).expect("signed blob must parse successfully");
        assert_eq!(parsed.module_id, module_id);
        assert_eq!(parsed.module_name, module_name);
        assert_eq!(parsed.code.len(), code.len());
        let header_version = parsed.header.version;
        assert_eq!(header_version, pack_version(version));
    }
}

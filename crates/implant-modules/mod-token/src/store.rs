//! In-memory token store
//!
//! Holds duplicated / synthesised tokens keyed by a monotonically increasing
//! u32 ID.  The store is process-wide and protected by a Mutex so it can be
//! safely accessed from async contexts via `spawn_blocking`.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Mutex;

use common::KrakenError;

/// Information recorded alongside each stored token.
#[derive(Debug, Clone)]
pub struct StoredToken {
    /// Unique ID assigned by the store.
    pub id: u32,
    /// Human-readable source description ("steal:<pid>" or "make:<domain>\\<user>").
    pub source: String,
    /// Raw handle value (isize so the struct is Send/Sync on all platforms).
    /// On Windows this is a duplicated HANDLE; the store owns it.
    pub raw_handle: isize,
}

static NEXT_ID: AtomicU32 = AtomicU32::new(1);

/// Global token store.
static STORE: Mutex<Option<HashMap<u32, StoredToken>>> = Mutex::new(None);

fn with_store<F, R>(f: F) -> Result<R, KrakenError>
where
    F: FnOnce(&mut HashMap<u32, StoredToken>) -> Result<R, KrakenError>,
{
    let mut guard = STORE
        .lock()
        .map_err(|_| KrakenError::Internal("token store lock poisoned".into()))?;
    let map = guard.get_or_insert_with(HashMap::new);
    f(map)
}

/// Insert a token into the store and return its assigned ID.
///
/// # Arguments
/// * `raw_handle` - Raw HANDLE value (cast to isize).  The store takes
///   ownership; the caller must NOT close this handle independently.
/// * `source`     - Free-form description used by `list_tokens`.
pub fn insert(raw_handle: isize, source: impl Into<String>) -> Result<u32, KrakenError> {
    let id = NEXT_ID.fetch_add(1, Ordering::Relaxed);
    with_store(|map| {
        map.insert(
            id,
            StoredToken {
                id,
                source: source.into(),
                raw_handle,
            },
        );
        Ok(id)
    })
}

/// Look up a token by ID without removing it.
pub fn get(id: u32) -> Result<StoredToken, KrakenError> {
    with_store(|map| {
        map.get(&id)
            .cloned()
            .ok_or_else(|| KrakenError::NotFound(format!("token id {id}")))
    })
}

/// Remove and return a token by ID.
pub fn remove(id: u32) -> Result<StoredToken, KrakenError> {
    with_store(|map| {
        map.remove(&id)
            .ok_or_else(|| KrakenError::NotFound(format!("token id {id}")))
    })
}

/// Return a snapshot of all stored tokens (cloned metadata, no handles).
pub fn list() -> Result<Vec<StoredToken>, KrakenError> {
    with_store(|map| {
        let mut tokens: Vec<StoredToken> = map.values().cloned().collect();
        tokens.sort_by_key(|t| t.id);
        Ok(tokens)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn insert_and_list() {
        // IDs are globally monotonic; just check the round-trip.
        let id = insert(0xdead_beef, "test:1234").unwrap();
        let tokens = list().unwrap();
        assert!(tokens.iter().any(|t| t.id == id && t.source == "test:1234"));
        remove(id).unwrap();
    }

    #[test]
    fn get_missing_returns_not_found() {
        let err = get(0xffff_ffff).unwrap_err();
        assert!(matches!(err, KrakenError::NotFound(_)));
    }

    // ------------------------------------------------------------------
    // Token store operations — cross-platform
    // ------------------------------------------------------------------

    #[test]
    fn store_token_with_metadata() {
        let id = insert(0x1111, "steal:9999").unwrap();
        let tok = get(id).unwrap();
        assert_eq!(tok.id, id);
        assert_eq!(tok.source, "steal:9999");
        assert_eq!(tok.raw_handle, 0x1111);
        remove(id).unwrap();
    }

    #[test]
    fn retrieve_stored_token_by_id() {
        let id = insert(0xABCD, "make:DOMAIN\\user").unwrap();
        let tok = get(id).unwrap();
        assert_eq!(tok.id, id);
        assert_eq!(tok.raw_handle, 0xABCD);
        remove(id).unwrap();
    }

    #[test]
    fn list_returns_all_inserted_tokens() {
        let id_a = insert(0x0001, "list-test:a").unwrap();
        let id_b = insert(0x0002, "list-test:b").unwrap();
        let tokens = list().unwrap();
        let sources: Vec<&str> = tokens.iter().map(|t| t.source.as_str()).collect();
        assert!(sources.contains(&"list-test:a"));
        assert!(sources.contains(&"list-test:b"));
        remove(id_a).unwrap();
        remove(id_b).unwrap();
    }

    #[test]
    fn list_returns_tokens_sorted_by_id() {
        let id_a = insert(0x0010, "sort-test:a").unwrap();
        let id_b = insert(0x0020, "sort-test:b").unwrap();
        let id_c = insert(0x0030, "sort-test:c").unwrap();
        let tokens = list().unwrap();
        // Extract only the IDs we just inserted (filter to avoid interference
        // from parallel tests touching the global store).
        let our_ids: Vec<u32> = tokens
            .iter()
            .filter(|t| t.source.starts_with("sort-test:"))
            .map(|t| t.id)
            .collect();
        assert_eq!(our_ids, vec![id_a, id_b, id_c]);
        remove(id_a).unwrap();
        remove(id_b).unwrap();
        remove(id_c).unwrap();
    }

    #[test]
    fn delete_token_removes_it_from_store() {
        let id = insert(0x5555, "delete-test:x").unwrap();
        // Confirm it exists first.
        get(id).unwrap();
        // Remove it.
        let removed = remove(id).unwrap();
        assert_eq!(removed.id, id);
        // Should be gone now.
        let err = get(id).unwrap_err();
        assert!(matches!(err, KrakenError::NotFound(_)));
    }

    #[test]
    fn remove_returns_token_data() {
        let id = insert(0xBEEF, "remove-data-test").unwrap();
        let tok = remove(id).unwrap();
        assert_eq!(tok.id, id);
        assert_eq!(tok.source, "remove-data-test");
        assert_eq!(tok.raw_handle, 0xBEEF);
    }

    #[test]
    fn remove_missing_returns_not_found() {
        // Use an absurdly high ID that should never be assigned.
        let err = remove(0xFFFE_FFFF).unwrap_err();
        assert!(matches!(err, KrakenError::NotFound(_)));
    }

    #[test]
    fn get_after_remove_returns_not_found() {
        let id = insert(0x1234, "ephemeral").unwrap();
        remove(id).unwrap();
        let err = get(id).unwrap_err();
        assert!(matches!(err, KrakenError::NotFound(_)));
    }

    #[test]
    fn multiple_tokens_have_unique_ids() {
        let id_a = insert(0xAAAA, "unique:a").unwrap();
        let id_b = insert(0xBBBB, "unique:b").unwrap();
        assert_ne!(id_a, id_b);
        remove(id_a).unwrap();
        remove(id_b).unwrap();
    }

    #[test]
    fn stored_token_clone_matches_original() {
        let id = insert(0x7777, "clone-test").unwrap();
        let tok = get(id).unwrap();
        let cloned = tok.clone();
        assert_eq!(cloned.id, tok.id);
        assert_eq!(cloned.source, tok.source);
        assert_eq!(cloned.raw_handle, tok.raw_handle);
        remove(id).unwrap();
    }

    #[test]
    fn source_format_steal_prefix() {
        let id = insert(0x1, "steal:4321").unwrap();
        let tok = get(id).unwrap();
        assert!(tok.source.starts_with("steal:"));
        remove(id).unwrap();
    }

    #[test]
    fn source_format_make_prefix() {
        let id = insert(0x2, "make:CORP\\svc_account").unwrap();
        let tok = get(id).unwrap();
        assert!(tok.source.starts_with("make:"));
        assert!(tok.source.contains('\\'));
        remove(id).unwrap();
    }

    #[test]
    fn ids_are_monotonically_increasing() {
        let id_a = insert(0xA, "mono:a").unwrap();
        let id_b = insert(0xB, "mono:b").unwrap();
        assert!(id_b > id_a);
        remove(id_a).unwrap();
        remove(id_b).unwrap();
    }
}

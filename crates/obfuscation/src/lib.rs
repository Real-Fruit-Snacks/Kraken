//! Kraken obfuscation utilities — Phase 4
//!
//! Provides compile-time string encryption, API name hashing, and control flow obfuscation.
//!
//! Macros:
//! - `encrypted_string!("str")` - Compile-time string encryption
//! - `djb2_hash!("str")` - Compile-time DJB2 hash
//! - `obf_if!(cond, then_block, else_block)` - Obfuscated conditional
//! - `junk_code!()` - Insert junk computation

use proc_macro::TokenStream;
use quote::quote;
use syn::{parse_macro_input, Expr, LitStr, Token};
use syn::parse::{Parse, ParseStream};

/// Compile-time string encryption macro
///
/// Usage: `let s = encrypted_string!("sensitive string");`
///
/// The string is XOR-encrypted at compile time with a random key
/// and decrypted at runtime.
#[proc_macro]
pub fn encrypted_string(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as LitStr);
    let string = input.value();
    let bytes = string.as_bytes();

    // Generate random 16-byte key at compile time
    let key: [u8; 16] = rand::random();

    // Encrypt string bytes
    let encrypted: Vec<u8> = bytes
        .iter()
        .enumerate()
        .map(|(i, &b)| b ^ key[i % 16])
        .collect();

    let key_tokens: Vec<_> = key.iter().map(|&b| quote! { #b }).collect();
    let encrypted_tokens: Vec<_> = encrypted.iter().map(|&b| quote! { #b }).collect();
    let len = bytes.len();

    let expanded = quote! {
        {
            const ENCRYPTED: [u8; #len] = [#(#encrypted_tokens),*];
            const KEY: [u8; 16] = [#(#key_tokens),*];

            let mut decrypted = [0u8; #len];
            let mut i = 0;
            while i < #len {
                decrypted[i] = ENCRYPTED[i] ^ KEY[i % 16];
                i += 1;
            }

            // SAFETY: We encrypted valid UTF-8, XOR preserves validity
            unsafe { core::str::from_utf8_unchecked(&decrypted) }.to_string()
        }
    };

    expanded.into()
}

/// DJB2 hash function for API name hashing
#[proc_macro]
pub fn djb2_hash(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as LitStr);
    let string = input.value();

    let mut hash: u32 = 5381;
    for byte in string.bytes() {
        hash = hash.wrapping_mul(33).wrapping_add(byte as u32);
    }

    let expanded = quote! { #hash };
    expanded.into()
}

// =============================================================================
// Control Flow Obfuscation
// =============================================================================

/// Input for obf_if! macro: condition, then block, else block
struct ObfIfInput {
    condition: Expr,
    then_block: Expr,
    else_block: Expr,
}

impl Parse for ObfIfInput {
    fn parse(input: ParseStream) -> syn::Result<Self> {
        let condition: Expr = input.parse()?;
        input.parse::<Token![,]>()?;
        let then_block: Expr = input.parse()?;
        input.parse::<Token![,]>()?;
        let else_block: Expr = input.parse()?;
        Ok(ObfIfInput {
            condition,
            then_block,
            else_block,
        })
    }
}

/// Obfuscated conditional with opaque predicate
///
/// Usage: `obf_if!(x > 5, { do_something() }, { do_other() })`
///
/// The macro wraps the condition with an opaque predicate that is always true
/// but difficult for static analysis to determine. This makes control flow
/// harder to analyze.
///
/// The opaque predicate uses: (7 * 7) % 4 != 2, which equals 49 % 4 = 1, != 2 = true
#[proc_macro]
pub fn obf_if(input: TokenStream) -> TokenStream {
    let ObfIfInput {
        condition,
        then_block,
        else_block,
    } = parse_macro_input!(input as ObfIfInput);

    let expanded = quote! {
        {
            // Opaque predicate: (7 * 7) % 4 != 2 is always true
            // but requires computation to verify
            let __opaque_x = ::core::hint::black_box(7u32);
            let __opaque_y = ::core::hint::black_box(4u32);
            let __opaque_pred = (__opaque_x.wrapping_mul(__opaque_x)) % __opaque_y != 2;

            // The actual condition, guarded by the opaque predicate
            if (#condition && __opaque_pred) || (!(#condition) && !__opaque_pred) {
                // This branch is taken when condition is true
                // (since opaque_pred is always true)
                if #condition {
                    #then_block
                } else {
                    #else_block
                }
            } else {
                // Dead code path - never taken
                // Include both blocks to confuse static analysis
                if ::core::hint::black_box(false) {
                    #then_block
                } else {
                    #else_block
                }
            }
        }
    };

    expanded.into()
}

/// Insert junk computation that doesn't affect program logic
///
/// Usage: `junk_code!()`
///
/// This inserts meaningless but valid computations that waste analysis time
/// without affecting the program's behavior.
#[proc_macro]
pub fn junk_code(_input: TokenStream) -> TokenStream {
    // Generate random junk operations
    let iterations: u32 = rand::random::<u32>() % 5 + 2;
    let seed: u64 = rand::random();

    let expanded = quote! {
        {
            let mut __junk_v = ::core::hint::black_box(#seed);
            let __junk_iterations = ::core::hint::black_box(#iterations);
            for _ in 0..__junk_iterations {
                __junk_v = __junk_v.wrapping_mul(6364136223846793005u64);
                __junk_v = __junk_v.wrapping_add(1442695040888963407u64);
            }
            ::core::hint::black_box(__junk_v);
        }
    };

    expanded.into()
}

/// Obfuscated loop with junk iterations
///
/// Usage: `obf_loop!(count, |i| { body using i })`
///
/// Adds junk iterations that don't execute the body.
#[proc_macro]
pub fn obf_loop(input: TokenStream) -> TokenStream {
    // Parse: count, closure
    struct LoopInput {
        count: Expr,
        body: Expr,
    }

    impl Parse for LoopInput {
        fn parse(input: ParseStream) -> syn::Result<Self> {
            let count: Expr = input.parse()?;
            input.parse::<Token![,]>()?;
            let body: Expr = input.parse()?;
            Ok(LoopInput { count, body })
        }
    }

    let LoopInput { count, body } = parse_macro_input!(input as LoopInput);

    // Add 2-4 junk iterations
    let junk_start: usize = (rand::random::<u32>() % 3 + 1) as usize;
    let junk_end: usize = (rand::random::<u32>() % 3 + 1) as usize;

    let expanded = quote! {
        {
            let __real_count: usize = #count;
            let __junk_start: usize = ::core::hint::black_box(#junk_start);
            let __junk_end: usize = ::core::hint::black_box(#junk_end);
            let __total: usize = __real_count + __junk_start + __junk_end;

            for __i in 0usize..__total {
                // Only execute body for real iterations
                if __i >= __junk_start && __i < __junk_start + __real_count {
                    let __real_i: usize = __i - __junk_start;
                    (#body)(__real_i);
                } else {
                    // Junk iteration - do meaningless work
                    let _ = ::core::hint::black_box(__i.wrapping_mul(31));
                }
            }
        }
    };

    expanded.into()
}

//! Procedural macros for kata's test suite.
//!
//! Today: `#[kata_timeout(secs = N)]` — arms a REAL-TIME watchdog at the test's entry
//! (`kata_test_utils::timeout_watchdog`) that, if the body is still running after `N`
//! seconds of wall clock, names the test and its budget on stderr and ends the test
//! process (and the process group it leads, as nextest's own kill does).
//!
//! Stack ABOVE `#[tokio::test]` (or `#[test]`):
//!
//! ```ignore
//! #[kata_test_utils::kata_timeout(secs = 30)]
//! #[tokio::test(flavor = "multi_thread")]
//! async fn my_test() { /* ... */ }
//! ```
//!
//! The watchdog is an OS thread on the monotonic clock, so a paused tokio clock spends
//! none of its budget and a body that blocks its runtime thread cannot hold it back.
//!
//! Default if `secs` is omitted: [`DEFAULT_SECS`], below the default nextest profile's
//! 60 s kill (`slow-timeout` period 10 s x terminate-after 6). The budget's whole point is
//! to fire BEFORE the test's nextest kill, so the hang is attributed to a test by name
//! instead of surfacing as an anonymous TIMEOUT: `bin/kata-eval/tests/timeout_budgets.rs`
//! refuses a budget at or above the kill nextest resolves for the test. Pick a tighter
//! budget only if the tight bound is itself the assertion.
//!
//! The expansion names `::kata_test_utils`, so a crate using the attribute depends on
//! `kata-test-utils` (which re-exports it).

use proc_macro::TokenStream;
use quote::quote;
use syn::parse::{Parse, ParseStream};
use syn::{ItemFn, LitInt, Token, parse_macro_input};

/// The budget, in seconds, when `secs` is omitted.
const DEFAULT_SECS: u64 = 50;

/// Parsed form of `#[kata_timeout(secs = N)]` arguments.
struct TimeoutArgs {
    secs: u64,
}

impl Parse for TimeoutArgs {
    fn parse(input: ParseStream) -> syn::Result<Self> {
        if input.is_empty() {
            return Ok(Self { secs: DEFAULT_SECS });
        }
        let key: syn::Ident = input.parse()?;
        if key != "secs" {
            return Err(syn::Error::new(
                key.span(),
                "expected `secs = N` (only key recognized today)",
            ));
        }
        let _eq: Token![=] = input.parse()?;
        let value: LitInt = input.parse()?;
        let secs: u64 = value.base10_parse()?;
        if secs == 0 {
            return Err(syn::Error::new(
                value.span(),
                "`secs` must be > 0 (zero would fire the timeout immediately)",
            ));
        }
        Ok(Self { secs })
    }
}

/// Arm a real-time watchdog over a test body.
///
/// Emits a function with the same signature as the input. The body becomes:
///
/// ```ignore
/// {
///     let _watchdog = ::kata_test_utils::timeout_watchdog::arm(
///         concat!(module_path!(), "::", "<fn_name>"),
///         SECS,
///     );
///     /* original body */
/// }
/// ```
///
/// The guard disarms the watchdog when the body returns or unwinds.
#[proc_macro_attribute]
pub fn kata_timeout(args: TokenStream, item: TokenStream) -> TokenStream {
    let args = parse_macro_input!(args as TimeoutArgs);
    let secs = args.secs;
    let mut input = parse_macro_input!(item as ItemFn);

    let fn_name = input.sig.ident.to_string();
    let original_block = input.block;

    let new_block: syn::Block = syn::parse_quote!({
        let __kata_timeout_watchdog = ::kata_test_utils::timeout_watchdog::arm(
            ::core::concat!(::core::module_path!(), "::", #fn_name),
            #secs,
        );
        #original_block
    });
    input.block = Box::new(new_block);

    quote!(#input).into()
}

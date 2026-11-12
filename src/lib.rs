//! wren-vault: a client for Bitwarden® accounts that a browser starts as a child process.
//!
//! The browser writes requests on the helper's standard input and reads answers on its standard output. The protocol
//! is in README.md. It carries accounts, logins and plain values, never a type of the SDK.
//!
//! Modules:
//! - `frame`: the length-prefixed frames on the pipes.
//! - `protocol`: the requests and the answers, as JSON.
//! - `matching`: which saved URIs match a page.
//! - `state`: the encrypted account state on disk.
//! - `tokens`: the secrets that open the server (refresh token, API key secret), in the system store.
//! - `identity`: the token request of the identity server, as a form and its answer (no SDK type).
//! - `sdk`: every call to the Bitwarden SDK. No other module names an SDK type.
//! - `server`: the loop that reads requests and writes answers, and the idle deadline.
//! - `harden`: process protections (no core dump, no debugger attach).

pub mod frame;
pub mod harden;
pub mod identity;
pub mod matching;
pub mod protocol;
pub mod sdk;
pub mod server;
pub mod state;
pub mod tokens;

/// The version of the pipe protocol. A browser that sends another version gets an error from `hello`.
pub const PROTOCOL_VERSION: u32 = 4;

/// The version of this helper, as `hello` reports it.
pub const HELPER_VERSION: &str = env!("CARGO_PKG_VERSION");

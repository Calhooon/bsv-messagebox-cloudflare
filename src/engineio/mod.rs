//! Engine.IO v4 + Socket.IO v5 transport layer.
//!
//! Phase A: HTTP polling + WS upgrade transport with a CONNECT/ECHO
//! Socket.IO event surface (auth-less).
//! Phase B (current): BRC-103 mutual authentication layered over the
//! `authMessage` Socket.IO event. Non-`authMessage` events sent before
//! the handshake completes are dropped. After the handshake the
//! session has a `verified_identity_key` available, and the server
//! emits an `authenticated` follow-up event back to the client to
//! confirm.
//! Phase C will bridge the post-auth event surface to the existing
//! `MessageHub` (joinRoom / leaveRoom / sendMessage / etc).
//!
//! See `codec.rs` for the wire format, `auth.rs` for the BRC-103
//! driver, and `session.rs` for the per-sid Durable Object.

pub mod auth;
pub mod codec;
pub mod session;

// Re-exports used by `lib.rs` to wire the Worker route. The
// `EngineIoSession` durable object struct is referenced by name
// (not symbol) via `env.durable_object("ENGINEIO_SESSION")`, so
// keeping it on `session::EngineIoSession` is enough for the
// `#[durable_object]` macro to register it.
pub use session::make_session_id;
#[allow(unused_imports)]
pub use session::{open_handshake_packet, public_polling_text_response, EngineIoSession};

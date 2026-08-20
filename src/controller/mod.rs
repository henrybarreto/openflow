//! A working learning-switch controller built on this crate.
//!
//! [`server`] listens for switches and drives each connection; [`switch`]
//! holds the per-connection state (role, bundles, learned MAC table) and
//! the packet-in policy. Useful as a runnable reference for how the
//! protocol types fit together -- see `examples/10_run_controller.rs`.

mod ethernet;
/// Accepts switch connections and drives each one's handshake and
/// message loop.
pub mod server;
pub mod switch;

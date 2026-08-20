//! The `OpenFlow` 1.5.1 wire protocol: every message, action,
//! instruction, match field, and property, typed.
//!
//! Start at [`codec::Encoder`]/[`codec::Decoder`] to turn frames into
//! values and back, or at [`message::Message`] for the union of every
//! message type. The rest of the modules hold the pieces:
//!
//! - [`rule`] flow-mods, [`action`] and [`instruction`] their bodies
//! - [`ofmatch`] and [`oxm`] the match fields, [`oxs`] the flow statistics
//! - [`control`] the large families: multipart, table/port/group/meter
//!   mods, bundles, and the async status messages
//! - [`error_msg`] typed `OFPT_ERROR`, [`constants`] every `OFP*` value
//!
//! Messages this crate does not recognize fail to decode with
//! [`error::OfError`]; values it does not recognize (an unknown property
//! or action type) decode losslessly into an `Unknown`/`Raw` variant so
//! they round-trip.

pub mod action;
pub mod barrier;
mod bytes;
pub mod codec;
pub mod config;
pub mod constants;
pub mod control;
pub mod echo;
pub mod error;
pub mod error_msg;
pub mod features;
pub mod header;
pub mod hello;
pub mod instruction;
pub mod io;
pub mod message;
pub mod nicira;
pub mod ofmatch;
pub mod oxm;
pub mod oxs;
pub mod packet_in;
pub mod packet_out;
pub mod proto_error;
pub mod rule;
#[cfg(all(test, not(clippy)))]
mod tests;
#[cfg(all(test, not(clippy)))]
mod tests_coverage;

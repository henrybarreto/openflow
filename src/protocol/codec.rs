//! [`Encoder`] and [`Decoder`]: the single entry point for turning
//! `OpenFlow` messages into frames and back.
//!
//! Every message family also has its own encoder in its own module
//! ([`crate::protocol::barrier::encode_barrier_request`], and so on);
//! these two facades just gather them in one place, and are what you
//! should reach for unless you already hold the typed struct.

use crate::protocol::action::{parse_actions, Action};
use crate::protocol::barrier::Barrier;
use crate::protocol::config::Config;
use crate::protocol::control::{self, RoleRequest};
use crate::protocol::echo::Echo;
use crate::protocol::error::Result;
use crate::protocol::error_msg::ErrorMessage;
use crate::protocol::features::{self, Request};
use crate::protocol::hello::Hello;
use crate::protocol::instruction::{parse_instructions, Instruction};
use crate::protocol::message::{self, Message};
use crate::protocol::packet_in::PacketIn;
use crate::protocol::packet_out::PacketOut;
use crate::protocol::rule::{Entry, Rule};

/// Encodes any `OpenFlow` 1.5.1 message into a wire frame.
///
/// Every method is associated (no instance needed) and returns the complete
/// frame, header included. Variable-length encoders return a `Result` and
/// reject data that cannot fit in the protocol's length fields.
///
/// ```
/// use openflow::protocol::codec::Encoder;
///
/// let frame = Encoder::barrier_request(42);
/// assert_eq!(frame.len(), 8); // header only
/// assert_eq!(frame[1], openflow::protocol::constants::OFPT_BARRIER_REQUEST);
/// ```
pub struct Encoder;

impl Encoder {
    /// Encode an `OFPT_HELLO` advertising `OpenFlow` 1.5.
    ///
    /// # Errors
    ///
    /// Returns an error if the encoded frame exceeds the wire length limit.
    pub fn hello(xid: u32) -> Result<Vec<u8>> {
        Hello::new(xid).encode()
    }

    /// Encode an `OFPT_FEATURES_REQUEST`.
    pub fn features_request(xid: u32) -> Vec<u8> {
        Request::new(xid).encode()
    }

    /// Encode an `OFPT_ECHO_REQUEST` carrying `payload`.
    ///
    /// # Errors
    ///
    /// Returns an error if the encoded frame exceeds the wire length limit.
    pub fn echo_request(xid: u32, payload: &[u8]) -> Result<Vec<u8>> {
        Echo::new(xid, payload.to_vec()).encode_request()
    }

    /// Encode an `OFPT_ECHO_REPLY`; `payload` must be the request's, unchanged.
    ///
    /// # Errors
    ///
    /// Returns an error if the encoded frame exceeds the wire length limit.
    pub fn echo_reply(xid: u32, payload: &[u8]) -> Result<Vec<u8>> {
        Echo::new(xid, payload.to_vec()).encode_reply()
    }

    /// Encode an `OFPT_ERROR` from a raw type/code pair.
    ///
    /// # Errors
    ///
    /// Returns an error if the encoded frame exceeds the wire length limit.
    pub fn error(xid: u32, error_type: u16, code: u16, data: &[u8]) -> Result<Vec<u8>> {
        ErrorMessage::new(xid, error_type, code, data.to_vec()).encode()
    }

    /// Encode an `OFPT_GET_CONFIG_REQUEST`.
    pub fn get_config_request(xid: u32) -> Vec<u8> {
        Config::get_request(xid)
    }

    /// Encode an `OFPT_GET_CONFIG_REPLY` (switch side).
    pub fn get_config_reply(xid: u32, flags: u16, miss_send_len: u16) -> Vec<u8> {
        Config::new(xid, flags, miss_send_len).encode_reply()
    }

    /// Encode an `OFPT_SET_CONFIG` carrying `OFPC_*` flags and `miss_send_len`.
    pub fn set_config(xid: u32, flags: u16, miss_send_len: u16) -> Vec<u8> {
        Config::new(xid, flags, miss_send_len).encode_set()
    }

    /// Encode an `OFPT_PACKET_OUT` injecting `data` into the pipeline.
    ///
    /// # Errors
    ///
    /// Returns an error if the encoded frame exceeds the wire length limit or
    /// an action is invalid.
    pub fn packet_out(
        xid: u32,
        buffer_id: u32,
        in_port: Option<u32>,
        actions: Vec<Action>,
        data: &[u8],
    ) -> Result<Vec<u8>> {
        PacketOut::new(xid, buffer_id, in_port, actions, data.to_vec()).encode()
    }

    /// Encode the standard priority-0 table-miss flow-mod sending misses to the controller.
    ///
    /// # Errors
    ///
    /// Returns an error if the encoded frame exceeds the wire length limit.
    pub fn table_miss_to_controller(xid: u32) -> Result<Vec<u8>> {
        Rule::table_miss_to_controller(xid).encode()
    }

    /// Encode an `OFPT_FLOW_MOD` from a [`Rule`].
    ///
    /// # Errors
    ///
    /// Returns an error if the rule cannot be encoded within the wire limits.
    pub fn flow_mod(flow_mod: &Rule) -> Result<Vec<u8>> {
        flow_mod.encode()
    }

    /// Encode an `OFPT_BARRIER_REQUEST`.
    pub fn barrier_request(xid: u32) -> Vec<u8> {
        Barrier::new(xid).encode_request()
    }

    /// Encode an `OFPT_BARRIER_REPLY`.
    pub fn barrier_reply(xid: u32) -> Vec<u8> {
        Barrier::new(xid).encode_reply()
    }

    /// Encode an `OFPT_GET_ASYNC_REQUEST`.
    ///
    /// # Errors
    ///
    /// Returns an error if the encoded message would exceed the wire
    /// format's `u16` length limit.
    pub fn get_async_request(xid: u32) -> Result<Vec<u8>> {
        control::encode_get_async_request(xid)
    }

    /// Encode an `OFPT_GET_ASYNC_REPLY` from raw property bytes (switch side).
    ///
    /// # Errors
    ///
    /// Returns an error if the encoded message would exceed the wire
    /// format's `u16` length limit.
    pub fn get_async_reply(xid: u32, properties: &[u8]) -> Result<Vec<u8>> {
        control::encode_get_async_reply(xid, properties)
    }

    /// Encode an `OFPT_GET_ASYNC_REPLY` from typed properties.
    ///
    /// # Errors
    ///
    /// Returns an error if a property list cannot be encoded within the wire
    /// length limit.
    pub fn get_async_reply_properties(
        xid: u32,
        properties: &[crate::protocol::control::Property],
    ) -> Result<Vec<u8>> {
        control::encode_get_async_reply_properties(xid, properties)
    }

    /// Encode an `OFPT_SET_ASYNC` selecting which async events this connection receives.
    ///
    /// # Errors
    ///
    /// Returns an error if the encoded message would exceed the wire
    /// format's `u16` length limit.
    pub fn set_async(
        xid: u32,
        properties: &[crate::protocol::control::Property],
    ) -> Result<Vec<u8>> {
        control::encode_set_async(xid, properties)
    }

    /// Encode an `OFPT_ROLE_REQUEST` (`OFPCR_ROLE_*`).
    ///
    /// # Errors
    ///
    /// Returns an error if the encoded message would exceed the wire
    /// format's `u16` length limit.
    pub fn role_request(xid: u32, role: u32, short_id: u16, generation_id: u64) -> Result<Vec<u8>> {
        control::encode_role_request(xid, role, short_id, generation_id)
    }

    /// Encode an `OFPT_ROLE_REPLY` (switch side).
    ///
    /// # Errors
    ///
    /// Returns an error if the encoded message would exceed the wire
    /// format's `u16` length limit.
    pub fn role_reply(xid: u32, role: u32, short_id: u16, generation_id: u64) -> Result<Vec<u8>> {
        control::encode_role_reply(xid, role, short_id, generation_id)
    }

    /// Encode an `OFPT_MULTIPART_REQUEST` from a raw body.
    ///
    /// # Errors
    ///
    /// Returns an error if the encoded message would exceed the wire
    /// format's `u16` length limit.
    pub fn multipart_request(xid: u32, kind: u16, flags: u16, body: &[u8]) -> Result<Vec<u8>> {
        control::encode_multipart_request(xid, kind, flags, body)
    }

    /// Encode an `OFPT_MULTIPART_REPLY` from a raw body (switch side).
    ///
    /// # Errors
    ///
    /// Returns an error if the encoded message would exceed the wire
    /// format's `u16` length limit.
    pub fn multipart_reply(xid: u32, kind: u16, flags: u16, body: &[u8]) -> Result<Vec<u8>> {
        control::encode_multipart_reply(xid, kind, flags, body)
    }

    /// Encode an `OFPT_MULTIPART_REQUEST` from a typed body.
    ///
    /// # Errors
    ///
    /// Returns an error if the encoded message would exceed the wire
    /// format's `u16` length limit.
    pub fn multipart_request_from_body(
        xid: u32,
        kind: u16,
        flags: u16,
        body: &control::MultipartRequestBody,
    ) -> Result<Vec<u8>> {
        control::MultipartMessage::from_request_body(xid, kind, flags, body)?.encode_request()
    }

    /// Encode an `OFPT_TABLE_MOD`.
    ///
    /// # Errors
    ///
    /// Returns an error if the encoded message would exceed the wire
    /// format's `u16` length limit.
    pub fn table_mod(
        xid: u32,
        table_id: u8,
        config: u32,
        properties: &[control::TableModProperty],
    ) -> Result<Vec<u8>> {
        control::encode_table_mod(xid, table_id, config, properties)
    }

    /// Encode an `OFPT_PORT_MOD`.
    ///
    /// # Errors
    ///
    /// Returns an error if the encoded message would exceed the wire
    /// format's `u16` length limit.
    pub fn port_mod(
        xid: u32,
        port_no: u32,
        hw_addr: [u8; 6],
        config: u32,
        mask: u32,
        properties: &[control::PortModProperty],
    ) -> Result<Vec<u8>> {
        control::encode_port_mod(xid, port_no, hw_addr, config, mask, properties)
    }

    /// Encode an `OFPT_METER_MOD` (`OFPMC_*` command, `OFPMF_*` flags).
    ///
    /// # Errors
    ///
    /// Returns an error if the encoded message would exceed the wire
    /// format's `u16` length limit.
    pub fn meter_mod(
        xid: u32,
        command: u16,
        flags: u16,
        meter_id: u32,
        bands: &[control::MeterBand],
    ) -> Result<Vec<u8>> {
        control::encode_meter_mod(xid, command, flags, meter_id, bands)
    }

    /// Encode an `OFPT_BUNDLE_CONTROL` (`OFPBCT_*`).
    ///
    /// # Errors
    ///
    /// Returns an error if the encoded message would exceed the wire
    /// format's `u16` length limit.
    pub fn bundle_control(
        xid: u32,
        bundle_id: u32,
        ctrl_type: u16,
        flags: u16,
        properties: &[control::BundleProperty],
    ) -> Result<Vec<u8>> {
        control::BundleMessage {
            xid,
            bundle_id,
            ctrl_type,
            flags,
            properties: properties.to_vec(),
        }
        .encode()
    }

    /// Encode an `OFPT_BUNDLE_ADD_MESSAGE` wrapping an already-encoded message.
    ///
    /// # Errors
    ///
    /// Returns an error if the encoded message would exceed the wire
    /// format's `u16` length limit.
    pub fn bundle_add_message(
        xid: u32,
        bundle_id: u32,
        flags: u16,
        message: &[u8],
        properties: &[control::BundleProperty],
    ) -> Result<Vec<u8>> {
        control::encode_bundle_add_message(xid, bundle_id, flags, message, properties)
    }

    /// Encode an `OFPT_TABLE_STATUS` (switch side).
    ///
    /// # Errors
    ///
    /// Returns an error if the encoded message would exceed the wire
    /// format's `u16` length limit.
    pub fn table_status(status: &control::TableStatus) -> Result<Vec<u8>> {
        control::encode_table_status(status)
    }

    /// Encode an `OFPT_CONTROLLER_STATUS` (switch side).
    ///
    /// # Errors
    ///
    /// Returns an error if the encoded message would exceed the wire
    /// format's `u16` length limit.
    pub fn controller_status(status: &control::ControllerStatus) -> Result<Vec<u8>> {
        control::encode_controller_status(status)
    }

    /// Encode an `OFPT_FEATURES_REPLY` (switch side).
    pub fn features_reply(reply: &features::Reply) -> Vec<u8> {
        reply.encode()
    }

    /// Encode an `OFPT_PACKET_IN` (switch side).
    ///
    /// # Errors
    ///
    /// Returns an error if the encoded message would exceed the wire
    /// format's `u16` length limit.
    pub fn packet_in(packet_in: &PacketIn) -> Result<Vec<u8>> {
        packet_in.encode()
    }

    /// Encode an `OFPT_FLOW_REMOVED` (switch side).
    ///
    /// # Errors
    ///
    /// Returns an error if the encoded message would exceed the wire
    /// format's `u16` length limit.
    pub fn flow_removed(removed: &control::FlowRemoved) -> Result<Vec<u8>> {
        removed.encode()
    }

    /// Encode an `OFPT_PORT_STATUS` (switch side).
    ///
    /// # Errors
    ///
    /// Returns an error if the encoded message would exceed the wire
    /// format's `u16` length limit.
    pub fn port_status(status: &control::PortStatus) -> Result<Vec<u8>> {
        status.encode()
    }

    /// Encode an `OFPT_ROLE_STATUS` (switch side).
    ///
    /// # Errors
    ///
    /// Returns an error if the encoded message would exceed the wire
    /// format's `u16` length limit.
    pub fn role_status(status: &control::RoleStatus) -> Result<Vec<u8>> {
        status.encode()
    }

    /// Encode an `OFPT_REQUESTFORWARD` (switch side).
    ///
    /// # Errors
    ///
    /// Returns an error if the encoded message would exceed the wire
    /// format's `u16` length limit.
    pub fn request_forward(forward: &control::RequestForward) -> Result<Vec<u8>> {
        forward.encode()
    }

    /// Encode an `OFPT_EXPERIMENTER` message.
    ///
    /// # Errors
    ///
    /// Returns an error if the encoded message would exceed the wire
    /// format's `u16` length limit.
    pub fn experimenter(
        xid: u32,
        experimenter: u32,
        exp_type: u32,
        data: &[u8],
    ) -> Result<Vec<u8>> {
        control::encode_experimenter(xid, experimenter, exp_type, data)
    }
}

/// Decodes wire frames into typed messages.
///
/// `Decoder::message` is not public: use
/// [`crate::client::Connection::recv_message`] for the general case. The
/// methods here are the targeted decoders, for when you already know what
/// a frame is -- typically when writing the switch side of the protocol.
///
/// ```
/// use openflow::protocol::codec::{Decoder, Encoder};
///
/// let frame = Encoder::error(1, 1, 0, b"bad")?;
/// let err = Decoder::error(&frame)?;
/// assert_eq!(err.error_type, 1);
/// # Ok::<(), openflow::protocol::error::OfError>(())
/// ```
pub struct Decoder;

impl Decoder {
    pub(crate) fn message(frame: &[u8]) -> Result<Message> {
        message::decode(frame)
    }

    /// Decode a flow-modification frame.
    ///
    /// # Errors
    ///
    /// Returns an error when the frame is too short, the message type does
    /// not match `FLOW_MOD`, or the payload is otherwise malformed.
    pub fn flow_mod(frame: &[u8]) -> Result<Entry> {
        Entry::parse(frame)
    }

    /// Decode an `OpenFlow` error message.
    ///
    /// # Errors
    ///
    /// Returns an error when the frame is too short, the message type does
    /// not match `ERROR`, or the payload is otherwise malformed.
    pub fn error(frame: &[u8]) -> Result<ErrorMessage> {
        ErrorMessage::parse(frame)
    }

    /// Decode a configuration reply.
    ///
    /// # Errors
    ///
    /// Returns an error when the frame is too short, the message type does
    /// not match `GET_CONFIG_REPLY`, or the payload is otherwise malformed.
    pub fn get_config_reply(frame: &[u8]) -> Result<Config> {
        Config::parse_reply(frame)
    }

    /// Decode a raw action list.
    ///
    /// # Errors
    ///
    /// Returns an error when the action buffer is truncated or malformed.
    pub fn actions(buf: &[u8]) -> Result<Vec<Action>> {
        parse_actions(buf)
    }

    /// Decode a raw instruction list.
    ///
    /// # Errors
    ///
    /// Returns an error when the instruction buffer is truncated or malformed.
    pub fn instructions(buf: &[u8]) -> Result<Vec<Instruction>> {
        parse_instructions(buf)
    }

    /// Decode a role request frame.
    ///
    /// # Errors
    ///
    /// Returns an error when the frame is too short, the message type does
    /// not match `ROLE_REQUEST`, or the payload is otherwise malformed.
    pub fn role_request(frame: &[u8]) -> Result<RoleRequest> {
        control::parse_role_request(frame)
    }

    /// Decode an `OFPT_SET_CONFIG` frame (switch side).
    ///
    /// # Errors
    ///
    /// Returns an error when the frame is too short, the message type
    /// does not match `SET_CONFIG`, or the payload is malformed.
    pub fn set_config(frame: &[u8]) -> Result<Config> {
        crate::protocol::config::parse_set_config(frame)
    }

    /// Decode an `OFPT_PACKET_OUT` frame (switch side).
    ///
    /// # Errors
    ///
    /// Returns an error when the frame is too short, the message type
    /// does not match `PACKET_OUT`, or the payload is malformed.
    pub fn packet_out(frame: &[u8]) -> Result<PacketOut> {
        PacketOut::parse(frame)
    }

    /// Decode an `OFPT_FEATURES_REQUEST` frame (switch side), which
    /// carries only a header.
    ///
    /// # Errors
    ///
    /// Returns an error when the frame is malformed or is not a
    /// features request.
    pub fn features_request(frame: &[u8]) -> Result<features::Request> {
        features::Request::parse(frame)
    }

    /// Decode an `OFPT_GET_CONFIG_REQUEST` frame (switch side),
    /// returning its xid.
    ///
    /// # Errors
    ///
    /// Returns an error when the frame is malformed or is not a
    /// get-config request.
    pub fn get_config_request(frame: &[u8]) -> Result<u32> {
        Config::parse_get_request(frame)
    }
}

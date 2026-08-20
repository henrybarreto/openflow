//! [`Message`], the union of every `OpenFlow` 1.5.1 message type.
//!
//! Decoding is [`crate::client::Connection::recv_message`] (or the
//! crate-internal `Decoder::message`); encoding goes the other way,
//! through [`crate::protocol::codec::Encoder`].

use crate::protocol::bytes::read_u32;
use crate::protocol::config::Config;
use crate::protocol::constants::{
    OFPT_BARRIER_REPLY, OFPT_BARRIER_REQUEST, OFPT_BUNDLE_ADD_MESSAGE, OFPT_BUNDLE_CONTROL,
    OFPT_CONTROLLER_STATUS, OFPT_ECHO_REPLY, OFPT_ECHO_REQUEST, OFPT_ERROR, OFPT_EXPERIMENTER,
    OFPT_FEATURES_REPLY, OFPT_FEATURES_REQUEST, OFPT_FLOW_MOD, OFPT_FLOW_REMOVED,
    OFPT_GET_ASYNC_REPLY, OFPT_GET_ASYNC_REQUEST, OFPT_GET_CONFIG_REPLY, OFPT_GET_CONFIG_REQUEST,
    OFPT_GROUP_MOD, OFPT_HELLO, OFPT_METER_MOD, OFPT_MULTIPART_REPLY, OFPT_MULTIPART_REQUEST,
    OFPT_PACKET_IN, OFPT_PACKET_OUT, OFPT_PORT_MOD, OFPT_PORT_STATUS, OFPT_REQUESTFORWARD,
    OFPT_ROLE_REPLY, OFPT_ROLE_REQUEST, OFPT_ROLE_STATUS, OFPT_SET_ASYNC, OFPT_SET_CONFIG,
    OFPT_TABLE_MOD, OFPT_TABLE_STATUS,
};
use crate::protocol::constants::{OFP_HEADER_LEN, OFP_VERSION_1_5};
use crate::protocol::control::{
    parse_async_config_get_reply, parse_async_config_set, parse_async_controller_status,
    parse_async_flow_removed, parse_async_port_status, parse_async_request_forward,
    parse_async_role_status, parse_async_table_status, parse_bundle_add_message,
    parse_bundle_message, parse_group_mod, parse_meter_mod, parse_multipart_reply,
    parse_multipart_request, parse_port_mod, parse_role_reply, parse_role_request, parse_table_mod,
    BundleAddMessage, BundleMessage, ControllerStatus, FlowRemoved, GroupMod, MeterMod,
    MultipartMessage, PortMod, PortStatus, Property, RequestForward, RoleRequest, RoleStatus,
    TableMod, TableStatus,
};
use crate::protocol::error::{OfError, Result};
use crate::protocol::error_msg::{parse_error, ErrorMessage};
use crate::protocol::features::Reply;
use crate::protocol::header::Header;
use crate::protocol::hello::Hello;
use crate::protocol::packet_in::PacketIn;
use crate::protocol::packet_out::PacketOut;
use crate::protocol::rule::Entry;

#[derive(Debug)]
/// Any `OpenFlow` message, in either direction.
///
/// Variants carrying a single typed struct (`Message::FlowRemoved`,
/// `Message::MultipartReply`, ...) delegate to that struct; the ones with
/// inline fields are messages whose whole body is one or two scalars.
///
/// Decoding never fails on an unrecognized `OFPT_*` type: the frame comes
/// back as [`Message::Ignored`], header and body intact. What does fail is
/// a *structural* problem -- a truncated frame, or a non-Hello message
/// whose header version is not 1.5
/// ([`crate::protocol::error::OfError::UnsupportedVersion`]).
/// `OFPT_EXPERIMENTER` is a defined type with a vendor-defined body, so it
/// decodes into [`Message::Experimenter`] with that body kept verbatim.
pub enum Message {
    /// `OFPT_HELLO`, the first message on any connection (§7.5.1).
    Hello {
        /// Transaction id.
        xid: u32,
        /// The `version` field of the peer's `OpenFlow` header.
        version: u8,
        /// The peer's `OFPHET_VERSIONBITMAP` element, if it sent one.
        version_bitmap: Option<Vec<u32>>,
    },
    /// `OFPT_ERROR`: the peer rejected something. See
    /// [`crate::protocol::error_msg::ErrorMessage`].
    Error(ErrorMessage),
    /// `OFPT_ECHO_REQUEST`: a keepalive that must be answered with the
    /// same payload.
    EchoRequest {
        /// Transaction id to echo back.
        xid: u32,
        /// Opaque payload to return unchanged.
        payload: Vec<u8>,
    },
    /// `OFPT_ECHO_REPLY`: the answer to an echo request.
    EchoReply {
        /// Transaction id from the request.
        xid: u32,
        /// The request's payload, unchanged.
        payload: Vec<u8>,
    },
    /// `OFPT_FEATURES_REQUEST`: asks for the switch's datapath id,
    /// table count and capabilities. Header only.
    FeaturesRequest {
        /// Transaction id.
        xid: u32,
    },
    /// `OFPT_FEATURES_REPLY` (`ofp_switch_features`).
    FeaturesReply(Reply),
    /// `OFPT_GET_CONFIG_REQUEST`: asks for fragment handling and
    /// `miss_send_len`. Header only.
    GetConfigRequest {
        /// Transaction id.
        xid: u32,
    },
    /// `OFPT_GET_CONFIG_REPLY` (`ofp_switch_config`).
    GetConfigReply(Config),
    /// `OFPT_SET_CONFIG`: sets fragment handling and `miss_send_len`.
    SetConfig(Config),
    /// `OFPT_PACKET_OUT`: controller injects a packet into the pipeline.
    PacketOut(PacketOut),
    /// `OFPT_PACKET_IN`: the pipeline punted a packet to the controller.
    PacketIn(PacketIn),
    /// `OFPT_FLOW_MOD`: add, modify or delete a flow entry. Decodes into
    /// [`Entry`]; build one to send with
    /// [`crate::protocol::rule::Rule`].
    FlowMod(Entry),
    /// `OFPT_FLOW_REMOVED`: an entry expired or was deleted. Only sent
    /// for entries installed with `OFPFF_SEND_FLOW_REM`.
    FlowRemoved(FlowRemoved),
    /// `OFPT_PORT_STATUS`: a port was added, removed or changed.
    PortStatus(PortStatus),
    /// `OFPT_GROUP_MOD`: add, modify or delete a group.
    GroupMod(GroupMod),
    /// `OFPT_PORT_MOD`: change a port's configuration.
    PortMod(PortMod),
    /// `OFPT_TABLE_MOD`: change a table's configuration.
    TableMod(TableMod),
    /// `OFPT_MULTIPART_REQUEST`: a statistics or description query.
    MultipartRequest(MultipartMessage),
    /// `OFPT_MULTIPART_REPLY`: one part of a query's answer; more follow
    /// while `OFPMPF_REPLY_MORE` is set.
    MultipartReply(MultipartMessage),
    /// `OFPT_ROLE_REQUEST`: claim master, slave or equal role.
    RoleRequest(RoleRequest),
    /// `OFPT_ROLE_REPLY`: the role the switch granted.
    RoleReply(RoleRequest),
    /// `OFPT_GET_ASYNC_REQUEST`: asks which async events this connection
    /// receives. Header only.
    GetAsyncRequest {
        /// Transaction id.
        xid: u32,
    },
    /// `OFPT_GET_ASYNC_REPLY`: the connection's current async mask.
    GetAsyncReply {
        /// Transaction id.
        xid: u32,
        /// `OFPACPT_*` properties describing the mask.
        properties: Vec<Property>,
    },
    /// `OFPT_SET_ASYNC`: choose which async events this connection
    /// receives. A fresh connection gets few until this is sent.
    SetAsync {
        /// Transaction id.
        xid: u32,
        /// `OFPACPT_*` properties describing the wanted mask.
        properties: Vec<Property>,
    },
    /// `OFPT_ROLE_STATUS`: the switch changed this connection's role.
    RoleStatus(RoleStatus),
    /// `OFPT_TABLE_STATUS`: a table's state changed (1.5).
    TableStatus(TableStatus),
    /// `OFPT_REQUESTFORWARD`: the switch forwards another controller's
    /// group- or meter-mod to this one.
    RequestForward(RequestForward),
    /// `OFPT_CONTROLLER_STATUS`: a controller connection's status changed
    /// (1.5).
    ControllerStatus(ControllerStatus),
    /// `OFPT_METER_MOD`: add, modify or delete a meter.
    MeterMod(MeterMod),
    /// `OFPT_BUNDLE_CONTROL`: open, close, commit or discard a bundle.
    BundleControl(BundleMessage),
    /// `OFPT_BUNDLE_ADD_MESSAGE`: add one message to an open bundle.
    BundleAddMessage(BundleAddMessage),
    /// `OFPT_BARRIER_REQUEST`: process everything sent so far, then
    /// reply. Header only.
    BarrierRequest {
        /// Transaction id.
        xid: u32,
    },
    /// `OFPT_BARRIER_REPLY`: everything before the barrier is done.
    BarrierReply {
        /// Transaction id from the request.
        xid: u32,
    },
    /// `OFPT_EXPERIMENTER`: a vendor message. The body is vendor-defined,
    /// so it is kept verbatim.
    Experimenter {
        /// Transaction id.
        xid: u32,
        /// The vendor's experimenter id.
        experimenter: u32,
        /// Vendor-defined subtype.
        exp_type: u32,
        /// Vendor payload following the 16-byte header.
        data: Vec<u8>,
    },
    /// A message this crate decodes structurally but does not model
    /// further; header and body are kept so it can be re-encoded or
    /// inspected by hand.
    Ignored {
        /// The message's parsed header.
        header: Header,
        /// Everything after the 8-byte header.
        payload: Vec<u8>,
    },
}

pub(crate) fn decode(frame: &[u8]) -> Result<Message> {
    let header = Header::parse(frame)?;
    let msg_len = header.length as usize;
    if frame.len() < msg_len {
        return Err(OfError::ShortBuffer);
    }
    let message = frame.get(..msg_len).ok_or(OfError::ShortBuffer)?;
    let payload = message.get(8..).ok_or(OfError::ShortBuffer)?;

    if header.msg_type != OFPT_HELLO && header.version != OFP_VERSION_1_5 {
        return Err(OfError::UnsupportedVersion(header.version));
    }

    if matches!(
        header.msg_type,
        OFPT_FEATURES_REQUEST
            | OFPT_GET_CONFIG_REQUEST
            | OFPT_GET_ASYNC_REQUEST
            | OFPT_BARRIER_REQUEST
            | OFPT_BARRIER_REPLY
    ) && msg_len != OFP_HEADER_LEN
    {
        return Err(OfError::InvalidLength(header.length));
    }

    match header.msg_type {
        OFPT_HELLO => {
            let hello = Hello::parse(message)?;
            Ok(Message::Hello {
                xid: header.xid,
                version: hello.version,
                version_bitmap: hello.version_bitmap,
            })
        }
        OFPT_ERROR => Ok(Message::Error(parse_error(message)?)),
        OFPT_ECHO_REQUEST => Ok(Message::EchoRequest {
            xid: header.xid,
            payload: payload.to_vec(),
        }),
        OFPT_ECHO_REPLY => Ok(Message::EchoReply {
            xid: header.xid,
            payload: payload.to_vec(),
        }),
        OFPT_FEATURES_REQUEST => Ok(Message::FeaturesRequest { xid: header.xid }),
        OFPT_FEATURES_REPLY => Ok(Message::FeaturesReply(Reply::parse(message)?)),
        OFPT_GET_CONFIG_REQUEST => Ok(Message::GetConfigRequest { xid: header.xid }),
        OFPT_SET_CONFIG => Ok(Message::SetConfig(
            crate::protocol::config::parse_set_config(message)?,
        )),
        OFPT_PACKET_OUT => Ok(Message::PacketOut(PacketOut::parse(message)?)),
        OFPT_GET_CONFIG_REPLY => Ok(Message::GetConfigReply(
            crate::protocol::config::parse_get_config_reply(message)?,
        )),
        OFPT_PACKET_IN => Ok(Message::PacketIn(PacketIn::parse(message)?)),
        OFPT_FLOW_MOD => Ok(Message::FlowMod(Entry::parse(message)?)),
        OFPT_FLOW_REMOVED => Ok(Message::FlowRemoved(parse_async_flow_removed(message)?)),
        OFPT_PORT_STATUS => Ok(Message::PortStatus(parse_async_port_status(message)?)),
        OFPT_GROUP_MOD => Ok(Message::GroupMod(parse_group_mod(message)?)),
        OFPT_PORT_MOD => Ok(Message::PortMod(parse_port_mod(message)?)),
        OFPT_TABLE_MOD => Ok(Message::TableMod(parse_table_mod(message)?)),
        OFPT_MULTIPART_REQUEST => Ok(Message::MultipartRequest(parse_multipart_request(message)?)),
        OFPT_MULTIPART_REPLY => Ok(Message::MultipartReply(parse_multipart_reply(message)?)),
        OFPT_ROLE_REQUEST => Ok(Message::RoleRequest(parse_role_request(message)?)),
        OFPT_ROLE_REPLY => Ok(Message::RoleReply(parse_role_reply(message)?)),
        OFPT_GET_ASYNC_REQUEST => Ok(Message::GetAsyncRequest { xid: header.xid }),
        OFPT_GET_ASYNC_REPLY => Ok(Message::GetAsyncReply {
            xid: header.xid,
            properties: parse_async_config_get_reply(message)?.properties,
        }),
        OFPT_SET_ASYNC => Ok(Message::SetAsync {
            xid: header.xid,
            properties: parse_async_config_set(message)?.properties,
        }),
        OFPT_METER_MOD => Ok(Message::MeterMod(parse_meter_mod(message)?)),
        OFPT_ROLE_STATUS => Ok(Message::RoleStatus(parse_async_role_status(message)?)),
        OFPT_TABLE_STATUS => Ok(Message::TableStatus(parse_async_table_status(message)?)),
        OFPT_REQUESTFORWARD => Ok(Message::RequestForward(parse_async_request_forward(
            message,
        )?)),
        OFPT_CONTROLLER_STATUS => Ok(Message::ControllerStatus(parse_async_controller_status(
            message,
        )?)),
        OFPT_BUNDLE_CONTROL => Ok(Message::BundleControl(parse_bundle_message(message)?)),
        OFPT_BUNDLE_ADD_MESSAGE => Ok(Message::BundleAddMessage(parse_bundle_add_message(
            message,
        )?)),
        OFPT_BARRIER_REQUEST => Ok(Message::BarrierRequest { xid: header.xid }),
        OFPT_BARRIER_REPLY => Ok(Message::BarrierReply { xid: header.xid }),
        OFPT_EXPERIMENTER => {
            if msg_len < 16 {
                return Err(OfError::ShortBuffer);
            }

            Ok(Message::Experimenter {
                xid: header.xid,
                experimenter: read_u32(message, 8)?,
                exp_type: read_u32(message, 12)?,
                data: message.get(16..).ok_or(OfError::ShortBuffer)?.to_vec(),
            })
        }
        _ => Ok(Message::Ignored {
            header,
            payload: payload.to_vec(),
        }),
    }
}

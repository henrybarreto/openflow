//! Wire constants for `OpenFlow` 1.5.1, named exactly as the specification
//! names them.
//!
//! Every value here comes from `docs/rfcs/openflow-switch-v1.5.1.txt` and
//! is checked against that text by a scripted diff, so a constant in this
//! file always carries its spec value.
//!
//! # Assembling a flow entry
//!
//! Four families combine to make one flow: an `OFPXMT_OFB_*` match field
//! says *which packets*, an `OFPIT_*` instruction says *what to do*, an
//! `OFPAT_*` action says *how*, and an `OFPP_*` port says *where*.
//!
//! ```
//! use openflow::protocol::action::Action;
//! use openflow::protocol::constants::{OFPCML_NO_BUFFER, OFPP_CONTROLLER, OFPT_FLOW_MOD};
//! use openflow::protocol::instruction::Instruction;
//! use openflow::protocol::ofmatch::Match;
//! use openflow::protocol::{oxm, rule::Rule};
//!
//! // "Every IPv4 packet arriving on port 1 goes to the controller."
//! let rule = Rule::add(
//!     1,   // xid
//!     0,   // table_id
//!     100, // priority
//!     Match::new(vec![oxm::in_port(1), oxm::eth_type(0x0800)]),
//!     vec![Instruction::ApplyActions(vec![Action::Output {
//!         port: OFPP_CONTROLLER,
//!         max_len: OFPCML_NO_BUFFER,
//!     }])],
//! );
//! assert_eq!(rule.encode().unwrap()[1], OFPT_FLOW_MOD);
//! ```
//!
//! # Reading the prefixes
//!
//! The prefix names the family, and the family says which struct field the
//! value belongs in:
//!
//! | Prefix | Family | Where it goes |
//! |---|---|---|
//! | `OFPT_` | message type | `ofp_header.type` |
//! | `OFPP_` | port number | `ofp_action_output.port`, `ofp_flow_mod.out_port` |
//! | `OFPXMT_OFB_` | match field | an OXM TLV inside `ofp_match` |
//! | `OFPXST_OFB_` | stat field | an OXS TLV inside `ofp_stats` |
//! | `OFPAT_` | action type | `ofp_action_header.type` |
//! | `OFPIT_` | instruction type | `ofp_instruction_header.type` |
//! | `OFPFC_` / `OFPFF_` | flow command / flags | `ofp_flow_mod.command` / `.flags` |
//! | `OFPGC_` / `OFPGT_` | group command / type | `ofp_group_mod.command` / `.type` |
//! | `OFPMC_` / `OFPMF_` | meter command / flags | `ofp_meter_mod.command` / `.flags` |
//! | `OFPMP_` | multipart subtype | `ofp_multipart_request.type` |
//! | `OFPET_` | error type | `ofp_error_msg.type` |
//! | `OFPBCT_` / `OFPBF_` | bundle command / flags | `ofp_bundle_ctrl_msg.type` / `.flags` |
//! | `OFPACPT_` | async property | `ofp_async_config` property list |
//! | `NXM_` / `NXAST_` / `NX_` | Nicira extension | Open vSwitch only, not in the spec |
//!
//! # Reserved values are not ordinary numbers
//!
//! Several families reserve the top of their range. Using a reserved value
//! where a real one belongs (or the reverse) is the most common cause of an
//! `OFPT_ERROR` reply.
//!
//! ```
//! use openflow::protocol::constants::{OFPP_CONTROLLER, OFPP_MAX, OFPTT_ALL, OFPTT_MAX};
//!
//! assert!(OFPP_CONTROLLER > OFPP_MAX); // real ports stop at OFPP_MAX
//! assert!(OFPTT_ALL > OFPTT_MAX);      // OFPTT_ALL is a delete-only wildcard
//! ```
//!
//! # Family notes
//!
//! Behaviour the one-line docs below cannot carry, gathered per family.
//!
//! ## Ports (`OFPP_*`)
//!
//! - `OFPP_IN_PORT` must be named explicitly: a plain output action naming
//!   the ingress port is dropped, because a packet is never sent back the
//!   way it came by default.
//! - `OFPP_TABLE` is legal only inside `ofp_packet_out`; in a flow entry it
//!   draws `OFPBAC_BAD_OUT_PORT`.
//! - `OFPP_ANY` is a *query* wildcard (`out_port` filters, stats requests),
//!   never an output target.
//! - `max_len` in an output action only means anything for
//!   `OFPP_CONTROLLER`; `OFPCML_NO_BUFFER` sends the whole packet.
//!
//! ## Flow commands (`OFPFC_*`) and flags (`OFPFF_*`)
//!
//! - `_STRICT` variants match priority and the full match, masks included,
//!   exactly. The non-strict forms treat the request as a wildcard superset,
//!   so a non-strict delete with an empty match clears the table.
//! - Neither `MODIFY` nor `DELETE` reports an error when nothing matches.
//! - `OFPFF_SEND_FLOW_REM` asks for an `OFPT_FLOW_REMOVED` when the entry
//!   goes away. The spec only says a controller-initiated delete *should*
//!   generate one, and Open vSwitch does not; a timeout expiry always does.
//! - A connection also has to opt in via `OFPT_SET_ASYNC` before Open
//!   vSwitch delivers `FLOW_REMOVED` or `PORT_STATUS` at all.
//!
//! ## Tables (`OFPTT_*`)
//!
//! Real table ids run to `OFPTT_MAX` (254). `OFPTT_ALL` is a wildcard for
//! delete and stats requests only -- using it as the target of an
//! `OFPFC_ADD` draws `OFPFMFC_BAD_TABLE_ID`.
//!
//! ## Groups (`OFPGT_*`, `OFPGC_*`, `OFPG_*`)
//!
//! - `ALL` runs every bucket (flooding), `SELECT` picks one by hash or
//!   weight, `INDIRECT` must hold exactly one bucket, and `FF` runs the
//!   first bucket whose watch port or watch group is live.
//! - `command_bucket_id` is used *only* by `INSERT_BUCKET` and
//!   `REMOVE_BUCKET`. For `ADD`, `MODIFY` and `DELETE` it must be
//!   `OFPG_BUCKET_ALL`; anything else is `OFPGMFC_BAD_BUCKET`.
//! - `OFPG_ALL` (`0xfffffffc`) means "every group" in a delete or a stats
//!   request. It is *not* `OFPG_ANY` (`0xffffffff`), which means "no group".
//!
//! ## Meters (`OFPMC_*`, `OFPMF_*`)
//!
//! A meter must declare its rate unit: exactly one of `OFPMF_KBPS` or
//! `OFPMF_PKTPS`. A `flags` of zero is rejected with `OFPMMFC_BAD_FLAGS`.
//!
//! ```
//! use openflow::protocol::constants::{OFPMC_ADD, OFPMF_KBPS};
//! use openflow::protocol::control::{MeterBand, MeterMod};
//!
//! let meter = MeterMod {
//!     xid: 1,
//!     command: OFPMC_ADD,
//!     flags: OFPMF_KBPS, // never 0
//!     meter_id: 1,
//!     bands: vec![MeterBand::Drop { rate: 1000, burst_size: 0 }],
//! };
//! assert!(meter.encode().is_ok());
//! ```
//!
//! ## Bundles (`OFPBCT_*`, `OFPBF_*`)
//!
//! The lifecycle is OPEN -> ADD... -> CLOSE -> COMMIT, with DISCARD
//! abandoning it at any point; each request has a matching `_REPLY`.
//! Every message added to a bundle must carry the same xid as its
//! enclosing `OFPT_BUNDLE_ADD_MESSAGE`, or the switch answers
//! `OFPBFC_MSG_BAD_XID`.
//!
//! ## Async configuration (`OFPACPT_*`)
//!
//! Properties come in `_SLAVE`/`_MASTER` pairs; the master mask also
//! governs the equal role. A mask may only set bits the corresponding
//! reason enum defines -- an out-of-range bit draws
//! `OFPET_ASYNC_CONFIG_FAILED`, so all-ones is not a shortcut.
//!
//! ## Match fields (`OFPXMT_OFB_*`)
//!
//! Most fields have prerequisites: `OXM_OF_IPV4_SRC` needs
//! `OXM_OF_ETH_TYPE` = `0x0800` earlier in the same list, and 1.5 adds an
//! alternative form where `OXM_OF_PACKET_TYPE` supplies the context for a
//! pipeline whose packets have no Ethernet header. Only 15 of the 44
//! fields are maskable.
//!
//! ## Nicira extensions (`NXM_*`, `NXAST_*`, `NX_*`)
//!
//! Not part of any `OpenFlow` specification -- these are Open vSwitch
//! extensions for connection tracking, reconstructed from OVS's sources
//! and verified against a live bridge.

/// `OpenFlow` 1.5.x wire version (`OFP_VERSION`), written into `ofp_header.version` on every
/// message this crate sends.
pub const OFP_VERSION_1_5: u8 = 0x06;

/// Size in bytes of `ofp_header` (version, type, length, xid), the fixed prefix of every `OpenFlow`
/// message.
pub const OFP_HEADER_LEN: usize = 8;

// Hello element type: bitmap of `OpenFlow` versions supported.
/// `ofp_hello_elem_type`: bitmap of supported versions, carried as an
/// `ofp_hello_elem_versionbitmap` element in `OFPT_HELLO`.
pub const OFPHET_VERSIONBITMAP: u16 = 1;

/// `ofp_type` 0: symmetric `OFPT_HELLO`, first message on a new connection, carrying version-bitmap
/// elements.
pub const OFPT_HELLO: u8 = 0;
/// `ofp_type` 1: symmetric `OFPT_ERROR` (`ofp_error_msg`), reporting a type/code pair plus the
/// offending message.
pub const OFPT_ERROR: u8 = 1;
/// `ofp_type` 2: symmetric `OFPT_ECHO_REQUEST`, a liveness probe whose body must be echoed back.
pub const OFPT_ECHO_REQUEST: u8 = 2;
/// `ofp_type` 3: symmetric `OFPT_ECHO_REPLY`, the reply to `OFPT_ECHO_REQUEST` with the same xid
/// and body.
pub const OFPT_ECHO_REPLY: u8 = 3;
/// `ofp_type` 4: symmetric `OFPT_EXPERIMENTER` message, body defined by the experimenter id it
/// carries.
pub const OFPT_EXPERIMENTER: u8 = 4;
/// `ofp_type` 5: controller-to-switch `OFPT_FEATURES_REQUEST`, header only, asking for the
/// datapath's features.
pub const OFPT_FEATURES_REQUEST: u8 = 5;
/// `ofp_type` 6: switch-to-controller `ofp_switch_features`, carrying the datapath id, table count
/// and capabilities.
pub const OFPT_FEATURES_REPLY: u8 = 6;
/// `ofp_type` 7: controller-to-switch `OFPT_GET_CONFIG_REQUEST`, header only, asking for
/// `ofp_switch_config`.
pub const OFPT_GET_CONFIG_REQUEST: u8 = 7;
/// `ofp_type` 8: switch-to-controller `ofp_switch_config` reply with the fragment-handling flags
/// and `miss_send_len`.
pub const OFPT_GET_CONFIG_REPLY: u8 = 8;
/// `ofp_type` 9: controller-to-switch `ofp_switch_config`, setting the fragment-handling flags and
/// `miss_send_len`.
pub const OFPT_SET_CONFIG: u8 = 9;
/// `ofp_type` 10: asynchronous `ofp_packet_in`, a packet punted to the controller with a reason
/// from `ofp_packet_in_reason`.
pub const OFPT_PACKET_IN: u8 = 10;

// `ofp_packet_in_reason` (`OpenFlow` 1.5 spec, `enum ofp_packet_in_reason`).
/// `ofp_packet_in.reason` 0: no flow entry matched, so the table-miss entry sent the packet to the
/// controller.
pub const OFPR_TABLE_MISS: u8 = 0;
/// `ofp_packet_in.reason` 1: an `OFPAT_OUTPUT` to `OFPP_CONTROLLER` in an apply-actions instruction
/// sent the packet.
pub const OFPR_APPLY_ACTION: u8 = 1;
/// `ofp_packet_in.reason` 2: the packet had an invalid IP or MPLS TTL, detected by a
/// TTL-decrementing action.
pub const OFPR_INVALID_TTL: u8 = 2;
/// `ofp_packet_in.reason` 3: output to `OFPP_CONTROLLER` came from the packet's action set, not an
/// apply-actions list.
pub const OFPR_ACTION_SET: u8 = 3;
/// `ofp_packet_in.reason` 4: output to `OFPP_CONTROLLER` came from a group bucket.
pub const OFPR_GROUP: u8 = 4;
/// `ofp_packet_in.reason` 5: output to `OFPP_CONTROLLER` came from the action list of an
/// `ofp_packet_out`.
pub const OFPR_PACKET_OUT: u8 = 5;
/// `ofp_type` 11: asynchronous `ofp_flow_removed`, sent when a flow entry expires or is deleted
/// (see `ofp_flow_removed_reason`).
pub const OFPT_FLOW_REMOVED: u8 = 11;
/// `ofp_type` 12: asynchronous `ofp_port_status`, reporting a port added, removed or changed (see
/// `ofp_port_reason`).
pub const OFPT_PORT_STATUS: u8 = 12;
/// `ofp_type` 13: controller-to-switch `ofp_packet_out`, injecting a buffered or inline packet
/// through an action list.
pub const OFPT_PACKET_OUT: u8 = 13;
/// `ofp_type` 14: controller-to-switch `ofp_flow_mod`, adding, modifying or deleting flow entries.
pub const OFPT_FLOW_MOD: u8 = 14;
/// `ofp_type` 15: controller-to-switch `ofp_group_mod`, adding, modifying or deleting group entries
/// and buckets.
pub const OFPT_GROUP_MOD: u8 = 15;
/// `ofp_type` 16: controller-to-switch `ofp_port_mod`, changing a port's `ofp_port_config` bits and
/// properties.
pub const OFPT_PORT_MOD: u8 = 16;
/// `ofp_type` 17: controller-to-switch `ofp_table_mod`, changing a flow table's `ofp_table_config`
/// and properties.
pub const OFPT_TABLE_MOD: u8 = 17;
/// `ofp_type` 18: controller-to-switch `ofp_multipart_request`, whose body is selected by an
/// `OFPMP_*` type.
pub const OFPT_MULTIPART_REQUEST: u8 = 18;
/// `ofp_type` 19: switch-to-controller `ofp_multipart_reply`, possibly split over several messages
/// via `OFPMPF_REPLY_MORE`.
pub const OFPT_MULTIPART_REPLY: u8 = 19;
/// `ofp_type` 20: controller-to-switch `OFPT_BARRIER_REQUEST`, header only, forcing all prior
/// messages to complete first.
pub const OFPT_BARRIER_REQUEST: u8 = 20;
/// `ofp_type` 21: switch-to-controller `OFPT_BARRIER_REPLY`, sent once every message before the
/// barrier has been processed.
pub const OFPT_BARRIER_REPLY: u8 = 21;
/// `ofp_type` 24: controller-to-switch `ofp_role_request`, claiming an `ofp_controller_role` with a
/// generation id.
pub const OFPT_ROLE_REQUEST: u8 = 24;
/// `ofp_type` 25: switch-to-controller reply reporting the role actually in effect for this
/// connection.
pub const OFPT_ROLE_REPLY: u8 = 25;
/// `ofp_type` 26: controller-to-switch `OFPT_GET_ASYNC_REQUEST`, header only, asking for this
/// connection's async filters.
pub const OFPT_GET_ASYNC_REQUEST: u8 = 26;
/// `ofp_type` 27: switch-to-controller `ofp_async_config`, listing the `OFPACPT_*` masks in force
/// on this connection.
pub const OFPT_GET_ASYNC_REPLY: u8 = 27;
/// `ofp_type` 28: controller-to-switch `ofp_async_config`, choosing which asynchronous messages
/// this connection receives.
pub const OFPT_SET_ASYNC: u8 = 28;
/// `ofp_type` 29: controller-to-switch `ofp_meter_mod`, adding, modifying or deleting a meter and
/// its bands.
pub const OFPT_METER_MOD: u8 = 29;
/// `ofp_type` 30: asynchronous `ofp_role_status`, telling a controller its role changed (see
/// `ofp_controller_role_reason`).
pub const OFPT_ROLE_STATUS: u8 = 30;
/// `ofp_type` 31: asynchronous `ofp_table_status`, raised when a table crosses a vacancy threshold
/// (see `ofp_table_reason`).
pub const OFPT_TABLE_STATUS: u8 = 31;
/// `ofp_type` 32: asynchronous `ofp_requestforward`, relaying another controller's group or meter
/// mod to this one.
pub const OFPT_REQUESTFORWARD: u8 = 32;
/// `ofp_type` 33: controller-to-switch `ofp_bundle_ctrl_msg`, opening, closing, committing or
/// discarding a bundle.
pub const OFPT_BUNDLE_CONTROL: u8 = 33;
/// `ofp_type` 34: controller-to-switch `ofp_bundle_add_msg`, appending one encapsulated message to
/// an open bundle.
pub const OFPT_BUNDLE_ADD_MESSAGE: u8 = 34;
/// `ofp_type` 35: asynchronous `ofp_controller_status`, reporting a control-channel or role change
/// (see `ofp_controller_status_reason`).
pub const OFPT_CONTROLLER_STATUS: u8 = 35;

/// `ofp_port_no`: highest assignable physical or logical port number; anything above is a reserved
/// port.
pub const OFPP_MAX: u32 = 0xffff_ff00;
/// Reserved port: no output port set in the action set; the initial value of the
/// `OXM_OF_ACTSET_OUTPUT` field.
pub const OFPP_UNSET: u32 = 0xffff_fff7;
/// Reserved port: send the packet back out its ingress port. Must be named explicitly in an
/// `OFPAT_OUTPUT` action.
pub const OFPP_IN_PORT: u32 = 0xffff_fff8;
/// Reserved port: resubmit the packet to the first flow table. Valid only in an `ofp_packet_out`
/// action list.
pub const OFPP_TABLE: u32 = 0xffff_fff9;
/// Reserved port: forward using the switch's normal, non-`OpenFlow` L2/L3 pipeline. Valid in an
/// `OFPAT_OUTPUT` action.
pub const OFPP_NORMAL: u32 = 0xffff_fffa;
/// Reserved port: flood on all standard ports except the ingress port and any port set
/// `OFPPC_NO_FLOOD`. Valid in an `OFPAT_OUTPUT` action.
pub const OFPP_FLOOD: u32 = 0xffff_fffb;
/// Reserved port: send out every standard port except the ingress port. Valid in an `OFPAT_OUTPUT`
/// action.
pub const OFPP_ALL: u32 = 0xffff_fffc;
/// Reserved port: send the packet to the controller as an `ofp_packet_in`; the action's `max_len`
/// caps how much is sent.
///
/// The paired `max_len` decides how much of the packet is copied: a byte
/// count, or `OFPCML_NO_BUFFER` for the whole frame with no buffering.
///
/// ```
/// use openflow::protocol::action::Action;
/// use openflow::protocol::constants::{OFPCML_NO_BUFFER, OFPP_CONTROLLER};
///
/// let punt = Action::Output { port: OFPP_CONTROLLER, max_len: OFPCML_NO_BUFFER };
/// let mut out = Vec::new();
/// punt.encode(&mut out).unwrap();
/// assert_eq!(out.len(), 16); // ofp_action_output is 16 bytes
/// ```
pub const OFPP_CONTROLLER: u32 = 0xffff_fffd;
/// Reserved port: the switch's own local networking stack port. Can be an output port or an ingress
/// port.
pub const OFPP_LOCAL: u32 = 0xffff_fffe;
/// Reserved port: wildcard meaning "no port specified", used in `ofp_flow_mod.out_port` and port
/// stats requests.
pub const OFPP_ANY: u32 = 0xffff_ffff;

/// Sentinel for `ofp_packet_out.buffer_id` and `ofp_flow_mod.buffer_id` meaning no buffered packet
/// is referenced.
pub const OFP_NO_BUFFER: u32 = 0xffff_ffff;

/// `ofp_controller_max_len`: largest ordinary `max_len` usable in an `OFPAT_OUTPUT` action to
/// `OFPP_CONTROLLER`.
pub const OFPCML_MAX: u16 = 0xffe5;
/// `ofp_controller_max_len`: do not buffer; send the whole packet to the controller in the
/// `ofp_packet_in`.
///
/// Asks the switch to send the entire packet inline rather than buffering
/// it and sending a `buffer_id`. Simplest and most portable, at the cost
/// of copying every byte to the controller.
pub const OFPCML_NO_BUFFER: u16 = 0xffff;

/// `ofp_match_type` 1: the only match type in 1.5, meaning `ofp_match.type` is followed by OXM
/// TLVs.
pub const OFPMT_OXM: u16 = 1;

/// `ofp_oxm_class` 0x0000: legacy Nicira match class 0, kept for backward compatibility with NXM.
pub const OFPXMC_NXM_0: u16 = 0x0000;
/// `ofp_oxm_class` 0x0001: legacy Nicira match class 1, used here for the `NXM_NX_CT_*`
/// connection-tracking fields.
pub const OFPXMC_NXM_1: u16 = 0x0001;
/// `ofp_oxm_class` 0x8000: the basic class holding every `OFPXMT_OFB_*` match field.
pub const OFPXMC_OPENFLOW_BASIC: u16 = 0x8000;
/// `ofp_oxm_class` 0x8001: packet register (pipeline scratch) fields, addressed by register number.
pub const OFPXMC_PACKET_REGS: u16 = 0x8001;
/// `ofp_oxm_class` 0xffff: experimenter class; the TLV body starts with a 32-bit experimenter id.
pub const OFPXMC_EXPERIMENTER: u16 = 0xffff;

/// OXM basic field 0: ingress port the packet arrived on, physical, logical or `OFPP_LOCAL`. Not
/// maskable.
///
/// Mandatory in an `ofp_packet_out` match: the spec calls this TLV
/// required, and a packet-out with an empty match draws
/// `OFPBRC_BAD_PORT`.
///
/// ```
/// use openflow::protocol::oxm;
/// // A 4-byte OXM TLV: 4-byte header plus a u32 port.
/// assert_eq!(oxm::in_port(1).len(), 8);
/// ```
pub const OFPXMT_OFB_IN_PORT: u8 = 0;
/// OXM basic field 1: underlying physical ingress port; only meaningful in `ofp_packet_in` and
/// requires `OXM_OF_IN_PORT`.
pub const OFPXMT_OFB_IN_PHY_PORT: u8 = 1;
/// OXM basic field 2: 64-bit metadata carried between tables, written by `OFPIT_WRITE_METADATA`.
/// Maskable.
pub const OFPXMT_OFB_METADATA: u8 = 2;
/// OXM basic field 3: Ethernet destination MAC address. Maskable.
pub const OFPXMT_OFB_ETH_DST: u8 = 3;
/// OXM basic field 4: Ethernet source MAC address. Maskable.
pub const OFPXMT_OFB_ETH_SRC: u8 = 4;
/// OXM basic field 5: Ethernet frame type of the payload; the prerequisite for most L3 and L4
/// fields. Not maskable.
pub const OFPXMT_OFB_ETH_TYPE: u8 = 5;
/// OXM basic field 6: outermost 802.1Q VLAN id, or-ed with `OFPVID_PRESENT`; `OFPVID_NONE` means
/// untagged. Maskable.
pub const OFPXMT_OFB_VLAN_VID: u8 = 6;
/// OXM basic field 7: outermost 802.1Q priority code point. Requires a VLAN id other than
/// `OFPVID_NONE`.
pub const OFPXMT_OFB_VLAN_PCP: u8 = 7;
/// OXM basic field 8: the six DSCP bits of the IPv4 type-of-service or IPv6 traffic-class byte.
/// Requires an IP ethertype.
pub const OFPXMT_OFB_IP_DSCP: u8 = 8;
/// OXM basic field 9: the two ECN bits of the IPv4 type-of-service or IPv6 traffic-class byte.
/// Requires an IP ethertype.
pub const OFPXMT_OFB_IP_ECN: u8 = 9;
/// OXM basic field 10: the IPv4 protocol or IPv6 next-header byte; prerequisite for the TCP, UDP,
/// SCTP and ICMP fields.
pub const OFPXMT_OFB_IP_PROTO: u8 = 10;
/// OXM basic field 11: IPv4 source address. Requires ethertype 0x0800. Maskable.
pub const OFPXMT_OFB_IPV4_SRC: u8 = 11;
/// OXM basic field 12: IPv4 destination address. Requires ethertype 0x0800. Maskable.
pub const OFPXMT_OFB_IPV4_DST: u8 = 12;
/// OXM basic field 13: TCP source port. Requires an IP ethertype and `OXM_OF_IP_PROTO` 6. Not
/// maskable.
pub const OFPXMT_OFB_TCP_SRC: u8 = 13;
/// OXM basic field 14: TCP destination port. Requires an IP ethertype and `OXM_OF_IP_PROTO` 6. Not
/// maskable.
pub const OFPXMT_OFB_TCP_DST: u8 = 14;
/// OXM basic field 15: UDP source port. Requires an IP ethertype and `OXM_OF_IP_PROTO` 17. Not
/// maskable.
pub const OFPXMT_OFB_UDP_SRC: u8 = 15;
/// OXM basic field 16: UDP destination port. Requires an IP ethertype and `OXM_OF_IP_PROTO` 17. Not
/// maskable.
pub const OFPXMT_OFB_UDP_DST: u8 = 16;
/// OXM basic field 17: SCTP source port. Requires an IP ethertype and `OXM_OF_IP_PROTO` 132.
pub const OFPXMT_OFB_SCTP_SRC: u8 = 17;
/// OXM basic field 18: SCTP destination port. Requires an IP ethertype and `OXM_OF_IP_PROTO` 132.
pub const OFPXMT_OFB_SCTP_DST: u8 = 18;
/// OXM basic field 19: ICMP type byte. Requires ethertype 0x0800 and `OXM_OF_IP_PROTO` 1.
pub const OFPXMT_OFB_ICMPV4_TYPE: u8 = 19;
/// OXM basic field 20: ICMP code byte. Requires ethertype 0x0800 and `OXM_OF_IP_PROTO` 1.
pub const OFPXMT_OFB_ICMPV4_CODE: u8 = 20;
/// OXM basic field 21: ARP opcode. Requires ethertype 0x0806. Not maskable.
pub const OFPXMT_OFB_ARP_OP: u8 = 21;
/// OXM basic field 22: ARP sender protocol (IPv4) address. Requires ethertype 0x0806. Maskable.
pub const OFPXMT_OFB_ARP_SPA: u8 = 22;
/// OXM basic field 23: ARP target protocol (IPv4) address. Requires ethertype 0x0806. Maskable.
pub const OFPXMT_OFB_ARP_TPA: u8 = 23;
/// OXM basic field 24: ARP sender hardware address. Requires ethertype 0x0806. Not maskable.
pub const OFPXMT_OFB_ARP_SHA: u8 = 24;
/// OXM basic field 25: ARP target hardware address. Requires ethertype 0x0806. Not maskable.
pub const OFPXMT_OFB_ARP_THA: u8 = 25;
/// OXM basic field 26: IPv6 source address. Requires ethertype 0x86dd. Maskable.
pub const OFPXMT_OFB_IPV6_SRC: u8 = 26;
/// OXM basic field 27: IPv6 destination address. Requires ethertype 0x86dd. Maskable.
pub const OFPXMT_OFB_IPV6_DST: u8 = 27;
/// OXM basic field 28: 20-bit IPv6 flow label. Requires ethertype 0x86dd. Maskable.
pub const OFPXMT_OFB_IPV6_FLABEL: u8 = 28;
/// OXM basic field 29: `ICMPv6` type byte. Requires ethertype 0x86dd and `OXM_OF_IP_PROTO` 58.
pub const OFPXMT_OFB_ICMPV6_TYPE: u8 = 29;
/// OXM basic field 30: `ICMPv6` code byte. Requires ethertype 0x86dd and `OXM_OF_IP_PROTO` 58.
pub const OFPXMT_OFB_ICMPV6_CODE: u8 = 30;
/// OXM basic field 31: target address of an IPv6 neighbour discovery message. Requires `ICMPv6` type
/// 135 or 136.
pub const OFPXMT_OFB_IPV6_ND_TARGET: u8 = 31;
/// OXM basic field 32: source link-layer address option of an IPv6 neighbour solicitation (`ICMPv6`
/// type 135).
pub const OFPXMT_OFB_IPV6_ND_SLL: u8 = 32;
/// OXM basic field 33: target link-layer address option of an IPv6 neighbour advertisement (`ICMPv6`
/// type 136).
pub const OFPXMT_OFB_IPV6_ND_TLL: u8 = 33;
/// OXM basic field 34: 20-bit label of the outermost MPLS shim header. Requires ethertype 0x8847 or
/// 0x8848.
pub const OFPXMT_OFB_MPLS_LABEL: u8 = 34;
/// OXM basic field 35: three-bit traffic-class field of the outermost MPLS shim header.
pub const OFPXMT_OFB_MPLS_TC: u8 = 35;
/// OXM basic field 36: bottom-of-stack bit of the outermost MPLS shim header.
pub const OFPXMT_OFB_MPLS_BOS: u8 = 36;
/// OXM basic field 37: 24-bit 802.1ah I-SID of the outermost PBB service tag. Requires ethertype
/// 0x88e7. Maskable.
pub const OFPXMT_OFB_PBB_ISID: u8 = 37;
/// OXM basic field 38: logical-port metadata, such as a GRE key or VXLAN VNI; zero for
/// non-tunnelled packets. Maskable.
pub const OFPXMT_OFB_TUNNEL_ID: u8 = 38;
/// OXM basic field 39: IPv6 extension-header pseudo-field, a bitmap of `OFPIEH_*` flags. Maskable.
pub const OFPXMT_OFB_IPV6_EXTHDR: u8 = 39;
/// OXM basic field 41: 802.1ah UCA (use customer address) bit of the outermost PBB service tag.
pub const OFPXMT_OFB_PBB_UCA: u8 = 41;
/// OXM basic field 42: the TCP header flags. Requires `OXM_OF_IP_PROTO` 6; bits 0 to 11 are
/// maskable.
pub const OFPXMT_OFB_TCP_FLAGS: u8 = 42;
/// OXM basic field 43: output port currently recorded in the action set, or `OFPP_UNSET` if none.
/// Not maskable.
pub const OFPXMT_OFB_ACTSET_OUTPUT: u8 = 43;
/// OXM basic field 44: canonical type of the outermost header, a namespace and ns-type pair (see
/// `OFPHTN_ONF`).
///
/// Must appear as the **first** OXM TLV in a match. Its value is a
/// (namespace, `ns_type`) pair -- `(1, 0x0800)` for bare IPv4, `(0, 0)` for
/// Ethernet -- and in 1.5 it is an alternative to `OXM_OF_ETH_TYPE` for
/// satisfying the IP-family prerequisites on a non-Ethernet pipeline.
pub const OFPXMT_OFB_PACKET_TYPE: u8 = 44;

/// `ofp_instruction_type` 1: continue processing in the given later table
/// (`ofp_instruction_goto_table`).
///
/// The target table id must be strictly greater than the current one:
/// the pipeline only moves forward, so a backwards jump is rejected with
/// `OFPBIC_BAD_TABLE_ID`.
pub const OFPIT_GOTO_TABLE: u16 = 1;
/// `ofp_instruction_type` 2: write masked bits into the packet's metadata for use by later tables.
pub const OFPIT_WRITE_METADATA: u16 = 2;
/// `ofp_instruction_type` 3: merge the given actions into the packet's action set, applied at the
/// end of the pipeline.
pub const OFPIT_WRITE_ACTIONS: u16 = 3;
/// `ofp_instruction_type` 4: execute the given action list immediately, in order, before any
/// further instruction.
///
/// Runs its action list immediately, in order, before the packet moves on
/// -- unlike [`OFPIT_WRITE_ACTIONS`], which merges into the action set for
/// execution at the end of the pipeline. Use `APPLY` when one action must
/// observe the effect of a previous one.
pub const OFPIT_APPLY_ACTIONS: u16 = 4;
/// `ofp_instruction_type` 5: empty the packet's action set; carries no actions of its own.
pub const OFPIT_CLEAR_ACTIONS: u16 = 5;
/// `ofp_instruction_type` 6: reserved, deprecated (was `apply meter`). Never legitimately sent;
/// a peer using it decodes losslessly as [`crate::protocol::instruction::Instruction::Unknown`].
pub const OFPIT_DEPRECATED: u16 = 6;
/// `ofp_instruction_type` 7: emit flow statistics when a threshold in
/// `ofp_instruction_stat_trigger` is crossed.
pub const OFPIT_STAT_TRIGGER: u16 = 7;
/// `ofp_instruction_type` 0xffff: experimenter instruction; the body follows a 32-bit experimenter
/// id.
pub const OFPIT_EXPERIMENTER: u16 = 0xffff;

/// `ofp_action_type` 0: send the packet out a port (`ofp_action_output`), with `max_len` when the
/// port is `OFPP_CONTROLLER`.
///
/// `ofp_action_output` is 16 bytes: a `u32` port plus a `u16` `max_len`
/// that only matters when the port is `OFPP_CONTROLLER`.
pub const OFPAT_OUTPUT: u16 = 0;
/// `ofp_action_type` 11: copy the TTL outwards, from the next-to-outermost header to the outermost
/// one.
pub const OFPAT_COPY_TTL_OUT: u16 = 11;
/// `ofp_action_type` 12: copy the TTL inwards, from the outermost header to the next-to-outermost
/// one.
pub const OFPAT_COPY_TTL_IN: u16 = 12;
/// `ofp_action_type` 15: set the TTL of the outermost MPLS shim header (`ofp_action_mpls_ttl`).
pub const OFPAT_SET_MPLS_TTL: u16 = 15;
/// `ofp_action_type` 16: decrement the outermost MPLS TTL; an invalid TTL yields
/// `OFPR_INVALID_TTL`.
pub const OFPAT_DEC_MPLS_TTL: u16 = 16;
/// `ofp_action_type` 17: push a new VLAN tag with the ethertype in `ofp_action_push`.
pub const OFPAT_PUSH_VLAN: u16 = 17;
/// `ofp_action_type` 18: pop the outermost VLAN tag; takes no argument.
pub const OFPAT_POP_VLAN: u16 = 18;
/// `ofp_action_type` 19: push a new MPLS shim header with the ethertype in `ofp_action_push`.
pub const OFPAT_PUSH_MPLS: u16 = 19;
/// `ofp_action_type` 20: pop the outermost MPLS shim header, revealing the ethertype in
/// `ofp_action_pop_mpls`.
pub const OFPAT_POP_MPLS: u16 = 20;
/// `ofp_action_type` 21: choose the queue used by later output actions (`ofp_action_set_queue`).
pub const OFPAT_SET_QUEUE: u16 = 21;
/// `ofp_action_type` 22: process the packet through the given group (`ofp_action_group`).
pub const OFPAT_GROUP: u16 = 22;
/// `ofp_action_type` 23: set the IPv4 TTL or IPv6 hop limit (`ofp_action_nw_ttl`).
pub const OFPAT_SET_NW_TTL: u16 = 23;
/// `ofp_action_type` 24: decrement the IPv4 TTL or IPv6 hop limit; an invalid TTL yields
/// `OFPR_INVALID_TTL`.
pub const OFPAT_DEC_NW_TTL: u16 = 24;
/// `ofp_action_type` 25: overwrite one header field, given as a single OXM TLV in
/// `ofp_action_set_field`.
///
/// Carries one OXM TLV naming the field and its new value, padded to a
/// multiple of 8. The field must be writable and its prerequisites must
/// already hold, or the switch answers `OFPBAC_BAD_SET_TYPE` /
/// `OFPBAC_BAD_SET_ARGUMENT`.
///
/// ```
/// use openflow::protocol::action::Action;
/// use openflow::protocol::oxm;
///
/// let rewrite = Action::SetField(oxm::eth_dst([0, 1, 2, 3, 4, 5]));
/// let mut out = Vec::new();
/// rewrite.encode(&mut out).unwrap();
/// assert!(out.len().is_multiple_of(8)); // actions are 8-byte aligned
/// ```
pub const OFPAT_SET_FIELD: u16 = 25;
/// `ofp_action_type` 26: push a new PBB service tag (I-TAG) with the ethertype in
/// `ofp_action_push`.
pub const OFPAT_PUSH_PBB: u16 = 26;
/// `ofp_action_type` 27: pop the outermost PBB service tag (I-TAG); takes no argument.
pub const OFPAT_POP_PBB: u16 = 27;
/// `ofp_action_type` 28: copy a bit range between two fields named by OXM ids
/// (`ofp_action_copy_field`).
pub const OFPAT_COPY_FIELD: u16 = 28;
/// `ofp_action_type` 29: pass the packet through a meter, which may drop or remark it
/// (`ofp_action_meter`).
pub const OFPAT_METER: u16 = 29;
/// `ofp_action_type` 0xffff: experimenter action; the body follows the 32-bit experimenter id, as
/// with the `NXAST_*` actions.
pub const OFPAT_EXPERIMENTER: u16 = 0xffff;

/// `ofp_flow_mod.command` 0: install a new flow entry, replacing any entry with the same match and
/// priority.
pub const OFPFC_ADD: u8 = 0;
/// `ofp_flow_mod.command` 1: change the instructions of every entry matching the match and cookie,
/// ignoring priority.
pub const OFPFC_MODIFY: u8 = 1;
/// `ofp_flow_mod.command` 2: change only the entry whose match and priority are exactly equal.
pub const OFPFC_MODIFY_STRICT: u8 = 2;
/// `ofp_flow_mod.command` 3: delete every entry overlapping the match, subject to `out_port` and
/// `out_group`.
pub const OFPFC_DELETE: u8 = 3;
/// `ofp_flow_mod.command` 4: delete only the entry whose match and priority are exactly equal.
pub const OFPFC_DELETE_STRICT: u8 = 4;

/// Value for `ofp_flow_mod.idle_timeout` and `hard_timeout` meaning the entry never expires on its
/// own.
pub const OFP_FLOW_PERMANENT: u16 = 0;
/// Mid-range default for `ofp_flow_mod.priority`, leaving room for both higher and lower priority
/// entries.
pub const OFP_DEFAULT_PRIORITY: u16 = 0x8000;
/// Default `ofp_switch_config.miss_send_len`: bytes of a missed packet sent to the controller.
pub const OFP_DEFAULT_MISS_SEND_LEN: u16 = 128;

/// IPv4 ethertype, the `OXM_OF_ETH_TYPE` value required before matching any IPv4 field.
pub const ETH_TYPE_IPV4: u16 = 0x0800;
/// IPv6 ethertype, the `OXM_OF_ETH_TYPE` value required before matching any IPv6 field.
pub const ETH_TYPE_IPV6: u16 = 0x86dd;
/// ARP ethertype, the `OXM_OF_ETH_TYPE` value required before matching any `OFPXMT_OFB_ARP_*`
/// field.
pub const ETH_TYPE_ARP: u16 = 0x0806;
/// MPLS unicast ethertype.
pub const ETH_TYPE_MPLS_UNICAST: u16 = 0x8847;
/// MPLS multicast ethertype.
pub const ETH_TYPE_MPLS_MULTICAST: u16 = 0x8848;
/// IEEE 802.1ah PBB I-TAG ethertype.
pub const ETH_TYPE_PBB: u16 = 0x88e7;
/// IEEE 802.1Q VLAN ethertype.
pub const ETH_TYPE_VLAN: u16 = 0x8100;
/// IEEE 802.1ad QinQ/provider VLAN ethertype.
pub const ETH_TYPE_QINQ: u16 = 0x88a8;

/// `ofp_table`: wildcard table id for `ofp_flow_mod` deletes, `ofp_table_mod` and flow stats
/// requests.
///
/// Legal as the target of a delete or a stats request only. An
/// `OFPFC_ADD` aimed at `OFPTT_ALL` is rejected with
/// `OFPFMFC_BAD_TABLE_ID`, since a flow has to land in one real table.
pub const OFPTT_ALL: u8 = 0xff;
/// `ofp_group`: highest assignable group id; anything above is a reserved group.
pub const OFPG_MAX: u32 = 0xffff_ff00;
/// `ofp_group`: wildcard matching all groups, valid in an `ofp_group_mod` delete command.
///
/// Easily confused with [`OFPG_ANY`] (`0xffffffff`), which means "no group
/// specified". `OFPG_ALL` means "every group" and is valid in an
/// `OFPGC_DELETE` and in `OFPMP_GROUP_STATS` requests.
pub const OFPG_ALL: u32 = 0xffff_fffc;
/// `ofp_group`: wildcard meaning no group specified, used in `ofp_flow_mod.out_group` and group
/// stats requests.
pub const OFPG_ANY: u32 = 0xffff_ffff;

/// `ofp_meter_mod.command` 0: create a new meter with the given id, flags and bands.
pub const OFPMC_ADD: u16 = 0;
/// `ofp_meter_mod.command` 1: replace the configuration of an existing meter.
pub const OFPMC_MODIFY: u16 = 1;
/// `ofp_meter_mod.command` 2: delete the given meter, or all of them when the id is `OFPM_ALL`.
pub const OFPMC_DELETE: u16 = 2;

/// `ofp_group_mod.command` 0: create a new group; fails with `OFPGMFC_GROUP_EXISTS` if the id is
/// taken.
pub const OFPGC_ADD: u16 = 0;
/// `ofp_group_mod.command` 1: replace the type and buckets of an existing group.
pub const OFPGC_MODIFY: u16 = 1;
/// `ofp_group_mod.command` 2: delete the given group, or all of them when the id is `OFPG_ALL`.
pub const OFPGC_DELETE: u16 = 2;
/// `ofp_group_mod.command` 3: insert buckets into an existing group at `command_bucket_id`.
pub const OFPGC_INSERT_BUCKET: u16 = 3;
/// `ofp_group_mod.command` 5: remove one bucket, or all of them when `command_bucket_id` is
/// `OFPG_BUCKET_ALL`.
pub const OFPGC_REMOVE_BUCKET: u16 = 5;

/// `ofp_group_mod.type` 0: execute every bucket on a clone of the packet; used for multicast and
/// broadcast.
pub const OFPGT_ALL: u8 = 0;
/// `ofp_group_mod.type` 1: execute one bucket chosen by the switch, weighted by `OFPGBPT_WEIGHT`.
pub const OFPGT_SELECT: u8 = 1;
/// `ofp_group_mod.type` 2: exactly one bucket, an indirection point shared by many flow entries.
pub const OFPGT_INDIRECT: u8 = 2;
/// `ofp_group_mod.type` 3: fast failover, executing the first bucket whose watch port or group is
/// live.
pub const OFPGT_FF: u8 = 3;

/// `ofp_role_request.role` 0: query the current role without changing it.
///
/// Queries the current role without changing it -- the reply carries the
/// role the connection already has, so `generation_id` is ignored.
pub const OFPCR_ROLE_NOCHANGE: u32 = 0;
/// `ofp_role_request.role` 1: default role with full access, held by any number of controllers at
/// once.
pub const OFPCR_ROLE_EQUAL: u32 = 1;
/// `ofp_role_request.role` 2: full access, at most one per switch; promoting one master demotes the
/// previous one.
pub const OFPCR_ROLE_MASTER: u32 = 2;
/// `ofp_role_request.role` 3: read-only access; controller commands are refused with
/// `OFPBRC_IS_SLAVE`.
///
/// Read-only: a slave controller may issue stats and description
/// requests, but any flow, group, meter or port modification is refused
/// with `OFPBRC_IS_SLAVE`.
pub const OFPCR_ROLE_SLAVE: u32 = 3;

/// `ofp_multipart_request.flags` bit 0: more request parts follow this message.
pub const OFPMPF_REQ_MORE: u16 = 1 << 0;
/// `ofp_multipart_reply.flags` bit 0: more reply parts follow this message.
///
/// Set on every frame of a multi-frame reply except the last. All frames
/// of one sequence share an xid, and their bodies concatenate into a
/// single logical body before decoding.
pub const OFPMPF_REPLY_MORE: u16 = 1 << 0;

/// `ofp_multipart_type` 0: switch description; empty request, `ofp_desc` reply.
pub const OFPMP_DESC: u16 = 0;
/// `ofp_multipart_type` 1: per-flow descriptions; `ofp_flow_stats_request` request, array of
/// `ofp_flow_desc`.
pub const OFPMP_FLOW_DESC: u16 = 1;
/// `ofp_multipart_type` 2: aggregate counters over matching flows; `ofp_aggregate_stats_reply`.
pub const OFPMP_AGGREGATE_STATS: u16 = 2;
/// `ofp_multipart_type` 3: per-table counters; empty request, array of `ofp_table_stats`.
pub const OFPMP_TABLE_STATS: u16 = 3;
/// `ofp_multipart_type` 4: per-port counters; `ofp_port_multipart_request`, array of
/// `ofp_port_stats`.
pub const OFPMP_PORT_STATS: u16 = 4;
/// `ofp_multipart_type` 5: per-queue counters; `ofp_queue_multipart_request`, array of
/// `ofp_queue_stats`.
pub const OFPMP_QUEUE_STATS: u16 = 5;
/// `ofp_multipart_type` 6: per-group counters; `ofp_group_multipart_request`, array of
/// `ofp_group_stats`.
pub const OFPMP_GROUP_STATS: u16 = 6;
/// `ofp_multipart_type` 7: group definitions and buckets; array of `ofp_group_desc`.
pub const OFPMP_GROUP_DESC: u16 = 7;
/// `ofp_multipart_type` 8: group capabilities; empty request, `ofp_group_features` reply.
pub const OFPMP_GROUP_FEATURES: u16 = 8;
/// `ofp_multipart_type` 9: per-meter counters; `ofp_meter_multipart_request`, array of
/// `ofp_meter_stats`.
pub const OFPMP_METER_STATS: u16 = 9;
/// `ofp_multipart_type` 10: meter configuration; array of `ofp_meter_desc`.
pub const OFPMP_METER_DESC: u16 = 10;
/// `ofp_multipart_type` 11: meter capabilities; empty request, `ofp_meter_features` reply.
pub const OFPMP_METER_FEATURES: u16 = 11;
/// `ofp_multipart_type` 12: table capabilities, readable and, with a body, settable; array of
/// `ofp_table_features`.
///
/// The only multipart that is both a read and a write: an empty request
/// reads the table feature set, while a request carrying
/// `ofp_table_features` bodies replaces it. Replies routinely span several
/// frames flagged `OFPMPF_REPLY_MORE`.
pub const OFPMP_TABLE_FEATURES: u16 = 12;
/// `ofp_multipart_type` 13: port descriptions; `ofp_port_multipart_request`, array of `ofp_port`.
pub const OFPMP_PORT_DESC: u16 = 13;
/// `ofp_multipart_type` 14: current table configuration; empty request, array of `ofp_table_desc`.
pub const OFPMP_TABLE_DESC: u16 = 14;
/// `ofp_multipart_type` 15: queue definitions; `ofp_queue_multipart_request`, array of
/// `ofp_queue_desc`.
pub const OFPMP_QUEUE_DESC: u16 = 15;
/// `ofp_multipart_type` 16: flow monitors; array of `ofp_flow_monitor_request`, replies of
/// `ofp_flow_update_header`.
pub const OFPMP_FLOW_MONITOR: u16 = 16;
/// `ofp_multipart_type` 17: per-flow counters without the description; array of `ofp_flow_stats`.
pub const OFPMP_FLOW_STATS: u16 = 17;
/// `ofp_multipart_type` 18: controller connection status; array of `ofp_controller_status`.
pub const OFPMP_CONTROLLER_STATUS: u16 = 18;
/// `ofp_multipart_type` 19: bundle capabilities; `ofp_bundle_features_request`,
/// `ofp_bundle_features` reply.
pub const OFPMP_BUNDLE_FEATURES: u16 = 19;
/// `ofp_multipart_type` 0xffff: experimenter multipart; bodies start with
/// `ofp_experimenter_multipart_header`.
pub const OFPMP_EXPERIMENTER: u16 = 0xffff;

/// `ofp_bundle_ctrl_msg.flags` bit 0: commit the bundle atomically, with no packet seeing a partial
/// pipeline.
pub const OFPBF_ATOMIC: u16 = 1 << 0;
/// `ofp_bundle_ctrl_msg.flags` bit 1: apply the bundled messages in the order they were added.
pub const OFPBF_ORDERED: u16 = 1 << 1;
/// `ofp_bundle_ctrl_msg.flags` bit 2: commit at the time given by the bundle's `OFPBPT_TIME`
/// property.
pub const OFPBF_TIME: u16 = 1 << 2;

/// `ofp_error_type` 17: a bundle operation failed; the code is an `ofp_bundle_failed_code`.
pub const OFPET_BUNDLE_FAILED: u16 = 17;

/// `ofp_bundle_failed_code` 2: the referenced bundle id does not exist.
pub const OFPBFC_BAD_ID: u16 = 2;
/// `ofp_bundle_failed_code` 4: the bundle is closed and cannot take more messages.
pub const OFPBFC_BUNDLE_CLOSED: u16 = 4;

/// `ofp_bundle_ctrl_msg.type` 0: open a new bundle with the given bundle id.
pub const OFPBCT_OPEN_REQUEST: u16 = 0;
/// `ofp_bundle_ctrl_msg.type` 1: switch acknowledgement that the bundle is open.
pub const OFPBCT_OPEN_REPLY: u16 = 1;
/// `ofp_bundle_ctrl_msg.type` 2: close the bundle to further `OFPT_BUNDLE_ADD_MESSAGE` messages.
pub const OFPBCT_CLOSE_REQUEST: u16 = 2;
/// `ofp_bundle_ctrl_msg.type` 3: switch acknowledgement that the bundle is closed.
pub const OFPBCT_CLOSE_REPLY: u16 = 3;
/// `ofp_bundle_ctrl_msg.type` 4: apply every message in the bundle, subject to the bundle flags.
///
/// Applies every staged message atomically. Note that each staged message
/// must have carried the same xid as its enclosing
/// `OFPT_BUNDLE_ADD_MESSAGE`, or it was already refused with
/// `OFPBFC_MSG_BAD_XID` at add time.
pub const OFPBCT_COMMIT_REQUEST: u16 = 4;
/// `ofp_bundle_ctrl_msg.type` 5: switch acknowledgement that the bundle was applied.
pub const OFPBCT_COMMIT_REPLY: u16 = 5;
/// `ofp_bundle_ctrl_msg.type` 6: drop the bundle and everything staged in it.
pub const OFPBCT_DISCARD_REQUEST: u16 = 6;
/// `ofp_bundle_ctrl_msg.type` 7: switch acknowledgement that the bundle was discarded.
pub const OFPBCT_DISCARD_REPLY: u16 = 7;

/// `ofp_flow_removed.reason` 0: the entry went unmatched for its `idle_timeout`.
pub const OFPRR_IDLE_TIMEOUT: u8 = 0;
/// `ofp_flow_removed.reason` 1: the entry reached its `hard_timeout` since installation.
pub const OFPRR_HARD_TIMEOUT: u8 = 1;
/// `ofp_flow_removed.reason` 2: the entry was removed by an `OFPFC_DELETE` flow mod.
pub const OFPRR_DELETE: u8 = 2;
/// `ofp_flow_removed.reason` 3: the entry went away with the group it referenced.
pub const OFPRR_GROUP_DELETE: u8 = 3;
/// `ofp_flow_removed.reason` 4: the entry went away with the meter it referenced.
pub const OFPRR_METER_DELETE: u8 = 4;
/// `ofp_flow_removed.reason` 5: the switch evicted the entry to free table space (see
/// `OFPTC_EVICTION`).
pub const OFPRR_EVICTION: u8 = 5;

/// `ofp_port_status.reason` 0: a port was added to the datapath.
pub const OFPPR_ADD: u8 = 0;
/// `ofp_port_status.reason` 1: a port was removed from the datapath.
pub const OFPPR_DELETE: u8 = 1;
/// `ofp_port_status.reason` 2: some attribute of an existing port changed, such as its config or
/// link state.
pub const OFPPR_MODIFY: u8 = 2;

/// `ofp_role_status.reason` 0: another controller claimed `OFPCR_ROLE_MASTER`, demoting this one.
pub const OFPCRR_MASTER_REQUEST: u8 = 0;
/// `ofp_role_status.reason` 1: the switch's own configuration changed this connection's role.
pub const OFPCRR_CONFIG: u8 = 1;
/// `ofp_role_status.reason` 2: an experimenter-defined cause, described by the message's
/// properties.
pub const OFPCRR_EXPERIMENTER: u8 = 2;

/// `ofp_table_status.reason` 3: free space in the table fell past the `vacancy_down` threshold.
pub const OFPTR_VACANCY_DOWN: u8 = 3;
/// `ofp_table_status.reason` 4: free space in the table rose past the `vacancy_up` threshold.
pub const OFPTR_VACANCY_UP: u8 = 4;

/// `ofp_requestforward` reason 0: the forwarded message is another controller's `ofp_group_mod`.
pub const OFPRFR_GROUP_MOD: u8 = 0;
/// `ofp_requestforward` reason 1: the forwarded message is another controller's `ofp_meter_mod`.
pub const OFPRFR_METER_MOD: u8 = 1;

/// `ofp_controller_status.reason` 0: the status is a reply to an `OFPMP_CONTROLLER_STATUS` request.
pub const OFPCSR_REQUEST: u8 = 0;
/// `ofp_controller_status.reason` 1: the control channel's operational status changed.
pub const OFPCSR_CHANNEL_STATUS: u8 = 1;
/// `ofp_controller_status.reason` 2: the controller's role changed.
pub const OFPCSR_ROLE: u8 = 2;
/// `ofp_controller_status.reason` 3: a new controller was added to the switch's configuration.
pub const OFPCSR_CONTROLLER_ADDED: u8 = 3;
/// `ofp_controller_status.reason` 4: a controller was removed from the switch's configuration.
pub const OFPCSR_CONTROLLER_REMOVED: u8 = 4;
/// `ofp_controller_status.reason` 5: the controller's short id changed (see `OFPCID_UNDEFINED`).
pub const OFPCSR_SHORT_ID: u8 = 5;
/// `ofp_controller_status.reason` 6: experimenter-defined status data changed.
pub const OFPCSR_EXPERIMENTER: u8 = 6;

/// `ofp_controller_status.channel_status` 0: the control channel is operational.
pub const OFPCT_STATUS_UP: u8 = 0;
/// `ofp_controller_status.channel_status` 1: the control channel is not operational.
pub const OFPCT_STATUS_DOWN: u8 = 1;

/// `ofp_table_mod` property 0x2: eviction settings (`ofp_table_mod_prop_eviction`), also seen in
/// `OFPMP_TABLE_DESC`.
pub const OFPTMPT_EVICTION: u16 = 0x0002;
/// `ofp_table_mod` property 0x3: vacancy thresholds (`ofp_table_mod_prop_vacancy`) driving
/// `OFPT_TABLE_STATUS`.
pub const OFPTMPT_VACANCY: u16 = 0x0003;
/// `ofp_table_mod` property 0xffff: experimenter property carrying an experimenter id and type.
pub const OFPTMPT_EXPERIMENTER: u16 = 0xffff;

/// `ofp_port_mod` property 0: Ethernet property advertising a bitmap of `OFPPF_*` features.
pub const OFPPMPT_ETHERNET: u16 = 0;
/// `ofp_port_mod` property 1: optical property configuring frequency, grid and transmit power.
pub const OFPPMPT_OPTICAL: u16 = 1;
/// `ofp_port_mod` property 0xffff: experimenter property carrying an experimenter id and type.
pub const OFPPMPT_EXPERIMENTER: u16 = 0xffff;

/// `ofp_async_config` property 0: `ofp_packet_in` reason mask applied while the connection is a
/// slave.
pub const OFPACPT_PACKET_IN_SLAVE: u16 = 0;
/// `ofp_async_config` property 1: `ofp_packet_in` reason mask applied while the connection is
/// master or equal.
pub const OFPACPT_PACKET_IN_MASTER: u16 = 1;
/// `ofp_async_config` property 2: `ofp_port_status` reason mask for the slave role.
pub const OFPACPT_PORT_STATUS_SLAVE: u16 = 2;
/// `ofp_async_config` property 3: `ofp_port_status` reason mask for the master or equal role.
pub const OFPACPT_PORT_STATUS_MASTER: u16 = 3;
/// `ofp_async_config` property 4: `ofp_flow_removed` reason mask for the slave role.
pub const OFPACPT_FLOW_REMOVED_SLAVE: u16 = 4;
/// `ofp_async_config` property 5: `ofp_flow_removed` reason mask for the master or equal role.
///
/// Governs the equal role as well as master. Its mask holds one bit per
/// `OFPRR_*` reason, so `0x3f` enables all six; a bit outside that range
/// draws `OFPET_ASYNC_CONFIG_FAILED`.
pub const OFPACPT_FLOW_REMOVED_MASTER: u16 = 5;
/// `ofp_async_config` property 6: `ofp_role_status` reason mask for the slave role.
pub const OFPACPT_ROLE_STATUS_SLAVE: u16 = 6;
/// `ofp_async_config` property 7: `ofp_role_status` reason mask for the master or equal role.
pub const OFPACPT_ROLE_STATUS_MASTER: u16 = 7;
/// `ofp_async_config` property 8: `ofp_table_status` reason mask for the slave role.
pub const OFPACPT_TABLE_STATUS_SLAVE: u16 = 8;
/// `ofp_async_config` property 9: `ofp_table_status` reason mask for the master or equal role.
pub const OFPACPT_TABLE_STATUS_MASTER: u16 = 9;
/// `ofp_async_config` property 10: `ofp_requestforward` reason mask for the slave role.
pub const OFPACPT_REQUESTFORWARD_SLAVE: u16 = 10;
/// `ofp_async_config` property 11: `ofp_requestforward` reason mask for the master or equal role.
pub const OFPACPT_REQUESTFORWARD_MASTER: u16 = 11;
/// `ofp_async_config` property 12: flow-stats trigger mask for the slave role.
pub const OFPACPT_FLOW_STATS_SLAVE: u16 = 12;
/// `ofp_async_config` property 13: flow-stats trigger mask for the master or equal role.
pub const OFPACPT_FLOW_STATS_MASTER: u16 = 13;
/// `ofp_async_config` property 14: `ofp_controller_status` reason mask for the slave role.
pub const OFPACPT_CONT_STATUS_SLAVE: u16 = 14;
/// `ofp_async_config` property 15: `ofp_controller_status` reason mask for the master or equal
/// role.
pub const OFPACPT_CONT_STATUS_MASTER: u16 = 15;
/// `ofp_async_config` property 0xfffe: experimenter async filter for the slave role.
pub const OFPACPT_EXPERIMENTER_SLAVE: u16 = 0xfffe;
/// `ofp_async_config` property 0xffff: experimenter async filter for the master or equal role.
pub const OFPACPT_EXPERIMENTER_MASTER: u16 = 0xffff;

/// `ofp_bucket` property 0: relative weight of this bucket; select groups only.
pub const OFPGBPT_WEIGHT: u16 = 0;
/// `ofp_bucket` property 1: port whose liveness gates this bucket; fast failover groups only.
pub const OFPGBPT_WATCH_PORT: u16 = 1;
/// `ofp_bucket` property 2: group whose liveness gates this bucket; fast failover groups only.
pub const OFPGBPT_WATCH_GROUP: u16 = 2;
/// `ofp_bucket` property 0xffff: experimenter bucket property carrying an experimenter id and type.
pub const OFPGBPT_EXPERIMENTER: u16 = 0xffff;

/// `ofp_group_mod` property 0xffff: the only group property type defined, carrying experimenter
/// data.
pub const OFPGPT_EXPERIMENTER: u16 = 0xffff;

/// `ofp_meter_band_header.type` 1: drop packets exceeding this band's rate (`ofp_meter_band_drop`).
pub const OFPMBT_DROP: u16 = 1;
/// `ofp_meter_band_header.type` 2: increase the IP drop precedence of packets exceeding the rate.
pub const OFPMBT_DSCP_REMARK: u16 = 2;
/// `ofp_meter_band_header.type` 0xffff: experimenter band, the body following an experimenter id.
pub const OFPMBT_EXPERIMENTER: u16 = 0xffff;

/// `ofp_oxs_class` 0x8002: the basic statistics class holding every `OFPXST_OFB_*` field.
pub const OFPXSC_OPENFLOW_BASIC: u16 = 0x8002;
/// `ofp_oxs_class` 0xffff: experimenter statistics class; the TLV body starts with an experimenter
/// id.
pub const OFPXSC_EXPERIMENTER: u16 = 0xffff;

/// OXS basic field 0: how long the flow entry has been alive, as seconds and nanoseconds.
pub const OFPXST_OFB_DURATION: u8 = 0;
/// OXS basic field 1: how long the flow entry has gone unmatched, as seconds and nanoseconds.
pub const OFPXST_OFB_IDLE_TIME: u8 = 1;
/// OXS basic field 3: number of aggregated flow entries; required in `OFPMP_AGGREGATE_STATS`
/// replies.
pub const OFPXST_OFB_FLOW_COUNT: u8 = 3;
/// OXS basic field 4: packets matched by the flow entry.
///
/// 1.5 moved the per-flow counters out of the fixed struct fields that
/// 1.3 used and into this OXS list, so `ofp_flow_removed`,
/// `ofp_flow_stats` and `ofp_flow_desc` all report packet and byte counts
/// here rather than inline.
pub const OFPXST_OFB_PACKET_COUNT: u8 = 4;
/// OXS basic field 5: bytes matched by the flow entry.
pub const OFPXST_OFB_BYTE_COUNT: u8 = 5;

/// `ofp_port` description property 0: Ethernet features and speeds (`ofp_port_desc_prop_ethernet`).
pub const OFPPDPT_ETHERNET: u16 = 0;
/// `ofp_port` description property 1: optical frequency, grid and power ranges
/// (`ofp_port_desc_prop_optical`).
pub const OFPPDPT_OPTICAL: u16 = 1;
/// `ofp_port` description property 2: OXM ids of the pipeline fields the port accepts on ingress.
pub const OFPPDPT_PIPELINE_INPUT: u16 = 2;
/// `ofp_port` description property 3: OXM ids of the pipeline fields the port accepts on egress.
pub const OFPPDPT_PIPELINE_OUTPUT: u16 = 3;
/// `ofp_port` description property 4: list of ingress port numbers this port recirculates packets
/// to.
pub const OFPPDPT_RECIRCULATE: u16 = 4;
/// `ofp_port` description property 0xffff: experimenter property carrying an experimenter id and
/// type.
pub const OFPPDPT_EXPERIMENTER: u16 = 0xffff;
/// `ofp_error_msg.type` 0: version negotiation failed; the code is an `ofp_hello_failed_code`.
pub const OFPET_HELLO_FAILED: u16 = 0;
/// `ofp_error_msg.type` 1: the request was not understood; the code is an `ofp_bad_request_code`.
///
/// The catch-all for a message the switch understood structurally but
/// would not act on -- unknown multipart subtype
/// (`OFPBRC_BAD_MULTIPART`), a slave attempting a write
/// (`OFPBRC_IS_SLAVE`), an unusable port (`OFPBRC_BAD_PORT`).
pub const OFPET_BAD_REQUEST: u16 = 1;
/// `ofp_error_msg.type` 2: an action was malformed or unsupported; the code is an
/// `ofp_bad_action_code`.
pub const OFPET_BAD_ACTION: u16 = 2;
/// `ofp_error_msg.type` 3: an instruction was malformed or unsupported; the code is an
/// `ofp_bad_instruction_code`.
pub const OFPET_BAD_INSTRUCTION: u16 = 3;
/// `ofp_error_msg.type` 4: the match was malformed or unsupported; the code is an
/// `ofp_bad_match_code`.
pub const OFPET_BAD_MATCH: u16 = 4;
/// `ofp_error_msg.type` 5: an `ofp_flow_mod` could not be applied; the code is an
/// `ofp_flow_mod_failed_code`.
pub const OFPET_FLOW_MOD_FAILED: u16 = 5;
/// `ofp_error_msg.type` 6: an `ofp_group_mod` could not be applied; the code is an
/// `ofp_group_mod_failed_code`.
pub const OFPET_GROUP_MOD_FAILED: u16 = 6;
/// `ofp_error_msg.type` 7: an `ofp_port_mod` could not be applied; the code is an
/// `ofp_port_mod_failed_code`.
pub const OFPET_PORT_MOD_FAILED: u16 = 7;
/// `ofp_error_msg.type` 8: an `ofp_table_mod` could not be applied; the code is an
/// `ofp_table_mod_failed_code`.
pub const OFPET_TABLE_MOD_FAILED: u16 = 8;
/// `ofp_error_msg.type` 9: a queue operation failed; the code is an `ofp_queue_op_failed_code`.
pub const OFPET_QUEUE_OP_FAILED: u16 = 9;
/// `ofp_error_msg.type` 10: an `OFPT_SET_CONFIG` was refused; the code is an
/// `ofp_switch_config_failed_code`.
pub const OFPET_SWITCH_CONFIG_FAILED: u16 = 10;
/// `ofp_error_msg.type` 11: an `ofp_role_request` was refused; the code is an
/// `ofp_role_request_failed_code`.
pub const OFPET_ROLE_REQUEST_FAILED: u16 = 11;
/// `ofp_error_msg.type` 12: an `ofp_meter_mod` could not be applied; the code is an
/// `ofp_meter_mod_failed_code`.
pub const OFPET_METER_MOD_FAILED: u16 = 12;
/// `ofp_error_msg.type` 13: an `OFPMP_TABLE_FEATURES` write failed; the code is an
/// `ofp_table_features_failed_code`.
pub const OFPET_TABLE_FEATURES_FAILED: u16 = 13;
/// `ofp_error_msg.type` 14: a TLV property was invalid; the code is an `ofp_bad_property_code`.
pub const OFPET_BAD_PROPERTY: u16 = 14;
/// `ofp_error_msg.type` 15: an `OFPT_SET_ASYNC` was refused; the code is an
/// `ofp_async_config_failed_code`.
pub const OFPET_ASYNC_CONFIG_FAILED: u16 = 15;
/// `ofp_error_msg.type` 16: a flow monitor request failed; the code is an
/// `ofp_flow_monitor_failed_code`.
pub const OFPET_FLOW_MONITOR_FAILED: u16 = 16;
/// `ofp_error_msg.type` 0xffff: experimenter error, sent as `ofp_error_experimenter_msg` with an
/// experimenter id.
pub const OFPET_EXPERIMENTER: u16 = 0xffff;
/// `OFPET_HELLO_FAILED` code 0: no version in common; `data` holds an explanatory ASCII string.
pub const OFPHFC_INCOMPATIBLE: u16 = 0;
/// `OFPET_HELLO_FAILED` code 1: permissions error during connection setup.
pub const OFPHFC_EPERM: u16 = 1;
/// `OFPET_BAD_REQUEST` code 0: `ofp_header.version` is not supported.
pub const OFPBRC_BAD_VERSION: u16 = 0;
/// `OFPET_BAD_REQUEST` code 1: `ofp_header.type` is not supported.
pub const OFPBRC_BAD_TYPE: u16 = 1;
/// `OFPET_BAD_REQUEST` code 2: `ofp_multipart_request.type` is not supported.
pub const OFPBRC_BAD_MULTIPART: u16 = 2;
/// `OFPET_BAD_REQUEST` code 3: the experimenter id in the message is not supported.
pub const OFPBRC_BAD_EXPERIMENTER: u16 = 3;
/// `OFPET_BAD_REQUEST` code 4: the experimenter subtype is not supported.
pub const OFPBRC_BAD_EXP_TYPE: u16 = 4;
/// `OFPET_BAD_REQUEST` code 5: permissions error.
pub const OFPBRC_EPERM: u16 = 5;
/// `OFPET_BAD_REQUEST` code 6: the message length does not fit the message type.
pub const OFPBRC_BAD_LEN: u16 = 6;
/// `OFPET_BAD_REQUEST` code 7: the referenced `buffer_id` has already been consumed.
pub const OFPBRC_BUFFER_EMPTY: u16 = 7;
/// `OFPET_BAD_REQUEST` code 8: the referenced `buffer_id` does not exist.
pub const OFPBRC_BUFFER_UNKNOWN: u16 = 8;
/// `OFPET_BAD_REQUEST` code 9: the table id is invalid or does not exist.
pub const OFPBRC_BAD_TABLE_ID: u16 = 9;
/// `OFPET_BAD_REQUEST` code 10: refused because this connection holds `OFPCR_ROLE_SLAVE`.
pub const OFPBRC_IS_SLAVE: u16 = 10;
/// `OFPET_BAD_REQUEST` code 11: the port number is invalid or missing.
pub const OFPBRC_BAD_PORT: u16 = 11;
/// `OFPET_BAD_REQUEST` code 12: the packet data in an `ofp_packet_out` is invalid.
pub const OFPBRC_BAD_PACKET: u16 = 12;
/// `OFPET_BAD_REQUEST` code 13: a multipart request overflowed the buffer assigned to it.
pub const OFPBRC_MULTIPART_BUFFER_OVERFLOW: u16 = 13;
/// `OFPET_BAD_REQUEST` code 14: the parts of a multipart request did not all arrive in time.
pub const OFPBRC_MULTIPART_REQUEST_TIMEOUT: u16 = 14;
/// `OFPET_BAD_REQUEST` code 15: the parts of a multipart reply were not all consumed in time.
pub const OFPBRC_MULTIPART_REPLY_TIMEOUT: u16 = 15;
/// `OFPET_BAD_REQUEST` code 16: an `OFPMP_BUNDLE_FEATURES` request failed to set the scheduling
/// tolerance.
pub const OFPBRC_MULTIPART_BAD_SCHED: u16 = 16;
/// `OFPET_BAD_REQUEST` code 17: the match may contain only pipeline fields here, as in
/// `ofp_packet_out`.
pub const OFPBRC_PIPELINE_FIELDS_ONLY: u16 = 17;
/// `OFPET_BAD_REQUEST` code 18: unspecified error.
pub const OFPBRC_UNKNOWN: u16 = 18;
/// `OFPET_BAD_ACTION` code 0: unknown or unsupported `ofp_action_type`.
pub const OFPBAC_BAD_TYPE: u16 = 0;
/// `OFPET_BAD_ACTION` code 1: an action length is wrong or the list does not fit.
pub const OFPBAC_BAD_LEN: u16 = 1;
/// `OFPET_BAD_ACTION` code 2: unknown experimenter id in an `OFPAT_EXPERIMENTER` action.
pub const OFPBAC_BAD_EXPERIMENTER: u16 = 2;
/// `OFPET_BAD_ACTION` code 3: unknown action subtype for that experimenter id.
pub const OFPBAC_BAD_EXP_TYPE: u16 = 3;
/// `OFPET_BAD_ACTION` code 4: the output port of an `OFPAT_OUTPUT` action is invalid.
pub const OFPBAC_BAD_OUT_PORT: u16 = 4;
/// `OFPET_BAD_ACTION` code 5: an action argument is out of range or otherwise invalid.
pub const OFPBAC_BAD_ARGUMENT: u16 = 5;
/// `OFPET_BAD_ACTION` code 6: permissions error.
pub const OFPBAC_EPERM: u16 = 6;
/// `OFPET_BAD_ACTION` code 7: more actions than the switch can handle.
pub const OFPBAC_TOO_MANY: u16 = 7;
/// `OFPET_BAD_ACTION` code 8: the queue in an `OFPAT_SET_QUEUE` action is invalid.
pub const OFPBAC_BAD_QUEUE: u16 = 8;
/// `OFPET_BAD_ACTION` code 9: the group id in an `OFPAT_GROUP` action is invalid.
pub const OFPBAC_BAD_OUT_GROUP: u16 = 9;
/// `OFPET_BAD_ACTION` code 10: the action cannot apply to this match, or a set-field prerequisite
/// is missing.
pub const OFPBAC_MATCH_INCONSISTENT: u16 = 10;
/// `OFPET_BAD_ACTION` code 11: this action order is unsupported inside an apply-actions
/// instruction.
pub const OFPBAC_UNSUPPORTED_ORDER: u16 = 11;
/// `OFPET_BAD_ACTION` code 12: the action uses an unsupported tag or encapsulation.
pub const OFPBAC_BAD_TAG: u16 = 12;
/// `OFPET_BAD_ACTION` code 13: unsupported field type in an `OFPAT_SET_FIELD` action.
pub const OFPBAC_BAD_SET_TYPE: u16 = 13;
/// `OFPET_BAD_ACTION` code 14: length problem in an `OFPAT_SET_FIELD` action.
pub const OFPBAC_BAD_SET_LEN: u16 = 14;
/// `OFPET_BAD_ACTION` code 15: bad value in an `OFPAT_SET_FIELD` action.
pub const OFPBAC_BAD_SET_ARGUMENT: u16 = 15;
/// `OFPET_BAD_ACTION` code 16: bad mask in an `OFPAT_SET_FIELD` action.
pub const OFPBAC_BAD_SET_MASK: u16 = 16;
/// `OFPET_BAD_ACTION` code 17: the meter id in an `OFPAT_METER` action is invalid.
pub const OFPBAC_BAD_METER: u16 = 17;
/// `OFPET_BAD_INSTRUCTION` code 0: unknown `ofp_instruction_type`.
pub const OFPBIC_UNKNOWN_INST: u16 = 0;
/// `OFPET_BAD_INSTRUCTION` code 1: the switch or that table does not support this instruction.
pub const OFPBIC_UNSUP_INST: u16 = 1;
/// `OFPET_BAD_INSTRUCTION` code 2: invalid table id in an `OFPIT_GOTO_TABLE` instruction.
pub const OFPBIC_BAD_TABLE_ID: u16 = 2;
/// `OFPET_BAD_INSTRUCTION` code 3: the metadata value is unsupported by the datapath.
pub const OFPBIC_UNSUP_METADATA: u16 = 3;
/// `OFPET_BAD_INSTRUCTION` code 4: the metadata mask is unsupported by the datapath.
pub const OFPBIC_UNSUP_METADATA_MASK: u16 = 4;
/// `OFPET_BAD_INSTRUCTION` code 5: unknown experimenter id in an `OFPIT_EXPERIMENTER` instruction.
pub const OFPBIC_BAD_EXPERIMENTER: u16 = 5;
/// `OFPET_BAD_INSTRUCTION` code 6: unknown instruction subtype for that experimenter id.
pub const OFPBIC_BAD_EXP_TYPE: u16 = 6;
/// `OFPET_BAD_INSTRUCTION` code 7: an instruction length is wrong or the list does not fit.
pub const OFPBIC_BAD_LEN: u16 = 7;
/// `OFPET_BAD_INSTRUCTION` code 8: permissions error.
pub const OFPBIC_EPERM: u16 = 8;
/// `OFPET_BAD_INSTRUCTION` code 9: the same instruction type appears twice.
pub const OFPBIC_DUP_INST: u16 = 9;
/// `OFPET_BAD_MATCH` code 0: unsupported `ofp_match.type`.
pub const OFPBMC_BAD_TYPE: u16 = 0;
/// `OFPET_BAD_MATCH` code 1: the match length is wrong or its TLVs do not fit.
pub const OFPBMC_BAD_LEN: u16 = 1;
/// `OFPET_BAD_MATCH` code 2: the match uses an unsupported tag or encapsulation.
pub const OFPBMC_BAD_TAG: u16 = 2;
/// `OFPET_BAD_MATCH` code 3: arbitrary masks on datalink addresses are unsupported.
pub const OFPBMC_BAD_DL_ADDR_MASK: u16 = 3;
/// `OFPET_BAD_MATCH` code 4: arbitrary masks on network addresses are unsupported.
pub const OFPBMC_BAD_NW_ADDR_MASK: u16 = 4;
/// `OFPET_BAD_MATCH` code 5: unsupported combination of masked or omitted fields.
pub const OFPBMC_BAD_WILDCARDS: u16 = 5;
/// `OFPET_BAD_MATCH` code 6: unsupported OXM field type in the match.
pub const OFPBMC_BAD_FIELD: u16 = 6;
/// `OFPET_BAD_MATCH` code 7: unsupported value in an OXM match field.
pub const OFPBMC_BAD_VALUE: u16 = 7;
/// `OFPET_BAD_MATCH` code 8: unsupported mask in an OXM match field.
pub const OFPBMC_BAD_MASK: u16 = 8;
/// `OFPET_BAD_MATCH` code 9: a field prerequisite was not met, such as matching a port without an
/// ethertype.
pub const OFPBMC_BAD_PREREQ: u16 = 9;
/// `OFPET_BAD_MATCH` code 10: the same OXM field appears twice in the match.
pub const OFPBMC_DUP_FIELD: u16 = 10;
/// `OFPET_BAD_MATCH` code 11: permissions error.
pub const OFPBMC_EPERM: u16 = 11;
/// `OFPET_FLOW_MOD_FAILED` code 0: unspecified error.
pub const OFPFMFC_UNKNOWN: u16 = 0;
/// `OFPET_FLOW_MOD_FAILED` code 1: the flow table is full.
pub const OFPFMFC_TABLE_FULL: u16 = 1;
/// `OFPET_FLOW_MOD_FAILED` code 2: the table does not exist.
pub const OFPFMFC_BAD_TABLE_ID: u16 = 2;
/// `OFPET_FLOW_MOD_FAILED` code 3: the entry overlaps an existing one and `OFPFF_CHECK_OVERLAP` was
/// set.
pub const OFPFMFC_OVERLAP: u16 = 3;
/// `OFPET_FLOW_MOD_FAILED` code 4: permissions error.
pub const OFPFMFC_EPERM: u16 = 4;
/// `OFPET_FLOW_MOD_FAILED` code 5: unsupported idle or hard timeout.
pub const OFPFMFC_BAD_TIMEOUT: u16 = 5;
/// `OFPET_FLOW_MOD_FAILED` code 6: unsupported or unknown `ofp_flow_mod.command`.
pub const OFPFMFC_BAD_COMMAND: u16 = 6;
/// `OFPET_FLOW_MOD_FAILED` code 7: unsupported or unknown `OFPFF_*` flags.
pub const OFPFMFC_BAD_FLAGS: u16 = 7;
/// `OFPET_FLOW_MOD_FAILED` code 8: table synchronisation problem.
pub const OFPFMFC_CANT_SYNC: u16 = 8;
/// `OFPET_FLOW_MOD_FAILED` code 9: unsupported priority value.
pub const OFPFMFC_BAD_PRIORITY: u16 = 9;
/// `OFPET_FLOW_MOD_FAILED` code 10: the entry belongs to a synchronised, read-only table.
pub const OFPFMFC_IS_SYNC: u16 = 10;
/// `OFPET_GROUP_MOD_FAILED` code 0: an `OFPGC_ADD` tried to replace an existing group.
pub const OFPGMFC_GROUP_EXISTS: u16 = 0;
/// `OFPET_GROUP_MOD_FAILED` code 1: the specified group id is invalid.
pub const OFPGMFC_INVALID_GROUP: u16 = 1;
/// `OFPET_GROUP_MOD_FAILED` code 2: unequal load sharing in select groups is unsupported.
pub const OFPGMFC_WEIGHT_UNSUPPORTED: u16 = 2;
/// `OFPET_GROUP_MOD_FAILED` code 3: the group table is full.
pub const OFPGMFC_OUT_OF_GROUPS: u16 = 3;
/// `OFPET_GROUP_MOD_FAILED` code 4: too many action buckets for one group.
pub const OFPGMFC_OUT_OF_BUCKETS: u16 = 4;
/// `OFPET_GROUP_MOD_FAILED` code 5: groups forwarding to other groups are unsupported.
pub const OFPGMFC_CHAINING_UNSUPPORTED: u16 = 5;
/// `OFPET_GROUP_MOD_FAILED` code 6: the given watch port or watch group cannot be watched.
pub const OFPGMFC_WATCH_UNSUPPORTED: u16 = 6;
/// `OFPET_GROUP_MOD_FAILED` code 7: the group would create a forwarding loop.
pub const OFPGMFC_LOOP: u16 = 7;
/// `OFPET_GROUP_MOD_FAILED` code 8: an `OFPGC_MODIFY` targeted a group that does not exist.
pub const OFPGMFC_UNKNOWN_GROUP: u16 = 8;
/// `OFPET_GROUP_MOD_FAILED` code 9: the group cannot be deleted while another group forwards to it.
pub const OFPGMFC_CHAINED_GROUP: u16 = 9;
/// `OFPET_GROUP_MOD_FAILED` code 10: unsupported or unknown `ofp_group_type`.
pub const OFPGMFC_BAD_TYPE: u16 = 10;
/// `OFPET_GROUP_MOD_FAILED` code 11: unsupported or unknown `ofp_group_mod.command`.
pub const OFPGMFC_BAD_COMMAND: u16 = 11;
/// `OFPET_GROUP_MOD_FAILED` code 12: error in one of the buckets.
pub const OFPGMFC_BAD_BUCKET: u16 = 12;
/// `OFPET_GROUP_MOD_FAILED` code 13: error in a bucket's watch port or watch group property.
pub const OFPGMFC_BAD_WATCH: u16 = 13;
/// `OFPET_GROUP_MOD_FAILED` code 14: permissions error.
pub const OFPGMFC_EPERM: u16 = 14;
/// `OFPET_GROUP_MOD_FAILED` code 15: invalid bucket id in an insert or remove bucket command.
pub const OFPGMFC_UNKNOWN_BUCKET: u16 = 15;
/// `OFPET_GROUP_MOD_FAILED` code 16: a bucket with that bucket id already exists.
pub const OFPGMFC_BUCKET_EXISTS: u16 = 16;
/// `OFPET_PORT_MOD_FAILED` code 0: the port number does not exist.
pub const OFPPMFC_BAD_PORT: u16 = 0;
/// `OFPET_PORT_MOD_FAILED` code 1: the hardware address does not match the port number.
pub const OFPPMFC_BAD_HW_ADDR: u16 = 1;
/// `OFPET_PORT_MOD_FAILED` code 2: the `OFPPC_*` configuration bits are invalid.
pub const OFPPMFC_BAD_CONFIG: u16 = 2;
/// `OFPET_PORT_MOD_FAILED` code 3: the advertised `OFPPF_*` features are invalid.
pub const OFPPMFC_BAD_ADVERTISE: u16 = 3;
/// `OFPET_PORT_MOD_FAILED` code 4: permissions error.
pub const OFPPMFC_EPERM: u16 = 4;
/// `OFPET_TABLE_MOD_FAILED` code 0: the table does not exist.
pub const OFPTMFC_BAD_TABLE: u16 = 0;
/// `OFPET_TABLE_MOD_FAILED` code 1: the `OFPTC_*` configuration bits are invalid.
pub const OFPTMFC_BAD_CONFIG: u16 = 1;
/// `OFPET_TABLE_MOD_FAILED` code 2: permissions error.
pub const OFPTMFC_EPERM: u16 = 2;
/// `OFPET_QUEUE_OP_FAILED` code 0: the port is invalid or does not exist.
pub const OFPQOFC_BAD_PORT: u16 = 0;
/// `OFPET_QUEUE_OP_FAILED` code 1: the queue does not exist on that port.
pub const OFPQOFC_BAD_QUEUE: u16 = 1;
/// `OFPET_QUEUE_OP_FAILED` code 2: permissions error.
pub const OFPQOFC_EPERM: u16 = 2;
/// `OFPET_SWITCH_CONFIG_FAILED` code 0: the `OFPC_FRAG_*` flags are invalid.
pub const OFPSCFC_BAD_FLAGS: u16 = 0;
/// `OFPET_SWITCH_CONFIG_FAILED` code 1: the `miss_send_len` value is invalid.
pub const OFPSCFC_BAD_LEN: u16 = 1;
/// `OFPET_SWITCH_CONFIG_FAILED` code 2: permissions error.
pub const OFPSCFC_EPERM: u16 = 2;
/// `OFPET_ROLE_REQUEST_FAILED` code 0: stale message, the generation id is older than the current
/// one.
pub const OFPRRFC_STALE: u16 = 0;
/// `OFPET_ROLE_REQUEST_FAILED` code 1: the switch does not support role changes.
pub const OFPRRFC_UNSUP: u16 = 1;
/// `OFPET_ROLE_REQUEST_FAILED` code 2: the requested `ofp_controller_role` is invalid.
pub const OFPRRFC_BAD_ROLE: u16 = 2;
/// `OFPET_ROLE_REQUEST_FAILED` code 3: the switch does not support changing the controller id.
pub const OFPRRFC_ID_UNSUP: u16 = 3;
/// `OFPET_ROLE_REQUEST_FAILED` code 4: the requested controller id is already in use.
pub const OFPRRFC_ID_IN_USE: u16 = 4;
/// `OFPET_METER_MOD_FAILED` code 0: unspecified error.
pub const OFPMMFC_UNKNOWN: u16 = 0;
/// `OFPET_METER_MOD_FAILED` code 1: an `OFPMC_ADD` tried to replace an existing meter.
pub const OFPMMFC_METER_EXISTS: u16 = 1;
/// `OFPET_METER_MOD_FAILED` code 2: the meter id is invalid, here or in an `OFPAT_METER` action.
pub const OFPMMFC_INVALID_METER: u16 = 2;
/// `OFPET_METER_MOD_FAILED` code 3: the referenced meter does not exist.
pub const OFPMMFC_UNKNOWN_METER: u16 = 3;
/// `OFPET_METER_MOD_FAILED` code 4: unsupported or unknown `ofp_meter_mod.command`.
pub const OFPMMFC_BAD_COMMAND: u16 = 4;
/// `OFPET_METER_MOD_FAILED` code 5: unsupported combination of `OFPMF_*` flags.
pub const OFPMMFC_BAD_FLAGS: u16 = 5;
/// `OFPET_METER_MOD_FAILED` code 6: unsupported band rate.
pub const OFPMMFC_BAD_RATE: u16 = 6;
/// `OFPET_METER_MOD_FAILED` code 7: unsupported burst size.
pub const OFPMMFC_BAD_BURST: u16 = 7;
/// `OFPET_METER_MOD_FAILED` code 8: unsupported band type.
pub const OFPMMFC_BAD_BAND: u16 = 8;
/// `OFPET_METER_MOD_FAILED` code 9: unsupported value inside a band.
pub const OFPMMFC_BAD_BAND_VALUE: u16 = 9;
/// `OFPET_METER_MOD_FAILED` code 10: no more meters available.
pub const OFPMMFC_OUT_OF_METERS: u16 = 10;
/// `OFPET_METER_MOD_FAILED` code 11: too many bands for one meter.
pub const OFPMMFC_OUT_OF_BANDS: u16 = 11;
/// `OFPET_TABLE_FEATURES_FAILED` code 0: the table does not exist.
pub const OFPTFFC_BAD_TABLE: u16 = 0;
/// `OFPET_TABLE_FEATURES_FAILED` code 1: invalid metadata match or write mask.
pub const OFPTFFC_BAD_METADATA: u16 = 1;
/// `OFPET_TABLE_FEATURES_FAILED` code 5: permissions error.
pub const OFPTFFC_EPERM: u16 = 5;
/// `OFPET_TABLE_FEATURES_FAILED` code 6: invalid `capabilities` field.
pub const OFPTFFC_BAD_CAPA: u16 = 6;
/// `OFPET_TABLE_FEATURES_FAILED` code 7: invalid `max_entries` field.
pub const OFPTFFC_BAD_MAX_ENT: u16 = 7;
/// `OFPET_TABLE_FEATURES_FAILED` code 8: invalid `features` field (`OFPTFF_*` bits).
pub const OFPTFFC_BAD_FEATURES: u16 = 8;
/// `OFPET_TABLE_FEATURES_FAILED` code 9: invalid `ofp_table_features_command`.
pub const OFPTFFC_BAD_COMMAND: u16 = 9;
/// `OFPET_TABLE_FEATURES_FAILED` code 10: more flow tables than the switch can handle.
pub const OFPTFFC_TOO_MANY: u16 = 10;
/// `OFPET_BAD_PROPERTY` code 0: unknown or unsupported property type.
pub const OFPBPC_BAD_TYPE: u16 = 0;
/// `OFPET_BAD_PROPERTY` code 1: the property length is wrong.
pub const OFPBPC_BAD_LEN: u16 = 1;
/// `OFPET_BAD_PROPERTY` code 2: unsupported value inside the property.
pub const OFPBPC_BAD_VALUE: u16 = 2;
/// `OFPET_BAD_PROPERTY` code 3: more properties than the switch can handle.
pub const OFPBPC_TOO_MANY: u16 = 3;
/// `OFPET_BAD_PROPERTY` code 4: the same property type appears twice.
pub const OFPBPC_DUP_TYPE: u16 = 4;
/// `OFPET_BAD_PROPERTY` code 5: unknown experimenter id in an experimenter property.
pub const OFPBPC_BAD_EXPERIMENTER: u16 = 5;
/// `OFPET_BAD_PROPERTY` code 6: unknown `exp_type` for that experimenter id.
pub const OFPBPC_BAD_EXP_TYPE: u16 = 6;
/// `OFPET_BAD_PROPERTY` code 7: unknown value for that experimenter property.
pub const OFPBPC_BAD_EXP_VALUE: u16 = 7;
/// `OFPET_BAD_PROPERTY` code 8: permissions error.
pub const OFPBPC_EPERM: u16 = 8;
/// `OFPET_ASYNC_CONFIG_FAILED` code 0: one of the `OFPACPT_*` masks is invalid.
pub const OFPACFC_INVALID: u16 = 0;
/// `OFPET_ASYNC_CONFIG_FAILED` code 1: the requested async configuration is unsupported.
pub const OFPACFC_UNSUPPORTED: u16 = 1;
/// `OFPET_ASYNC_CONFIG_FAILED` code 2: permissions error.
pub const OFPACFC_EPERM: u16 = 2;
/// `OFPET_FLOW_MONITOR_FAILED` code 0: unspecified error.
pub const OFPMOFC_UNKNOWN: u16 = 0;
/// `OFPET_FLOW_MONITOR_FAILED` code 1: an `OFPFMC_ADD` tried to replace an existing monitor.
pub const OFPMOFC_MONITOR_EXISTS: u16 = 1;
/// `OFPET_FLOW_MONITOR_FAILED` code 2: the monitor id is invalid.
pub const OFPMOFC_INVALID_MONITOR: u16 = 2;
/// `OFPET_FLOW_MONITOR_FAILED` code 3: an `OFPFMC_MODIFY` targeted a monitor that does not exist.
pub const OFPMOFC_UNKNOWN_MONITOR: u16 = 3;
/// `OFPET_FLOW_MONITOR_FAILED` code 4: unsupported or unknown `ofp_flow_monitor_command`.
pub const OFPMOFC_BAD_COMMAND: u16 = 4;
/// `OFPET_FLOW_MONITOR_FAILED` code 5: unsupported combination of `OFPFMF_*` flags.
pub const OFPMOFC_BAD_FLAGS: u16 = 5;
/// `OFPET_FLOW_MONITOR_FAILED` code 6: the monitored table does not exist.
pub const OFPMOFC_BAD_TABLE_ID: u16 = 6;
/// `OFPET_FLOW_MONITOR_FAILED` code 7: error in the monitor's output port or group filter.
pub const OFPMOFC_BAD_OUT: u16 = 7;
/// `OFPET_BUNDLE_FAILED` code 0: unspecified error.
pub const OFPBFC_UNKNOWN: u16 = 0;
/// `OFPET_BUNDLE_FAILED` code 1: permissions error.
pub const OFPBFC_EPERM: u16 = 1;
/// `OFPET_BUNDLE_FAILED` code 3: that bundle id is already open.
pub const OFPBFC_BUNDLE_EXIST: u16 = 3;
/// `OFPET_BUNDLE_FAILED` code 5: too many open bundles.
pub const OFPBFC_OUT_OF_BUNDLES: u16 = 5;
/// `OFPET_BUNDLE_FAILED` code 6: unsupported or unknown `ofp_bundle_ctrl_type`.
pub const OFPBFC_BAD_TYPE: u16 = 6;
/// `OFPET_BUNDLE_FAILED` code 7: unsupported, unknown or inconsistent bundle flags.
pub const OFPBFC_BAD_FLAGS: u16 = 7;
/// `OFPET_BUNDLE_FAILED` code 8: length problem in a message added to the bundle.
pub const OFPBFC_MSG_BAD_LEN: u16 = 8;
/// `OFPET_BUNDLE_FAILED` code 9: inconsistent or duplicate xid in a bundled message.
pub const OFPBFC_MSG_BAD_XID: u16 = 9;
/// `OFPET_BUNDLE_FAILED` code 10: that message type may not be bundled.
pub const OFPBFC_MSG_UNSUP: u16 = 10;
/// `OFPET_BUNDLE_FAILED` code 11: unsupported combination of messages in one bundle.
pub const OFPBFC_MSG_CONFLICT: u16 = 11;
/// `OFPET_BUNDLE_FAILED` code 12: more messages than the bundle can hold.
pub const OFPBFC_MSG_TOO_MANY: u16 = 12;
/// `OFPET_BUNDLE_FAILED` code 13: one message in the bundle failed on commit.
pub const OFPBFC_MSG_FAILED: u16 = 13;
/// `OFPET_BUNDLE_FAILED` code 14: the bundle stayed open too long.
pub const OFPBFC_TIMEOUT: u16 = 14;
/// `OFPET_BUNDLE_FAILED` code 15: another bundle is holding the resource.
pub const OFPBFC_BUNDLE_IN_PROGRESS: u16 = 15;
/// `OFPET_BUNDLE_FAILED` code 16: a scheduled commit arrived but scheduling is unsupported.
pub const OFPBFC_SCHED_NOT_SUPPORTED: u16 = 16;
/// `OFPET_BUNDLE_FAILED` code 17: the scheduled commit time is too far in the future.
pub const OFPBFC_SCHED_FUTURE: u16 = 17;
/// `OFPET_BUNDLE_FAILED` code 18: the scheduled commit time is too far in the past.
pub const OFPBFC_SCHED_PAST: u16 = 18;

// --- Bitmask and enum values from the 1.5.1 spec's flag enums ---

// `ofp_capabilities`: `ofp_switch_features.capabilities` bits.
/// `ofp_switch_features.capabilities` bit 0: the switch keeps per-flow statistics.
pub const OFPC_FLOW_STATS: u32 = 1 << 0;
/// `ofp_switch_features.capabilities` bit 1: the switch keeps per-table statistics.
pub const OFPC_TABLE_STATS: u32 = 1 << 1;
/// `ofp_switch_features.capabilities` bit 2: the switch keeps per-port statistics.
pub const OFPC_PORT_STATS: u32 = 1 << 2;
/// `ofp_switch_features.capabilities` bit 3: the switch keeps per-group statistics.
pub const OFPC_GROUP_STATS: u32 = 1 << 3;
/// `ofp_switch_features.capabilities` bit 5: the switch can reassemble IP fragments (see
/// `OFPC_FRAG_REASM`).
pub const OFPC_IP_REASM: u32 = 1 << 5;
/// `ofp_switch_features.capabilities` bit 6: the switch keeps per-queue statistics.
pub const OFPC_QUEUE_STATS: u32 = 1 << 6;
/// `ofp_switch_features.capabilities` bit 8: the switch blocks looping ports itself (see
/// `OFPPS_BLOCKED`).
pub const OFPC_PORT_BLOCKED: u32 = 1 << 8;
/// `ofp_switch_features.capabilities` bit 9: the switch supports bundles.
pub const OFPC_BUNDLES: u32 = 1 << 9;
/// `ofp_switch_features.capabilities` bit 10: the switch supports flow monitoring.
pub const OFPC_FLOW_MONITORING: u32 = 1 << 10;

// `ofp_config_flags`: `ofp_switch_config.flags`.
/// `ofp_switch_config.flags` 0: no special handling, IP fragments go through the pipeline as they
/// are.
pub const OFPC_FRAG_NORMAL: u16 = 0;
/// `ofp_switch_config.flags` bit 0: drop IP fragments.
pub const OFPC_FRAG_DROP: u16 = 1 << 0;
/// `ofp_switch_config.flags` bit 1: reassemble IP fragments; only valid if `OFPC_IP_REASM` is
/// supported.
pub const OFPC_FRAG_REASM: u16 = 1 << 1;
/// Mask covering the fragment-handling bits of `ofp_switch_config.flags`.
pub const OFPC_FRAG_MASK: u16 = 3;

// `ofp_flow_mod_flags`: `ofp_flow_mod.flags`.
/// `ofp_flow_mod.flags` bit 0: send an `ofp_flow_removed` when this entry expires or is deleted.
///
/// Two caveats that bite in practice. The spec only says a
/// controller-initiated delete *should* generate the message, and Open
/// vSwitch does not -- a timeout expiry always does. And the connection
/// must first opt in through `OFPT_SET_ASYNC`, or the switch drops the
/// event silently.
///
/// ```
/// use openflow::protocol::constants::OFPFF_SEND_FLOW_REM;
/// use openflow::protocol::ofmatch::Match;
/// use openflow::protocol::rule::Rule;
///
/// let mut rule = Rule::add(1, 0, 100, Match::any(), Vec::new());
/// rule.flags = OFPFF_SEND_FLOW_REM;
/// rule.hard_timeout = 30; // expiry is the reliable trigger
/// ```
pub const OFPFF_SEND_FLOW_REM: u16 = 1 << 0;
/// `ofp_flow_mod.flags` bit 1: reject the add with `OFPFMFC_OVERLAP` if it overlaps an existing
/// entry.
pub const OFPFF_CHECK_OVERLAP: u16 = 1 << 1;
/// `ofp_flow_mod.flags` bit 2: reset the packet and byte counters of an entry being modified.
pub const OFPFF_RESET_COUNTS: u16 = 1 << 2;
/// `ofp_flow_mod.flags` bit 3: do not maintain a packet counter for this entry.
pub const OFPFF_NO_PKT_COUNTS: u16 = 1 << 3;
/// `ofp_flow_mod.flags` bit 4: do not maintain a byte counter for this entry.
pub const OFPFF_NO_BYT_COUNTS: u16 = 1 << 4;

// `ofp_flow_stats_reason`: `ofp_flow_stats.reason`.
/// `ofp_flow_stats.reason` 0: these statistics answer an `OFPMP_FLOW_STATS` request.
pub const OFPFSR_STATS_REQUEST: u8 = 0;
/// `ofp_flow_stats.reason` 1: these statistics were pushed by an `OFPIT_STAT_TRIGGER` instruction.
pub const OFPFSR_STAT_TRIGGER: u8 = 1;

// `ofp_port_config`: `ofp_port.config` / `ofp_port_mod.config`.
/// `ofp_port.config` bit 0: the port is administratively down.
pub const OFPPC_PORT_DOWN: u32 = 1 << 0;
/// `ofp_port.config` bit 2: drop everything received on this port.
pub const OFPPC_NO_RECV: u32 = 1 << 2;
/// `ofp_port.config` bit 5: drop packets forwarded to this port.
pub const OFPPC_NO_FWD: u32 = 1 << 5;
/// `ofp_port.config` bit 6: never raise `ofp_packet_in` for packets from this port.
pub const OFPPC_NO_PACKET_IN: u32 = 1 << 6;

// `ofp_port_state`: `ofp_port.state`.
/// `ofp_port.state` bit 0: no physical link is present.
pub const OFPPS_LINK_DOWN: u32 = 1 << 0;
/// `ofp_port.state` bit 1: the port is blocked, typically by the switch's own loop prevention.
pub const OFPPS_BLOCKED: u32 = 1 << 1;
/// `ofp_port.state` bit 2: the port is live, so `OFPGT_FF` buckets watching it may be selected.
pub const OFPPS_LIVE: u32 = 1 << 2;

// `ofp_port_features`: `ofp_port_desc_prop_ethernet` bitmaps.
/// `ofp_port_features` bit 0: 10 Mb/s half duplex.
pub const OFPPF_10MB_HD: u32 = 1 << 0;
/// `ofp_port_features` bit 1: 10 Mb/s full duplex.
pub const OFPPF_10MB_FD: u32 = 1 << 1;
/// `ofp_port_features` bit 2: 100 Mb/s half duplex.
pub const OFPPF_100MB_HD: u32 = 1 << 2;
/// `ofp_port_features` bit 3: 100 Mb/s full duplex.
pub const OFPPF_100MB_FD: u32 = 1 << 3;
/// `ofp_port_features` bit 4: 1 Gb/s half duplex.
pub const OFPPF_1GB_HD: u32 = 1 << 4;
/// `ofp_port_features` bit 5: 1 Gb/s full duplex.
pub const OFPPF_1GB_FD: u32 = 1 << 5;
/// `ofp_port_features` bit 6: 10 Gb/s full duplex.
pub const OFPPF_10GB_FD: u32 = 1 << 6;
/// `ofp_port_features` bit 7: 40 Gb/s full duplex.
pub const OFPPF_40GB_FD: u32 = 1 << 7;
/// `ofp_port_features` bit 8: 100 Gb/s full duplex.
pub const OFPPF_100GB_FD: u32 = 1 << 8;
/// `ofp_port_features` bit 9: 1 Tb/s full duplex.
pub const OFPPF_1TB_FD: u32 = 1 << 9;
/// `ofp_port_features` bit 10: some other rate not in this list.
pub const OFPPF_OTHER: u32 = 1 << 10;
/// `ofp_port_features` bit 11: copper medium.
pub const OFPPF_COPPER: u32 = 1 << 11;
/// `ofp_port_features` bit 12: fibre medium.
pub const OFPPF_FIBER: u32 = 1 << 12;
/// `ofp_port_features` bit 13: auto-negotiation.
pub const OFPPF_AUTONEG: u32 = 1 << 13;
/// `ofp_port_features` bit 14: symmetric pause frames.
pub const OFPPF_PAUSE: u32 = 1 << 14;
/// `ofp_port_features` bit 15: asymmetric pause frames.
pub const OFPPF_PAUSE_ASYM: u32 = 1 << 15;

// `ofp_optical_port_features`: `ofp_port_desc_prop_optical.supported`.
/// `ofp_port_desc_prop_optical.supported` bit 0: the receiver is tunable.
pub const OFPOPF_RX_TUNE: u32 = 1 << 0;
/// `ofp_port_desc_prop_optical.supported` bit 1: the transmitter is tunable.
pub const OFPOPF_TX_TUNE: u32 = 1 << 1;
/// `ofp_port_desc_prop_optical.supported` bit 2: transmit power is configurable.
pub const OFPOPF_TX_PWR: u32 = 1 << 2;
/// `ofp_port_desc_prop_optical.supported` bit 3: the tuning fields are frequencies, not
/// wavelengths.
pub const OFPOPF_USE_FREQ: u32 = 1 << 3;

// `ofp_port_stats_optical_flags`: `ofp_port_stats_prop_optical.flags`.
/// `ofp_port_stats_prop_optical.flags` bit 0: the receive tuning fields are valid.
pub const OFPOSF_RX_TUNE: u32 = 1 << 0;
/// `ofp_port_stats_prop_optical.flags` bit 1: the transmit tuning fields are valid.
pub const OFPOSF_TX_TUNE: u32 = 1 << 1;
/// `ofp_port_stats_prop_optical.flags` bit 2: the transmit power reading is valid.
pub const OFPOSF_TX_PWR: u32 = 1 << 2;
/// `ofp_port_stats_prop_optical.flags` bit 4: the receive power reading is valid.
pub const OFPOSF_RX_PWR: u32 = 1 << 4;
/// `ofp_port_stats_prop_optical.flags` bit 5: the transmit bias current reading is valid.
pub const OFPOSF_TX_BIAS: u32 = 1 << 5;
/// `ofp_port_stats_prop_optical.flags` bit 6: the transmit laser temperature reading is valid.
pub const OFPOSF_TX_TEMP: u32 = 1 << 6;

// `ofp_table_config`: `ofp_table_mod.config` / `ofp_table_desc.config`.
/// `ofp_table_mod.config`: mask of the two bits deprecated since 1.3, which must be left zero.
pub const OFPTC_DEPRECATED_MASK: u32 = 3;
/// `ofp_table_mod.config` bit 2: let the table evict entries itself, reported as `OFPRR_EVICTION`.
pub const OFPTC_EVICTION: u32 = 1 << 2;
/// `ofp_table_mod.config` bit 3: raise `OFPT_TABLE_STATUS` when a vacancy threshold is crossed.
pub const OFPTC_VACANCY_EVENTS: u32 = 1 << 3;

// `ofp_table_mod_prop_eviction_flag`: `ofp_table_mod_prop_eviction.flags`.
/// `ofp_table_mod_prop_eviction.flags` bit 0: eviction uses factors other than the two below.
pub const OFPTMPEF_OTHER: u32 = 1 << 0;
/// `ofp_table_mod_prop_eviction.flags` bit 1: eviction considers each entry's `importance`.
pub const OFPTMPEF_IMPORTANCE: u32 = 1 << 1;
/// `ofp_table_mod_prop_eviction.flags` bit 2: eviction considers each entry's remaining lifetime.
pub const OFPTMPEF_LIFETIME: u32 = 1 << 2;

// `ofp_table_feature_flag`: `ofp_table_features.capabilities`.
/// `ofp_table_features` flag bit 0: the table can be configured as an ingress table.
pub const OFPTFF_INGRESS_TABLE: u32 = 1 << 0;
/// `ofp_table_features` flag bit 1: the table can be configured as an egress table.
pub const OFPTFF_EGRESS_TABLE: u32 = 1 << 1;
/// `ofp_table_features` flag bit 4: this table is the first table of the egress pipeline.
pub const OFPTFF_FIRST_EGRESS: u32 = 1 << 4;

// `ofp_meter_flags`: `ofp_meter_mod.flags` / `ofp_meter_desc.flags`.
/// `ofp_meter_mod.flags` bit 0: band rates are in kilobits per second.
///
/// Mutually exclusive with [`OFPMF_PKTPS`], and one of the two is
/// mandatory: a meter whose `flags` is zero is rejected with
/// `OFPMMFC_BAD_FLAGS`.
pub const OFPMF_KBPS: u16 = 1 << 0;
/// `ofp_meter_mod.flags` bit 1: band rates are in packets per second.
pub const OFPMF_PKTPS: u16 = 1 << 1;
/// `ofp_meter_mod.flags` bit 2: honour each band's `burst_size`.
pub const OFPMF_BURST: u16 = 1 << 2;
/// `ofp_meter_mod.flags` bit 3: collect statistics for this meter.
pub const OFPMF_STATS: u16 = 1 << 3;

// `ofp_meter_feature_flags`: `ofp_meter_features.features`.
/// `ofp_meter_features.features` bit 0: `OFPAT_METER` is allowed in the action set.
pub const OFPMFF_ACTION_SET: u32 = 1 << 0;
/// `ofp_meter_features.features` bit 1: `OFPAT_METER` may appear anywhere in an action list.
pub const OFPMFF_ANY_POSITION: u32 = 1 << 1;
/// `ofp_meter_features.features` bit 2: several `OFPAT_METER` actions may appear in one action
/// list.
pub const OFPMFF_MULTI_LIST: u32 = 1 << 2;

// `ofp_group_capabilities`: `ofp_group_features.capabilities`.
/// `ofp_group_features.capabilities` bit 0: select groups honour per-bucket weights.
pub const OFPGFC_SELECT_WEIGHT: u32 = 1 << 0;
/// `ofp_group_features.capabilities` bit 1: select groups honour bucket liveness.
pub const OFPGFC_SELECT_LIVENESS: u32 = 1 << 1;
/// `ofp_group_features.capabilities` bit 2: groups may forward to other groups.
pub const OFPGFC_CHAINING: u32 = 1 << 2;
/// `ofp_group_features.capabilities` bit 3: the switch checks group chains for loops.
pub const OFPGFC_CHAINING_CHECKS: u32 = 1 << 3;

// `ofp_flow_monitor_flags`: `ofp_flow_monitor_request.flags`.
/// `ofp_flow_monitor_request.flags` bit 0: report the flows already matching when the monitor is
/// created.
pub const OFPFMF_INITIAL: u16 = 1 << 0;
/// `ofp_flow_monitor_request.flags` bit 1: report matching flows as they are added.
pub const OFPFMF_ADD: u16 = 1 << 1;
/// `ofp_flow_monitor_request.flags` bit 2: report matching flows as they are removed.
pub const OFPFMF_REMOVED: u16 = 1 << 2;
/// `ofp_flow_monitor_request.flags` bit 3: report matching flows as they are changed.
pub const OFPFMF_MODIFY: u16 = 1 << 3;
/// `ofp_flow_monitor_request.flags` bit 4: include each flow's instructions in the updates.
pub const OFPFMF_INSTRUCTIONS: u16 = 1 << 4;
/// `ofp_flow_monitor_request.flags` bit 5: report this controller's own changes in full rather than
/// as `OFPFME_ABBREV`.
pub const OFPFMF_NO_ABBREV: u16 = 1 << 5;
/// `ofp_flow_monitor_request.flags` bit 6: report only this controller's own changes.
pub const OFPFMF_ONLY_OWN: u16 = 1 << 6;

// `ofp_stat_trigger_flags`: `ofp_instruction_stat_trigger.flags`.
/// `ofp_instruction_stat_trigger.flags` bit 0: trigger at every multiple of the thresholds, not
/// just once.
pub const OFPSTF_PERIODIC: u32 = 1 << 0;
/// `ofp_instruction_stat_trigger.flags` bit 1: trigger only the first time a threshold is reached.
pub const OFPSTF_ONLY_FIRST: u32 = 1 << 1;

// `ofp_ipv6exthdr_flags`: the `OXM_OF_IPV6_EXTHDR` pseudo-field.
/// `OXM_OF_IPV6_EXTHDR` bit 0: a "no next header" value was encountered.
pub const OFPIEH_NONEXT: u16 = 1 << 0;
/// `OXM_OF_IPV6_EXTHDR` bit 1: an encapsulating security payload header is present.
pub const OFPIEH_ESP: u16 = 1 << 1;
/// `OXM_OF_IPV6_EXTHDR` bit 2: an authentication header is present.
pub const OFPIEH_AUTH: u16 = 1 << 2;
/// `OXM_OF_IPV6_EXTHDR` bit 3: one or two destination option headers are present.
pub const OFPIEH_DEST: u16 = 1 << 3;
/// `OXM_OF_IPV6_EXTHDR` bit 4: a fragment header is present.
pub const OFPIEH_FRAG: u16 = 1 << 4;
/// `OXM_OF_IPV6_EXTHDR` bit 5: a routing header is present.
pub const OFPIEH_ROUTER: u16 = 1 << 5;
/// `OXM_OF_IPV6_EXTHDR` bit 6: a hop-by-hop options header is present.
pub const OFPIEH_HOP: u16 = 1 << 6;
/// `OXM_OF_IPV6_EXTHDR` bit 7: an extension header was repeated unexpectedly.
pub const OFPIEH_UNREP: u16 = 1 << 7;
/// `OXM_OF_IPV6_EXTHDR` bit 8: the extension headers appeared out of the recommended order.
pub const OFPIEH_UNSEQ: u16 = 1 << 8;

// `ofp_bundle_feature_flags`: `ofp_bundle_features.capabilities`.
/// `ofp_bundle_features.capabilities` bit 0: bundle requests may carry a timestamp.
pub const OFPBF_TIMESTAMP: u32 = 1 << 0;
/// `ofp_bundle_features.capabilities` bit 1: the scheduling tolerance parameters may be set.
pub const OFPBF_TIME_SET_SCHED: u32 = 1 << 1;

// `OFPCID_UNDEFINED`: `ofp_controller_status.short_id` when unset.
/// `ofp_controller_status.short_id` value meaning the switch has assigned no short id to this
/// controller.
pub const OFPCID_UNDEFINED: u16 = 0;

// --- Property-type, command and reserved-id enums from the 1.5.1 spec ---

// `ofp_table_feature_prop_type`: `ofp_table_features` property types.
/// `ofp_table_features` property 0: instructions supported by ordinary entries in this table.
pub const OFPTFPT_INSTRUCTIONS: u16 = 0;
/// `ofp_table_features` property 1: instructions supported by the table-miss entry.
pub const OFPTFPT_INSTRUCTIONS_MISS: u16 = 1;
/// `ofp_table_features` property 2: table ids reachable by `OFPIT_GOTO_TABLE` from ordinary
/// entries.
pub const OFPTFPT_NEXT_TABLES: u16 = 2;
/// `ofp_table_features` property 3: table ids reachable by `OFPIT_GOTO_TABLE` from the table-miss
/// entry.
pub const OFPTFPT_NEXT_TABLES_MISS: u16 = 3;
/// `ofp_table_features` property 4: actions allowed in `OFPIT_WRITE_ACTIONS` for ordinary entries.
pub const OFPTFPT_WRITE_ACTIONS: u16 = 4;
/// `ofp_table_features` property 5: actions allowed in `OFPIT_WRITE_ACTIONS` for the table-miss
/// entry.
pub const OFPTFPT_WRITE_ACTIONS_MISS: u16 = 5;
/// `ofp_table_features` property 6: actions allowed in `OFPIT_APPLY_ACTIONS` for ordinary entries.
pub const OFPTFPT_APPLY_ACTIONS: u16 = 6;
/// `ofp_table_features` property 7: actions allowed in `OFPIT_APPLY_ACTIONS` for the table-miss
/// entry.
pub const OFPTFPT_APPLY_ACTIONS_MISS: u16 = 7;
/// `ofp_table_features` property 8: OXM ids this table can match on.
pub const OFPTFPT_MATCH: u16 = 8;
/// `ofp_table_features` property 10: OXM ids this table can wildcard or mask.
pub const OFPTFPT_WILDCARDS: u16 = 10;
/// `ofp_table_features` property 12: OXM ids settable by `OFPAT_SET_FIELD` in write-actions.
pub const OFPTFPT_WRITE_SETFIELD: u16 = 12;
/// `ofp_table_features` property 13: as `OFPTFPT_WRITE_SETFIELD`, for the table-miss entry.
pub const OFPTFPT_WRITE_SETFIELD_MISS: u16 = 13;
/// `ofp_table_features` property 14: OXM ids settable by `OFPAT_SET_FIELD` in apply-actions.
pub const OFPTFPT_APPLY_SETFIELD: u16 = 14;
/// `ofp_table_features` property 15: as `OFPTFPT_APPLY_SETFIELD`, for the table-miss entry.
pub const OFPTFPT_APPLY_SETFIELD_MISS: u16 = 15;
/// `ofp_table_features` property 16: tables this one may be synchronised from.
pub const OFPTFPT_TABLE_SYNC_FROM: u16 = 16;
/// `ofp_table_features` property 18: OXM ids usable by `OFPAT_COPY_FIELD` in write-actions.
pub const OFPTFPT_WRITE_COPYFIELD: u16 = 18;
/// `ofp_table_features` property 19: as `OFPTFPT_WRITE_COPYFIELD`, for the table-miss entry.
pub const OFPTFPT_WRITE_COPYFIELD_MISS: u16 = 19;
/// `ofp_table_features` property 20: OXM ids usable by `OFPAT_COPY_FIELD` in apply-actions.
pub const OFPTFPT_APPLY_COPYFIELD: u16 = 20;
/// `ofp_table_features` property 21: as `OFPTFPT_APPLY_COPYFIELD`, for the table-miss entry.
pub const OFPTFPT_APPLY_COPYFIELD_MISS: u16 = 21;
/// `ofp_table_features` property 22: packet types this table accepts (see
/// `OFPXMT_OFB_PACKET_TYPE`).
pub const OFPTFPT_PACKET_TYPES: u16 = 22;
/// `ofp_table_features` property 0xfffe: experimenter property for ordinary entries.
pub const OFPTFPT_EXPERIMENTER: u16 = 0xFFFE;
/// `ofp_table_features` property 0xffff: experimenter property for the table-miss entry.
pub const OFPTFPT_EXPERIMENTER_MISS: u16 = 0xFFFF;

// `ofp_flow_update_event`: `ofp_flow_update_header.event`.
/// `ofp_flow_update_header.event` 0: a flow that already existed when the monitor was created.
pub const OFPFME_INITIAL: u16 = 0;
/// `ofp_flow_update_header.event` 1: a matching flow was added.
pub const OFPFME_ADDED: u16 = 1;
/// `ofp_flow_update_header.event` 2: a matching flow was removed.
pub const OFPFME_REMOVED: u16 = 2;
/// `ofp_flow_update_header.event` 3: a matching flow's instructions changed.
pub const OFPFME_MODIFIED: u16 = 3;
/// `ofp_flow_update_header.event` 4: abbreviated update naming only the xid of this controller's
/// own change.
pub const OFPFME_ABBREV: u16 = 4;
/// `ofp_flow_update_header.event` 5: monitoring paused because the switch ran out of buffer space.
pub const OFPFME_PAUSED: u16 = 5;
/// `ofp_flow_update_header.event` 6: monitoring resumed after a pause.
pub const OFPFME_RESUMED: u16 = 6;

// `ofp_flow_monitor_command`: `ofp_flow_monitor_request.command`.
/// `ofp_flow_monitor_request.command` 0: create a new flow monitor.
pub const OFPFMC_ADD: u8 = 0;
/// `ofp_flow_monitor_request.command` 1: change an existing flow monitor.
pub const OFPFMC_MODIFY: u8 = 1;
/// `ofp_flow_monitor_request.command` 2: cancel an existing flow monitor.
pub const OFPFMC_DELETE: u8 = 2;

// `ofp_table_features_command`: `ofp_table_features_request.command`.
/// `ofp_table_features.command` 0: replace the whole pipeline description.
pub const OFPTFC_REPLACE: u8 = 0;
/// `ofp_table_features.command` 1: change the capabilities of the listed tables only.
pub const OFPTFC_MODIFY: u8 = 1;
/// `ofp_table_features.command` 2: enable the listed tables in the pipeline.
pub const OFPTFC_ENABLE: u8 = 2;
/// `ofp_table_features.command` 3: disable the listed tables in the pipeline.
pub const OFPTFC_DISABLE: u8 = 3;

// `ofp_controller_status_prop_type`.
/// `ofp_controller_status` property 0: the connection URI of the controller being described.
pub const OFPCSPT_URI: u16 = 0;
/// `ofp_controller_status` property 0xffff: experimenter property carrying an experimenter id and
/// type.
pub const OFPCSPT_EXPERIMENTER: u16 = 0xFFFF;

// `ofp_queue_desc_prop_type`.
/// `ofp_queue_desc` property 1: guaranteed minimum rate, in tenths of a percent of the port rate.
pub const OFPQDPT_MIN_RATE: u16 = 1;
/// `ofp_queue_desc` property 2: maximum rate, in tenths of a percent of the port rate.
pub const OFPQDPT_MAX_RATE: u16 = 2;
/// `ofp_queue_desc` property 0xffff: experimenter property carrying an experimenter id and type.
pub const OFPQDPT_EXPERIMENTER: u16 = 0xffff;

// `ofp_queue_stats_prop_type`.
/// `ofp_queue_stats` property 0xffff: the only queue stats property type defined, carrying
/// experimenter data.
pub const OFPQSPT_EXPERIMENTER: u16 = 0xffff;

// `ofp_port_stats_prop_type`.
/// `ofp_port_stats` property 0: Ethernet error and collision counters.
pub const OFPPSPT_ETHERNET: u16 = 0;
/// `ofp_port_stats` property 1: optical readings, valid as flagged by `OFPOSF_*`.
pub const OFPPSPT_OPTICAL: u16 = 1;
/// `ofp_port_stats` property 0xffff: experimenter property carrying an experimenter id and type.
pub const OFPPSPT_EXPERIMENTER: u16 = 0xFFFF;

// `ofp_role_prop_type`.
/// `ofp_role_status` property 0xffff: the only role property type defined, carrying experimenter
/// data.
pub const OFPRPT_EXPERIMENTER: u16 = 0xFFFF;

// `ofp_bundle_prop_type`.
/// `ofp_bundle_ctrl_msg` property 1: scheduled commit time, used together with `OFPBF_TIME`.
pub const OFPBPT_TIME: u16 = 1;
/// `ofp_bundle_ctrl_msg` property 0xffff: experimenter property carrying an experimenter id and
/// type.
pub const OFPBPT_EXPERIMENTER: u16 = 0xFFFF;

// `ofp_bundle_features_prop_type`.
/// `ofp_bundle_features` property 0x1: the switch's time and scheduling capabilities.
pub const OFPTMPBF_TIME_CAPABILITY: u16 = 0x1;
/// `ofp_bundle_features` property 0xffff: experimenter property carrying an experimenter id and
/// type.
pub const OFPTMPBF_EXPERIMENTER: u16 = 0xFFFF;

// `ofp_header_type_namespaces`: `OXM_OF_PACKET_TYPE` namespaces.
/// `ofp_header_type.namespace` 0: the ONF namespace, whose types are the `OFPHTO_*` values.
pub const OFPHTN_ONF: u16 = 0;
/// `ofp_header_type.namespace` 1: `ns_type` is an ethertype, as in packet type (1, 0x0800) for
/// IPv4.
pub const OFPHTN_ETHERTYPE: u16 = 1;
/// `ofp_header_type.namespace` 2: `ns_type` is an IP protocol number.
pub const OFPHTN_IP_PROTO: u16 = 2;
/// `ofp_header_type.namespace` 3: `ns_type` is a TCP or UDP port number.
pub const OFPHTN_UDP_TCP_PORT: u16 = 3;
/// `ofp_header_type.namespace` 4: `ns_type` is an IPv4 option number.
pub const OFPHTN_IPV4_OPTION: u16 = 4;

// `ofp_header_type_onf`: `OFPHTN_ONF` namespace types.
/// `OFPHTN_ONF` type 0: the packet starts with an Ethernet header; the default packet type.
pub const OFPHTO_ETHERNET: u16 = 0;
/// `OFPHTN_ONF` type 1: the packet has no header, as on a circuit-switched port.
pub const OFPHTO_NO_HEADER: u16 = 1;
/// `OFPHTN_ONF` type 0xffff: the packet type is described by an experimenter OXM instead.
pub const OFPHTO_OXM_EXPERIMENTER: u16 = 0xFFFF;

// `ofp_vlan_id`: `OXM_OF_VLAN_VID` special values.
/// `OXM_OF_VLAN_VID` bit 12: set whenever an 802.1Q tag is present; or it into the id you match or
/// set.
pub const OFPVID_PRESENT: u16 = 0x1000;
/// `OXM_OF_VLAN_VID` value 0: the packet carries no 802.1Q tag.
pub const OFPVID_NONE: u16 = 0x0000;

// `ofp_table`: reserved table ids.
/// `ofp_table`: highest usable flow table id; 0xff is the wildcard `OFPTT_ALL`.
pub const OFPTT_MAX: u8 = 0xfe;

// `ofp_meter`: reserved meter ids.
/// `ofp_meter`: highest assignable meter id; anything above is a virtual meter.
pub const OFPM_MAX: u32 = 0xffff_0000;
/// `ofp_meter`: virtual meter rate-limiting traffic sent to the switch's slow path.
pub const OFPM_SLOWPATH: u32 = 0xffff_fffd;
/// `ofp_meter`: virtual meter rate-limiting traffic sent over the controller connection.
pub const OFPM_CONTROLLER: u32 = 0xffff_fffe;
/// `ofp_meter`: wildcard matching every meter, valid in `ofp_meter_mod` deletes and meter stats
/// requests.
pub const OFPM_ALL: u32 = 0xffff_ffff;

// `ofp_group_bucket`: reserved bucket ids.
/// `ofp_group_bucket`: highest assignable `ofp_bucket.bucket_id`.
pub const OFPG_BUCKET_MAX: u32 = 0xffff_ff00;
/// `ofp_group_bucket`: the first bucket in the group, for `OFPGC_INSERT_BUCKET` and
/// `OFPGC_REMOVE_BUCKET`.
pub const OFPG_BUCKET_FIRST: u32 = 0xffff_fffd;
/// `ofp_group_bucket`: the last bucket in the group, for `OFPGC_INSERT_BUCKET` and
/// `OFPGC_REMOVE_BUCKET`.
pub const OFPG_BUCKET_LAST: u32 = 0xffff_fffe;
/// `ofp_group_bucket`: every bucket in the group; valid only with `OFPGC_REMOVE_BUCKET`.
///
/// Also the value `command_bucket_id` **must** carry for `OFPGC_ADD`,
/// `OFPGC_MODIFY` and `OFPGC_DELETE`, which do not otherwise use the
/// field. Real switches enforce this: Open vSwitch answers
/// `OFPGMFC_BAD_BUCKET` for anything else.
pub const OFPG_BUCKET_ALL: u32 = 0xffff_ffff;

// Reserved queue ids and rate sentinels (spec 7.3.5.11 / 7.3.5.12).
/// Wildcard `queue_id` selecting all queues on a port in an `OFPMP_QUEUE_STATS` or
/// `OFPMP_QUEUE_DESC` request.
pub const OFPQ_ALL: u32 = 0xffff_ffff;
/// `OFPQDPT_MIN_RATE` value meaning no minimum rate is configured for the queue.
pub const OFPQ_MIN_RATE_UNCFG: u16 = 0xffff;
/// `OFPQDPT_MAX_RATE` value meaning no maximum rate is configured for the queue.
pub const OFPQ_MAX_RATE_UNCFG: u16 = 0xffff;

// Well-known transport ports for the `OpenFlow` channel.
/// IANA-registered TCP port for the `OpenFlow` channel, the default this crate listens on.
pub const OFP_TCP_PORT: u16 = 6653;
/// IANA-registered port for the `OpenFlow` channel over TLS; the same number as `OFP_TCP_PORT`.
pub const OFP_SSL_PORT: u16 = 6653;

// --- Nicira/OVS connection-tracking extension (see `protocol::nicira`) ---
// Mainline OpenFlow 1.5 has no notion of connection tracking; every
// constant below is an Open vSwitch extension, not part of the spec.
// All of them are verified against a real OVS bridge by
// `nicira_conntrack_actions_and_match_fields_are_accepted_by_ovs` in
// `tests/ovs_integration.rs`.

/// Nicira/OVS experimenter id ("vendor"), fixed by OVS's own
/// `nicira-ext.h` and used for every `NXM_NX_*` match field and
/// `NXAST_*` action this crate implements.
pub const NX_VENDOR_ID: u32 = 0x0000_2320;

/// `NXM_NX_CT_STATE` field number.
///
/// Legacy `NXM_NX_*` fields predate `OpenFlow`'s generic experimenter-OXM
/// mechanism, so they travel under Nicira's own registered OXM class
/// [`OFPXMC_NXM_1`] with their original field number -- *not* under
/// `OFPXMC_EXPERIMENTER` with an embedded vendor id (OVS rejects that
/// form with `OFPBMC_BAD_FIELD`). See
/// [`crate::protocol::oxm::ct_state`] for the encoder. The field number
/// is verified against real OVS (see the module note above).
pub const NXM_NX_CT_STATE: u8 = 105;
/// `NXM_NX_CT_ZONE` field number -- see [`NXM_NX_CT_STATE`]'s doc
/// comment for the encoding convention; likewise verified against OVS.
pub const NXM_NX_CT_ZONE: u8 = 106;

/// `ct_state` bit: this packet is the first of a new, not-yet-established
/// tracked connection (`ovs-fields(7)`'s `+new`).
pub const NX_CS_NEW: u32 = 0x01;
/// `ct_state` bit: this packet is the reply-direction leg of a tracked
/// connection (`ovs-fields(7)`'s `+rpl`).
pub const NX_CS_RPL: u32 = 0x08;
/// `ct_state` bit: this packet's connection has been through conntrack
/// at all (`ovs-fields(7)`'s `+trk`) -- an untracked packet has no other
/// `ct_state` bit meaningfully set.
///
/// The gate bit: an untracked packet has no other `ct_state` bit
/// meaningfully set, so a match on any other bit should also require
/// `+trk`.
///
/// ```
/// use openflow::protocol::constants::{NX_CS_RPL, NX_CS_TRK};
/// use openflow::protocol::oxm;
///
/// // "tracked and reply-direction", ignoring the other bits.
/// let bits = NX_CS_TRK | NX_CS_RPL;
/// let tlv = oxm::ct_state_masked(bits, bits);
/// assert_eq!(tlv.len(), 12); // 4-byte header + 4-byte value + 4-byte mask
/// ```
pub const NX_CS_TRK: u32 = 0x20;

/// `NXAST_CT`/`NXAST_NAT` action subtypes.
///
/// Carried inside an `OFPAT_EXPERIMENTER` action with `NX_VENDOR_ID`.
/// Values confirmed against real OVS, which accepts both actions.
pub const NXAST_CT: u16 = 35;
/// `NXAST_NAT` action subtype, carried like `NXAST_CT` and sharing its verification caveat.
pub const NXAST_NAT: u16 = 36;

/// `nx_action_conntrack.flags` bit: commit this connection to the
/// tracker (rather than only looking up an existing one).
pub const NX_CT_F_COMMIT: u16 = 1 << 0;
/// `nx_action_conntrack.recirc_table` sentinel meaning "don't recirculate
/// -- keep evaluating the rest of the current table's actions."
pub const NX_CT_RECIRC_NONE: u8 = 0xff;

/// `nx_action_nat.flags` bit selecting the source address for `nat()`.
pub const NX_NAT_F_SRC: u16 = 1 << 0;
/// `nx_action_nat.flags` bit selecting the destination address for
/// `nat()`.
pub const NX_NAT_F_DST: u16 = 1 << 1;
/// `nx_action_nat.range_present` bit: a single IPv4 address (used here
/// as both min and max of the range -- this crate never needs a real
/// range or a port range) follows the fixed header.
pub const NX_NAT_RANGE_IPV4_MIN: u16 = 1 << 0;

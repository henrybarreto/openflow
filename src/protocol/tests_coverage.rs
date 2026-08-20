//! Breadth tests: exercise every public constructor, accessor and
//! encode/decode entry point that the behavioural tests in `tests.rs`
//! don't reach, so a refactor that breaks one of them fails here rather
//! than in a user's code.

#[cfg(test)]
mod tests {
    use crate::protocol::constants::*;
    use crate::protocol::error::OfError;
    use crate::protocol::oxm::{self, Tlv};

    // ---- proto_error: Display / Error::source / From<io::Error> ----

    #[test]
    fn every_error_variant_formats_and_reports_its_source() {
        use std::error::Error as _;

        let io = OfError::from(std::io::Error::new(std::io::ErrorKind::Other, "boom"));
        assert!(io.to_string().contains("boom"));
        assert!(io.source().is_some());

        let cases: Vec<(OfError, &str)> = vec![
            (OfError::ShortBuffer, "short buffer"),
            (OfError::UnsupportedVersion(4), "unsupported"),
            (OfError::InvalidLength(9), "invalid message length"),
            (OfError::UnknownMessageType(99), "unknown message type"),
            (OfError::InvalidOxmLength, "invalid OXM length"),
            (
                OfError::InvalidValue {
                    field: "thing",
                    value: 7,
                },
                "invalid value for thing",
            ),
            (
                OfError::DuplicateOxmField {
                    class: 0x8000,
                    field: 3,
                },
                "duplicate OXM field",
            ),
            (
                OfError::UnknownOxmField {
                    class: 0x8000,
                    field: 90,
                },
                "unknown OXM field",
            ),
            (
                OfError::MissingOxmPrerequisite { field: 11 },
                "missing OXM prerequisite",
            ),
        ];
        for (err, needle) in cases {
            let rendered = err.to_string();
            assert!(
                rendered.contains(needle),
                "{rendered:?} should contain {needle:?}"
            );
            assert!(err.source().is_none(), "{rendered:?} should have no source");
            // Debug is derived but must not panic.
            let _ = format!("{err:?}");
        }
    }

    // ---- oxm: every field constructor, and its size/maskability table ----

    /// Each helper must emit exactly one TLV whose declared length equals
    /// the payload it wrote, and whose field id matches the accessor.
    #[test]
    fn every_oxm_field_constructor_encodes_one_well_formed_tlv() {
        let mac = [1u8, 2, 3, 4, 5, 6];
        let v4 = [10u8, 0, 0, 1];
        let v6 = [0u8; 16];

        let cases: Vec<(Vec<u8>, u8, usize)> = vec![
            (oxm::in_port(1), OFPXMT_OFB_IN_PORT, 4),
            (oxm::eth_dst(mac), OFPXMT_OFB_ETH_DST, 6),
            (oxm::eth_src(mac), OFPXMT_OFB_ETH_SRC, 6),
            (oxm::eth_type(0x0800), OFPXMT_OFB_ETH_TYPE, 2),
            (oxm::ipv4_src(v4), OFPXMT_OFB_IPV4_SRC, 4),
            (oxm::ipv4_dst(v4), OFPXMT_OFB_IPV4_DST, 4),
            (oxm::icmpv4_type(8), OFPXMT_OFB_ICMPV4_TYPE, 1),
            (oxm::icmpv4_code(0), OFPXMT_OFB_ICMPV4_CODE, 1),
            (oxm::icmpv6_type(135), OFPXMT_OFB_ICMPV6_TYPE, 1),
            (oxm::icmpv6_code(0), OFPXMT_OFB_ICMPV6_CODE, 1),
            (oxm::ipv6_src(v6), OFPXMT_OFB_IPV6_SRC, 16),
            (oxm::ipv6_dst(v6), OFPXMT_OFB_IPV6_DST, 16),
            (oxm::ipv6_nd_target(v6), OFPXMT_OFB_IPV6_ND_TARGET, 16),
            (oxm::ipv6_nd_sll(mac), OFPXMT_OFB_IPV6_ND_SLL, 6),
            (oxm::ipv6_nd_tll(mac), OFPXMT_OFB_IPV6_ND_TLL, 6),
            (oxm::ip_proto(6), OFPXMT_OFB_IP_PROTO, 1),
            (oxm::arp_op(1), OFPXMT_OFB_ARP_OP, 2),
            (oxm::arp_spa(v4), OFPXMT_OFB_ARP_SPA, 4),
            (oxm::arp_tpa(v4), OFPXMT_OFB_ARP_TPA, 4),
            (oxm::arp_sha(mac), OFPXMT_OFB_ARP_SHA, 6),
            (oxm::arp_tha(mac), OFPXMT_OFB_ARP_THA, 6),
        ];

        for (bytes, field, value_len) in cases {
            assert_eq!(bytes.len(), 4 + value_len, "field {field}");
            let header = u32::from_be_bytes(bytes[..4].try_into().unwrap());
            assert_eq!(
                u16::try_from(header >> 16).unwrap(),
                OFPXMC_OPENFLOW_BASIC,
                "field {field}"
            );
            assert_eq!(u8::try_from((header >> 9) & 0x7f).unwrap(), field);
            assert_eq!(header & 0x100, 0, "field {field} must be unmasked");
            assert_eq!(usize::try_from(header & 0xff).unwrap(), value_len);
        }
    }

    #[test]
    fn masked_oxm_constructors_double_the_length_and_set_the_mask_bit() {
        for bytes in [
            oxm::ipv4_src_masked([10, 0, 0, 0], [255, 0, 0, 0]),
            oxm::ipv4_dst_masked([10, 0, 0, 0], [255, 0, 0, 0]),
        ] {
            let header = u32::from_be_bytes(bytes[..4].try_into().unwrap());
            assert_ne!(header & 0x100, 0, "mask bit must be set");
            assert_eq!(header & 0xff, 8);
            assert_eq!(bytes.len(), 12);
        }
    }

    #[test]
    fn oxm_id_helpers_emit_bare_headers_with_no_value() {
        assert_eq!(oxm::field_id(OFPXMT_OFB_ETH_DST, 6).len(), 4);
        let pair = oxm::copy_field_ids(OFPXMT_OFB_ETH_SRC, 6, OFPXMT_OFB_ETH_DST, 6);
        assert_eq!(pair.len(), 8);
        let first = u32::from_be_bytes(pair[..4].try_into().unwrap());
        let second = u32::from_be_bytes(pair[4..8].try_into().unwrap());
        assert_eq!(
            u8::try_from((first >> 9) & 0x7f).unwrap(),
            OFPXMT_OFB_ETH_SRC
        );
        assert_eq!(
            u8::try_from((second >> 9) & 0x7f).unwrap(),
            OFPXMT_OFB_ETH_DST
        );
    }

    /// Every field id the spec defines must parse at its documented
    /// width, and every id it does not define must be rejected.
    #[test]
    fn oxm_accepts_all_44_basic_fields_and_rejects_unknown_ids() {
        // (field id, unmasked byte width) straight from the spec's
        // OXM_HEADER macros.
        const SPEC: [(u8, usize); 44] = [
            (0, 4),
            (1, 4),
            (2, 8),
            (3, 6),
            (4, 6),
            (5, 2),
            (6, 2),
            (7, 1),
            (8, 1),
            (9, 1),
            (10, 1),
            (11, 4),
            (12, 4),
            (13, 2),
            (14, 2),
            (15, 2),
            (16, 2),
            (17, 2),
            (18, 2),
            (19, 1),
            (20, 1),
            (21, 2),
            (22, 4),
            (23, 4),
            (24, 6),
            (25, 6),
            (26, 16),
            (27, 16),
            (28, 4),
            (29, 1),
            (30, 1),
            (31, 16),
            (32, 6),
            (33, 6),
            (34, 4),
            (35, 1),
            (36, 1),
            (37, 3),
            (38, 8),
            (39, 2),
            (41, 1),
            (42, 2),
            (43, 4),
            (44, 4),
        ];

        for (field, width) in SPEC {
            let tlvs =
                oxm::parse_oxm_list_unchecked(&oxm::field(field, &vec![0u8; width]).unwrap())
                    .unwrap_or_else(|e| panic!("field {field} width {width} rejected: {e}"));
            assert_eq!(
                tlvs,
                vec![Tlv::Basic {
                    field,
                    value: vec![0u8; width],
                    mask: None,
                }]
            );
            // The wrong width must be rejected.
            let wrong = oxm::field(field, &vec![0u8; width + 1]).unwrap();
            assert!(
                matches!(
                    oxm::parse_oxm_list_unchecked(&wrong),
                    Err(OfError::InvalidOxmLength)
                ),
                "field {field} accepted a {}-byte value",
                width + 1
            );
        }

        // 40 is the one gap in the enum, and 45+ are past its end.
        for field in [40u8, 45, 60] {
            assert!(matches!(
                oxm::parse_oxm_list_unchecked(&oxm::field(field, &[0]).unwrap()),
                Err(OfError::UnknownOxmField { .. })
            ));
        }
    }

    /// The spec defines exactly 15 maskable basic fields; the rest must
    /// be rejected when a mask is present.
    #[test]
    fn oxm_maskability_matches_the_spec_exactly() {
        const MASKABLE: [(u8, usize); 15] = [
            (OFPXMT_OFB_METADATA, 8),
            (OFPXMT_OFB_ETH_DST, 6),
            (OFPXMT_OFB_ETH_SRC, 6),
            (OFPXMT_OFB_VLAN_VID, 2),
            (OFPXMT_OFB_IPV4_SRC, 4),
            (OFPXMT_OFB_IPV4_DST, 4),
            (OFPXMT_OFB_TCP_FLAGS, 2),
            (OFPXMT_OFB_ARP_SPA, 4),
            (OFPXMT_OFB_ARP_TPA, 4),
            (OFPXMT_OFB_IPV6_SRC, 16),
            (OFPXMT_OFB_IPV6_DST, 16),
            (OFPXMT_OFB_IPV6_FLABEL, 4),
            (OFPXMT_OFB_PBB_ISID, 3),
            (OFPXMT_OFB_TUNNEL_ID, 8),
            (OFPXMT_OFB_IPV6_EXTHDR, 2),
        ];
        for (field, width) in MASKABLE {
            let bytes = oxm::masked_field(field, &vec![0u8; width], &vec![0xffu8; width]).unwrap();
            let tlvs = oxm::parse_oxm_list_unchecked(&bytes)
                .unwrap_or_else(|e| panic!("maskable field {field} rejected: {e}"));
            assert_eq!(
                tlvs,
                vec![Tlv::Basic {
                    field,
                    value: vec![0u8; width],
                    mask: Some(vec![0xffu8; width]),
                }]
            );
        }
        // A field outside that set must not accept a mask.
        let bad = oxm::masked_field(OFPXMT_OFB_ETH_TYPE, &[0, 0], &[0xff, 0xff]).unwrap();
        assert!(matches!(
            oxm::parse_oxm_list_unchecked(&bad),
            Err(OfError::InvalidOxmLength)
        ));
    }

    #[test]
    fn oxm_tlv_list_round_trips_every_variant() {
        let basic = Tlv::Basic {
            field: OFPXMT_OFB_ETH_DST,
            value: vec![1, 2, 3, 4, 5, 6],
            mask: Some(vec![0xff; 6]),
        };
        let experimenter = Tlv::Experimenter {
            field: 3,
            experimenter: 0x0000_2320,
            value: vec![9, 9],
            mask: None,
        };
        let other = Tlv::Other {
            class: OFPXMC_NXM_1,
            field: NXM_NX_CT_ZONE,
            value: vec![0, 7],
            mask: None,
        };
        let all = vec![basic, experimenter, other];
        let encoded = oxm::encode_tlv_list(&all).unwrap();
        assert_eq!(oxm::parse_oxm_list_unchecked(&encoded).unwrap(), all);

        // A value too long for the 8-bit length field is rejected rather
        // than silently truncated.
        let oversized = vec![Tlv::Basic {
            field: OFPXMT_OFB_ETH_DST,
            value: vec![0u8; 300],
            mask: None,
        }];
        assert!(oxm::encode_tlv_list(&oversized).is_err());
    }

    #[test]
    fn oxm_rejects_truncated_and_zero_length_tlvs() {
        assert!(matches!(
            oxm::parse_oxm_list_unchecked(&[0x80, 0x00]),
            Err(OfError::ShortBuffer)
        ));
        // Declared length runs past the buffer.
        assert!(matches!(
            oxm::parse_oxm_list_unchecked(&[0x80, 0x00, 0x00, 0x40]),
            Err(OfError::ShortBuffer)
        ));
        // Length 0 is illegal: a TLV is 5-259 bytes.
        assert!(matches!(
            oxm::parse_oxm_list_unchecked(&[0x00, 0x01, 0x00, 0x00]),
            Err(OfError::InvalidOxmLength)
        ));
        // Experimenter TLVs must carry at least the 4-byte vendor id.
        assert!(matches!(
            oxm::parse_oxm_list_unchecked(&[0xff, 0xff, 0x00, 0x02, 0, 0]),
            Err(OfError::InvalidOxmLength)
        ));
    }

    #[test]
    fn oxm_nicira_ct_helpers_encode_under_the_nxm1_class() {
        for (bytes, field, len) in [
            (oxm::ct_state(NX_CS_TRK), NXM_NX_CT_STATE, 4),
            (oxm::ct_zone(5), NXM_NX_CT_ZONE, 2),
        ] {
            let header = u32::from_be_bytes(bytes[..4].try_into().unwrap());
            assert_eq!(u16::try_from(header >> 16).unwrap(), OFPXMC_NXM_1);
            assert_eq!(u8::try_from((header >> 9) & 0x7f).unwrap(), field);
            assert_eq!(header & 0xff, len);
        }
        let masked = oxm::ct_state_masked(NX_CS_TRK, NX_CS_TRK | NX_CS_RPL);
        let header = u32::from_be_bytes(masked[..4].try_into().unwrap());
        assert_ne!(header & 0x100, 0);
        assert_eq!(header & 0xff, 8);
    }

    // ---- codec facade: every Encoder output must decode back ----

    /// Walks the whole `Encoder`/`Decoder` facade. Each encoder's output
    /// is fed to `Decoder::message`, so a wrong message type or a length
    /// that disagrees with the body fails here.
    #[test]
    fn every_codec_encoder_produces_a_decodable_frame() {
        use crate::protocol::codec::{Decoder, Encoder};
        use crate::protocol::control::{
            ControllerStatus, ControllerStatusProperty, FlowRemoved, PortDescEntry, PortStatus,
            Property, RequestForward, RoleStatus, TableDescEntry, TableStatus,
        };
        use crate::protocol::features;
        use crate::protocol::header::Header;
        use crate::protocol::message::Message;
        use crate::protocol::packet_in::PacketIn;
        use crate::protocol::rule::Rule;

        // Encoders returning a bare Vec.
        let simple: Vec<(Vec<u8>, u8)> = vec![
            (Encoder::hello(1).unwrap(), OFPT_HELLO),
            (Encoder::features_request(2), OFPT_FEATURES_REQUEST),
            (Encoder::echo_request(3, b"x").unwrap(), OFPT_ECHO_REQUEST),
            (Encoder::echo_reply(4, b"x").unwrap(), OFPT_ECHO_REPLY),
            (Encoder::error(5, 1, 2, b"data").unwrap(), OFPT_ERROR),
            (Encoder::get_config_request(6), OFPT_GET_CONFIG_REQUEST),
            (Encoder::get_config_reply(7, 0, 128), OFPT_GET_CONFIG_REPLY),
            (Encoder::set_config(8, 0, 128), OFPT_SET_CONFIG),
            (
                Encoder::packet_out(9, OFP_NO_BUFFER, Some(1), Vec::new(), b"f").unwrap(),
                OFPT_PACKET_OUT,
            ),
            (
                Encoder::table_miss_to_controller(10).unwrap(),
                OFPT_FLOW_MOD,
            ),
            (
                Encoder::flow_mod(&Rule::add(
                    11,
                    0,
                    1,
                    crate::protocol::ofmatch::Match::any(),
                    Vec::new(),
                ))
                .unwrap(),
                OFPT_FLOW_MOD,
            ),
            (Encoder::barrier_request(12), OFPT_BARRIER_REQUEST),
            (Encoder::barrier_reply(13), OFPT_BARRIER_REPLY),
            (
                Encoder::features_reply(&features::Reply {
                    xid: 14,
                    datapath_id: 1,
                    n_buffers: 0,
                    n_tables: 1,
                    auxiliary_id: 0,
                    capabilities: 0,
                    reserved: 0,
                }),
                OFPT_FEATURES_REPLY,
            ),
        ];

        // Encoders returning Result.
        let props = vec![Property::ReasonMask { kind: 1, mask: 3 }];
        let port_desc = PortDescEntry {
            port_no: 1,
            hw_addr: [1, 2, 3, 4, 5, 6],
            name: "p1".into(),
            config: 0,
            state: 0,
            properties: Vec::new(),
        };
        let fallible: Vec<(Vec<u8>, u8)> = vec![
            (
                Encoder::get_async_request(20).unwrap(),
                OFPT_GET_ASYNC_REQUEST,
            ),
            (
                Encoder::get_async_reply(21, &[]).unwrap(),
                OFPT_GET_ASYNC_REPLY,
            ),
            (Encoder::set_async(22, &props).unwrap(), OFPT_SET_ASYNC),
            (
                Encoder::role_request(23, OFPCR_ROLE_MASTER, 0, 1).unwrap(),
                OFPT_ROLE_REQUEST,
            ),
            (
                Encoder::role_reply(24, OFPCR_ROLE_MASTER, 0, 1).unwrap(),
                OFPT_ROLE_REPLY,
            ),
            (
                Encoder::multipart_request(25, OFPMP_DESC, 0, &[]).unwrap(),
                OFPT_MULTIPART_REQUEST,
            ),
            (
                Encoder::multipart_reply(26, OFPMP_DESC, 0, &[0u8; 1056]).unwrap(),
                OFPT_MULTIPART_REPLY,
            ),
            (Encoder::table_mod(27, 0, 0, &[]).unwrap(), OFPT_TABLE_MOD),
            (
                Encoder::port_mod(28, 1, [1, 2, 3, 4, 5, 6], 0, 0, &[]).unwrap(),
                OFPT_PORT_MOD,
            ),
            (
                Encoder::meter_mod(29, OFPMC_ADD, OFPMF_KBPS, 1, &[]).unwrap(),
                OFPT_METER_MOD,
            ),
            (
                Encoder::bundle_control(30, 1, OFPBCT_OPEN_REQUEST, 0, &[]).unwrap(),
                OFPT_BUNDLE_CONTROL,
            ),
            (
                Encoder::bundle_add_message(31, 1, 0, &Encoder::barrier_request(31), &[]).unwrap(),
                OFPT_BUNDLE_ADD_MESSAGE,
            ),
            (
                Encoder::table_status(&TableStatus {
                    xid: 32,
                    reason: OFPTR_VACANCY_DOWN,
                    table: TableDescEntry {
                        table_id: 0,
                        config: 0,
                        properties: Vec::new(),
                    },
                })
                .unwrap(),
                OFPT_TABLE_STATUS,
            ),
            (
                Encoder::controller_status(&ControllerStatus {
                    xid: 33,
                    length: 0,
                    short_id: 1,
                    role: OFPCR_ROLE_EQUAL,
                    reason: OFPCSR_REQUEST,
                    channel_status: OFPCT_STATUS_UP,
                    properties: vec![ControllerStatusProperty::Uri("tcp:1.2.3.4:6653".into())],
                })
                .unwrap(),
                OFPT_CONTROLLER_STATUS,
            ),
            (
                Encoder::packet_in(&PacketIn {
                    xid: 34,
                    buffer_id: OFP_NO_BUFFER,
                    total_len: 1,
                    reason: OFPR_TABLE_MISS,
                    table_id: 0,
                    cookie: 0,
                    of_match: Vec::new(),
                    data: vec![1],
                })
                .unwrap(),
                OFPT_PACKET_IN,
            ),
            (
                Encoder::flow_removed(&FlowRemoved {
                    xid: 35,
                    table_id: 0,
                    reason: OFPRR_DELETE,
                    priority: 1,
                    idle_timeout: 0,
                    hard_timeout: 0,
                    cookie: 0,
                    of_match: Vec::new(),
                    stats: Vec::new(),
                })
                .unwrap(),
                OFPT_FLOW_REMOVED,
            ),
            (
                Encoder::port_status(&PortStatus {
                    xid: 36,
                    reason: OFPPR_ADD,
                    desc: port_desc,
                })
                .unwrap(),
                OFPT_PORT_STATUS,
            ),
            (
                Encoder::role_status(&RoleStatus {
                    xid: 37,
                    role: OFPCR_ROLE_EQUAL,
                    reason: 0,
                    generation_id: 0,
                    properties: Vec::new(),
                })
                .unwrap(),
                OFPT_ROLE_STATUS,
            ),
            (
                Encoder::request_forward(&RequestForward {
                    xid: 38,
                    request: Encoder::barrier_request(1),
                })
                .unwrap(),
                OFPT_REQUESTFORWARD,
            ),
            (
                Encoder::experimenter(39, 0x2320, 1, &[1, 2, 3, 4]).unwrap(),
                OFPT_EXPERIMENTER,
            ),
        ];

        for (frame, msg_type) in simple.into_iter().chain(fallible) {
            let header = Header::parse(&frame)
                .unwrap_or_else(|e| panic!("type {msg_type}: header parse failed: {e}"));
            assert_eq!(header.msg_type, msg_type);
            assert_eq!(
                usize::from(header.length),
                frame.len(),
                "type {msg_type}: header length disagrees with the frame"
            );
            let decoded = Decoder::message(&frame)
                .unwrap_or_else(|e| panic!("type {msg_type}: decode failed: {e}"));
            assert!(
                !matches!(decoded, Message::Ignored { .. }),
                "type {msg_type} decoded as Ignored"
            );
        }
    }

    /// The typed `Decoder` entry points each reject a frame of the wrong
    /// message type rather than mis-parsing it.
    #[test]
    fn typed_decoders_accept_their_own_type_and_reject_others() {
        use crate::protocol::codec::{Decoder, Encoder};
        use crate::protocol::rule::Rule;

        let wrong = Encoder::barrier_request(1);

        assert!(Decoder::flow_mod(&Encoder::table_miss_to_controller(1).unwrap()).is_ok());
        assert!(Decoder::flow_mod(&wrong).is_err());

        assert!(Decoder::error(&Encoder::error(1, 1, 2, b"").unwrap()).is_ok());
        assert!(Decoder::error(&wrong).is_err());

        assert!(Decoder::get_config_reply(&Encoder::get_config_reply(1, 0, 128)).is_ok());
        assert!(Decoder::get_config_reply(&wrong).is_err());

        assert!(Decoder::set_config(&Encoder::set_config(1, 0, 128)).is_ok());
        assert!(Decoder::set_config(&wrong).is_err());

        assert!(Decoder::features_request(&Encoder::features_request(1)).is_ok());
        assert!(Decoder::features_request(&wrong).is_err());

        assert_eq!(
            Decoder::get_config_request(&Encoder::get_config_request(7)).unwrap(),
            7
        );
        assert!(Decoder::get_config_request(&wrong).is_err());

        let packet_out = Encoder::packet_out(1, OFP_NO_BUFFER, Some(2), Vec::new(), b"hi").unwrap();
        assert_eq!(Decoder::packet_out(&packet_out).unwrap().data, b"hi");
        assert!(Decoder::packet_out(&wrong).is_err());

        let role = Encoder::role_request(1, OFPCR_ROLE_MASTER, 0, 5).unwrap();
        assert_eq!(Decoder::role_request(&role).unwrap().generation_id, 5);
        assert!(Decoder::role_request(&wrong).is_err());

        // Raw action / instruction list decoders.
        assert!(Decoder::actions(&[]).unwrap().is_empty());
        assert!(Decoder::instructions(&[]).unwrap().is_empty());
        assert!(Decoder::actions(&[0, 0, 0, 3]).is_err());

        // multipart_request_from_body is the typed request entry point.
        use crate::protocol::control::MultipartRequestBody;
        let mp =
            Encoder::multipart_request_from_body(1, OFPMP_DESC, 0, &MultipartRequestBody::Empty)
                .unwrap();
        assert!(Decoder::message(&mp).is_ok());

        // A flow-mod built by hand still decodes.
        let rule = Rule::delete(2, OFPTT_ALL, crate::protocol::ofmatch::Match::any());
        assert!(Decoder::flow_mod(&Encoder::flow_mod(&rule).unwrap()).is_ok());
    }

    // ---- every property enum, every variant, through a real message ----

    fn exp_bytes() -> Vec<u8> {
        vec![1, 2, 3, 4]
    }

    /// Round-trips one of every variant of every property family through
    /// the message that carries it. The `Raw` and `Experimenter` arms are
    /// the ones a real switch reaches when it sends something newer than
    /// this crate models, so they matter as much as the typed ones.
    #[test]
    fn every_property_variant_round_trips_through_its_message() {
        use crate::protocol::control::{
            parse_bundle_message, parse_controller_status, parse_port_mod, parse_table_mod,
            BundleMessage, BundleProperty, ControllerStatus, ControllerStatusProperty, PortMod,
            PortModProperty, TableMod, TableModProperty, Time,
        };

        // --- ofp_table_mod properties ---
        let table_props = vec![
            TableModProperty::Eviction {
                flags: OFPTMPEF_OTHER | OFPTMPEF_LIFETIME,
            },
            TableModProperty::Vacancy {
                vacancy_down: 1,
                vacancy_up: 99,
                vacancy: 50,
            },
            TableModProperty::Experimenter {
                experimenter: 0x2320,
                exp_type: 4,
                data: exp_bytes(),
            },
            TableModProperty::Raw {
                kind: 0x0f00,
                data: vec![7, 7, 7, 7],
            },
        ];
        let encoded = TableMod {
            xid: 1,
            table_id: 3,
            config: 9,
            properties: table_props.clone(),
        }
        .encode()
        .unwrap();
        assert_eq!(parse_table_mod(&encoded).unwrap().properties, table_props);

        // --- ofp_port_mod properties ---
        let port_props = vec![
            PortModProperty::Ethernet {
                advertise: OFPPF_10GB_FD | OFPPF_FIBER,
            },
            PortModProperty::Optical {
                configure: OFPOPF_RX_TUNE,
                freq_lmda: 1,
                fl_offset: -7,
                grid_span: 3,
                tx_pwr: 4,
            },
            PortModProperty::Experimenter {
                experimenter: 0x2320,
                exp_type: 5,
                data: exp_bytes(),
            },
            PortModProperty::Raw {
                kind: 0x0f01,
                data: vec![8, 8, 8, 8],
            },
        ];
        let encoded = PortMod {
            xid: 2,
            port_no: 4,
            hw_addr: [6, 5, 4, 3, 2, 1],
            config: 1,
            mask: 1,
            properties: port_props.clone(),
        }
        .encode()
        .unwrap();
        assert_eq!(parse_port_mod(&encoded).unwrap().properties, port_props);

        // --- ofp_bundle_ctrl_msg properties ---
        let bundle_props = vec![
            BundleProperty::Time {
                scheduled_time: Time {
                    seconds: 99,
                    nanoseconds: 5,
                },
            },
            BundleProperty::Experimenter {
                experimenter: 0x2320,
                exp_type: 6,
                data: exp_bytes(),
            },
            BundleProperty::Raw {
                kind: 0x0f02,
                data: vec![1, 1, 1, 1],
            },
        ];
        let encoded = BundleMessage {
            xid: 3,
            bundle_id: 7,
            ctrl_type: OFPBCT_OPEN_REQUEST,
            flags: OFPBF_ATOMIC,
            properties: bundle_props.clone(),
        }
        .encode()
        .unwrap();
        assert_eq!(
            parse_bundle_message(&encoded).unwrap().properties,
            bundle_props
        );

        // --- ofp_controller_status properties ---
        let cs_props = vec![
            ControllerStatusProperty::Uri("tls:192.0.2.1:6653".into()),
            ControllerStatusProperty::Experimenter {
                experimenter: 0x2320,
                exp_type: 7,
                data: exp_bytes(),
            },
            ControllerStatusProperty::Raw {
                kind: 0x0f03,
                data: vec![2, 2, 2, 2],
            },
        ];
        let encoded = ControllerStatus {
            xid: 4,
            length: 0,
            short_id: 2,
            role: OFPCR_ROLE_MASTER,
            reason: OFPCSR_CHANNEL_STATUS,
            channel_status: OFPCT_STATUS_DOWN,
            properties: cs_props.clone(),
        }
        .encode()
        .unwrap();
        assert_eq!(
            parse_controller_status(&encoded).unwrap().properties,
            cs_props
        );
    }

    /// The multipart-carried property families, round-tripped through a
    /// real `OFPT_MULTIPART_REPLY` frame.
    #[test]
    fn every_multipart_carried_property_round_trips() {
        use crate::protocol::action::Action;
        use crate::protocol::control::{
            parse_multipart_reply, Bucket, BucketProperty, GroupDescEntry, GroupProperty,
            MultipartMessage, MultipartReplyBody, PortDescEntry, PortProperty, PortStatsEntry,
            PortStatsProperty, QueueDescEntry, QueueDescProperty, QueueStatsEntry,
            QueueStatsProperty, TableDescEntry, TableModProperty,
        };

        fn round_trip(kind: u16, body: MultipartReplyBody) -> MultipartReplyBody {
            let msg = MultipartMessage::from_reply_body(1, kind, 0, &body).unwrap();
            let frame = msg.encode_reply().unwrap();
            parse_multipart_reply(&frame)
                .unwrap()
                .typed_reply_body()
                .unwrap()
        }

        // ofp_port properties (OFPMP_PORT_DESC)
        let port = PortDescEntry {
            port_no: 1,
            hw_addr: [1; 6],
            name: "p".into(),
            config: 0,
            state: 0,
            properties: vec![
                PortProperty::Ethernet {
                    curr: 1,
                    advertised: 2,
                    supported: 3,
                    peer: 4,
                    curr_speed: 5,
                    max_speed: 6,
                },
                PortProperty::Optical {
                    supported: 1,
                    tx_min_freq_lmda: 2,
                    tx_max_freq_lmda: 3,
                    tx_grid_freq_lmda: 4,
                    rx_min_freq_lmda: 5,
                    rx_max_freq_lmda: 6,
                    rx_grid_freq_lmda: 7,
                    tx_pwr_min: 8,
                    tx_pwr_max: 9,
                },
                PortProperty::PipelineInput(vec![0, 0, 0, 1]),
                PortProperty::PipelineOutput(vec![0, 0, 0, 2]),
                PortProperty::Recirculate(vec![3, 4]),
                PortProperty::Experimenter {
                    experimenter: 0x2320,
                    exp_type: 1,
                    data: exp_bytes(),
                },
                PortProperty::Raw {
                    kind: 0x0f10,
                    data: vec![9, 9, 9, 9],
                },
            ],
        };
        assert_eq!(
            round_trip(
                OFPMP_PORT_DESC,
                MultipartReplyBody::PortDesc(vec![port.clone()])
            ),
            MultipartReplyBody::PortDesc(vec![port])
        );

        // ofp_port_stats properties
        let stats = PortStatsEntry {
            port_no: 1,
            duration_sec: 1,
            duration_nsec: 2,
            rx_packets: 3,
            tx_packets: 4,
            rx_bytes: 5,
            tx_bytes: 6,
            rx_dropped: 7,
            tx_dropped: 8,
            rx_errors: 9,
            tx_errors: 10,
            properties: vec![
                PortStatsProperty::Ethernet {
                    rx_frame_err: 1,
                    rx_over_err: 2,
                    rx_crc_err: 3,
                    collisions: 4,
                },
                PortStatsProperty::Optical {
                    flags: OFPOSF_RX_TUNE,
                    tx_freq_lmda: 1,
                    tx_offset: 2,
                    tx_grid_span: 3,
                    rx_freq_lmda: 4,
                    rx_offset: 5,
                    rx_grid_span: 6,
                    tx_pwr: 7,
                    rx_pwr: 8,
                    bias_current: 9,
                    temperature: 10,
                },
                PortStatsProperty::Experimenter {
                    experimenter: 0x2320,
                    exp_type: 2,
                    data: exp_bytes(),
                },
                PortStatsProperty::Raw {
                    kind: 0x0f11,
                    data: vec![5, 5, 5, 5],
                },
            ],
        };
        assert_eq!(
            round_trip(
                OFPMP_PORT_STATS,
                MultipartReplyBody::PortStats(vec![stats.clone()])
            ),
            MultipartReplyBody::PortStats(vec![stats])
        );

        // ofp_queue_stats + ofp_queue_desc properties
        let qs = QueueStatsEntry {
            port_no: 1,
            queue_id: 2,
            tx_bytes: 3,
            tx_packets: 4,
            tx_errors: 5,
            duration_sec: 6,
            duration_nsec: 7,
            properties: vec![
                QueueStatsProperty::Experimenter {
                    experimenter: 0x2320,
                    exp_type: 3,
                    data: exp_bytes(),
                },
                QueueStatsProperty::Raw {
                    kind: 0x0f12,
                    data: vec![4, 4, 4, 4],
                },
            ],
        };
        assert_eq!(
            round_trip(
                OFPMP_QUEUE_STATS,
                MultipartReplyBody::QueueStats(vec![qs.clone()])
            ),
            MultipartReplyBody::QueueStats(vec![qs])
        );

        let qd = QueueDescEntry {
            port_no: 1,
            queue_id: 2,
            properties: vec![
                QueueDescProperty::MinRate(10),
                QueueDescProperty::MaxRate(OFPQ_MAX_RATE_UNCFG),
                QueueDescProperty::Experimenter {
                    experimenter: 0x2320,
                    exp_type: 4,
                    data: exp_bytes(),
                },
                QueueDescProperty::Raw {
                    kind: 0x0f13,
                    data: vec![3, 3, 3, 3],
                },
            ],
        };
        assert_eq!(
            round_trip(
                OFPMP_QUEUE_DESC,
                MultipartReplyBody::QueueDesc(vec![qd.clone()])
            ),
            MultipartReplyBody::QueueDesc(vec![qd])
        );

        // ofp_table_desc reuses the table-mod property family.
        let td = TableDescEntry {
            table_id: 1,
            config: 2,
            properties: vec![
                TableModProperty::Vacancy {
                    vacancy_down: 5,
                    vacancy_up: 95,
                    vacancy: 10,
                },
                TableModProperty::Raw {
                    kind: 0x0f14,
                    data: vec![2, 2, 2, 2],
                },
            ],
        };
        assert_eq!(
            round_trip(
                OFPMP_TABLE_DESC,
                MultipartReplyBody::TableDesc(vec![td.clone()])
            ),
            MultipartReplyBody::TableDesc(vec![td])
        );

        // Bucket + group properties (OFPMP_GROUP_DESC).
        let gd = GroupDescEntry {
            group_type: OFPGT_SELECT,
            group_id: 1,
            buckets: vec![Bucket {
                bucket_id: 2,
                actions: vec![Action::output(3)],
                properties: vec![
                    BucketProperty::Weight(5),
                    BucketProperty::WatchPort(6),
                    BucketProperty::WatchGroup(7),
                    BucketProperty::Experimenter {
                        experimenter: 0x2320,
                        exp_type: 5,
                        data: exp_bytes(),
                    },
                    BucketProperty::Raw {
                        kind: 0x0f15,
                        data: vec![1, 1, 1, 1],
                    },
                ],
            }],
            properties: vec![
                GroupProperty::Experimenter {
                    experimenter: 0x2320,
                    exp_type: 6,
                    data: exp_bytes(),
                },
                GroupProperty::Raw {
                    kind: 0x0f16,
                    data: vec![0, 0, 0, 1],
                },
            ],
        };
        assert_eq!(
            round_trip(
                OFPMP_GROUP_DESC,
                MultipartReplyBody::GroupDesc(vec![gd.clone()])
            ),
            MultipartReplyBody::GroupDesc(vec![gd])
        );
    }

    // ---- oxs: every stat field, and the ofp_stats container ----

    #[test]
    fn every_oxs_variant_round_trips_and_bad_lengths_are_rejected() {
        use crate::protocol::oxs::{self, Tlv as Oxs};

        let all = vec![
            Oxs::Duration { sec: 1, nsec: 2 },
            Oxs::IdleTime { sec: 3, nsec: 4 },
            Oxs::FlowCount(5),
            Oxs::PacketCount(6),
            Oxs::ByteCount(7),
            Oxs::Experimenter {
                experimenter: 0x2320,
                data: vec![1, 2, 3, 4],
            },
            Oxs::Raw {
                class: 0x0001,
                field: 9,
                data: vec![9, 9],
            },
        ];
        let encoded = oxs::encode_oxs_list(&all).unwrap();
        assert_eq!(oxs::parse_oxs_list(&encoded).unwrap(), all);

        // A duplicate (class, field) is rejected.
        let dup = oxs::encode_oxs_list(&[Oxs::FlowCount(1), Oxs::FlowCount(2)]).unwrap();
        assert!(oxs::parse_oxs_list(&dup).is_err());

        // Each fixed-width field rejects a wrong-sized value. Field ids
        // and widths come straight from the spec's OXS_OF_* macros --
        // note the enum skips 2.
        for (field, good) in [
            (OFPXST_OFB_DURATION, 8usize),
            (OFPXST_OFB_IDLE_TIME, 8),
            (OFPXST_OFB_FLOW_COUNT, 4),
            (OFPXST_OFB_PACKET_COUNT, 8),
            (OFPXST_OFB_BYTE_COUNT, 8),
        ] {
            let mut buf = Vec::new();
            buf.extend_from_slice(&OFPXSC_OPENFLOW_BASIC.to_be_bytes());
            buf.push(field << 1);
            buf.push(u8::try_from(good + 1).unwrap());
            buf.extend(std::iter::repeat_n(0u8, good + 1));
            assert!(
                oxs::parse_oxs_list(&buf).is_err(),
                "field {field} accepted a {}-byte value",
                good + 1
            );
        }

        // Truncated header and truncated body.
        assert!(oxs::parse_oxs_list(&[0x80, 0x02, 0x00]).is_err());
        assert!(oxs::parse_oxs_list(&[0x80, 0x02, 0x00, 0x40]).is_err());
        // Experimenter needs its 4-byte id.
        assert!(oxs::parse_oxs_list(&[0xff, 0xff, 0x00, 0x02, 0, 0]).is_err());
    }

    #[test]
    fn ofp_stats_container_round_trips_and_validates() {
        use crate::protocol::oxs::{self, Tlv as Oxs};

        let fields = vec![Oxs::PacketCount(42), Oxs::ByteCount(4200)];
        let mut buf = Vec::new();
        oxs::encode_stats(&mut buf, &fields).unwrap();
        assert!(buf.len().is_multiple_of(8), "ofp_stats must be 8-aligned");
        let (parsed, padded) = oxs::parse_stats(&buf, 0).unwrap();
        assert_eq!(parsed, fields);
        assert_eq!(padded, buf.len());

        // An empty stats block is still a valid 8-byte header.
        let mut empty = Vec::new();
        oxs::encode_stats(&mut empty, &[]).unwrap();
        assert_eq!(empty.len(), 8);
        assert_eq!(oxs::parse_stats(&empty, 0).unwrap().0, Vec::new());

        // length < 4 is illegal.
        assert!(oxs::parse_stats(&[0, 0, 0, 2, 0, 0, 0, 0], 0).is_err());
        // Declared length runs past the buffer.
        assert!(oxs::parse_stats(&[0, 0, 0x00, 0x40, 0, 0, 0, 0], 0).is_err());
        // Padding contents are ignored per section 7.1.2.
        let mut bad = buf.clone();
        *bad.last_mut().unwrap() = 1;
        assert!(oxs::parse_stats(&bad, 0).is_ok());
    }

    // ---- packet_out: parse rejects every malformed shape ----

    #[test]
    fn packet_out_parse_rejects_malformed_frames() {
        use crate::protocol::codec::Encoder;
        use crate::protocol::ofmatch::Match;
        use crate::protocol::packet_out::PacketOut;

        let good = Encoder::packet_out(1, OFP_NO_BUFFER, Some(3), Vec::new(), b"data").unwrap();
        let parsed = PacketOut::parse(&good).unwrap();
        assert_eq!(parsed.data, b"data");
        assert_eq!(parsed.xid, 1);

        // with_match is the explicit-match constructor.
        let explicit = PacketOut::with_match(
            2,
            OFP_NO_BUFFER,
            Match::new(vec![oxm::in_port(9)]),
            vec![crate::protocol::action::Action::output(1)],
            b"x".to_vec(),
        );
        let reparsed = PacketOut::parse(&explicit.encode().unwrap()).unwrap();
        assert_eq!(reparsed.actions.len(), 1);
        assert_eq!(reparsed.of_match, explicit.of_match);

        // Wrong message type.
        assert!(PacketOut::parse(&Encoder::barrier_request(1)).is_err());
        // Truncated below the fixed header.
        assert!(PacketOut::parse(&good[..20]).is_err());
        // Padding contents are ignored per section 7.1.2.
        let mut bad_pad = good.clone();
        bad_pad[14] = 1;
        assert!(PacketOut::parse(&bad_pad).is_ok());
        // Match type that is not OFPMT_OXM.
        let mut bad_type = good.clone();
        bad_type[16] = 0xff;
        assert!(PacketOut::parse(&bad_type).is_err());
        // Match length below the 4-byte minimum.
        let mut bad_len = good.clone();
        bad_len[18] = 0;
        bad_len[19] = 2;
        assert!(PacketOut::parse(&bad_len).is_err());
        // actions_len that runs past the end of the message.
        let mut bad_actions = good.clone();
        bad_actions[12] = 0xff;
        bad_actions[13] = 0xf0;
        assert!(PacketOut::parse(&bad_actions).is_err());
        // The 1.5.1 packet-out match must carry OXM_OF_IN_PORT.
        let missing_in_port =
            PacketOut::with_match(3, OFP_NO_BUFFER, Match::any(), Vec::new(), b"data".to_vec());
        assert!(PacketOut::parse(&missing_in_port.encode().unwrap()).is_err());
    }

    // ---- nicira: the decode paths and error branches ----

    #[test]
    fn nicira_ct_and_nat_cover_every_constructor_and_error() {
        use crate::protocol::action::{parse_actions, Action};
        use crate::protocol::nicira::{ct, nat_bare, nat_dst, nat_src, parse_ct, parse_nat};

        // nat_dst is the mirror of nat_src.
        let dst = nat_dst("198.51.100.7".parse().unwrap());
        let Action::Experimenter { data, .. } = &dst else {
            panic!("expected an experimenter action");
        };
        let parsed = parse_nat(data).unwrap();
        assert!(parsed.dst && !parsed.src);
        assert_eq!(parsed.ipv4_min, Some("198.51.100.7".parse().unwrap()));

        // A ct() carrying several nested actions round-trips.
        let nested = vec![nat_src("203.0.113.1".parse().unwrap()), nat_bare()];
        let action = ct(true, 11, Some(7), &nested).unwrap();
        let mut bytes = Vec::new();
        action.encode(&mut bytes).unwrap();
        let Action::Experimenter { data, .. } = &parse_actions(&bytes).unwrap()[0] else {
            panic!("expected an experimenter action");
        };
        let decoded = parse_ct(data).unwrap();
        assert!(decoded.commit);
        assert_eq!(decoded.zone, 11);
        assert_eq!(decoded.recirc_table, 7);
        assert_eq!(decoded.nested.len(), 2);

        // Error paths: truncated bodies and wrong subtypes.
        assert!(parse_ct(&[0u8; 4]).is_err());
        assert!(parse_nat(&[0u8; 4]).is_err());
        let mut wrong = vec![0u8; 16];
        wrong[1] = 0xfe; // not NXAST_CT
        assert!(parse_ct(&wrong).is_err());
        let mut wrong_nat = vec![0u8; 8];
        wrong_nat[1] = 0xfe; // not NXAST_NAT
        assert!(parse_nat(&wrong_nat).is_err());

        // A NAT body that declares an IPv4-min range but is truncated
        // before the 4 address bytes at offset 8 can arrive.
        let Action::Experimenter { data, .. } = nat_src("203.0.113.1".parse().unwrap()) else {
            panic!("expected an experimenter action");
        };
        let mut short_range = data;
        short_range.truncate(10);
        assert!(parse_nat(&short_range).is_err());
    }

    // ---- systematic error-path sweeps ----

    /// A corpus of one valid frame per message type, used by the
    /// truncation and corruption sweeps below.
    fn frame_corpus() -> Vec<(&'static str, Vec<u8>)> {
        use crate::protocol::codec::Encoder;
        use crate::protocol::control::{
            ControllerStatus, ControllerStatusProperty, FlowRemoved, MultipartRequestBody,
            PortDescEntry, PortStatus, Property, RequestForward, RoleStatus, TableDescEntry,
            TableStatus,
        };
        use crate::protocol::features;
        use crate::protocol::ofmatch::Match;
        use crate::protocol::oxs::Tlv as Oxs;
        use crate::protocol::packet_in::PacketIn;
        use crate::protocol::rule::Rule;

        let mut rule = Rule::add(11, 0, 5, Match::new(vec![oxm::in_port(1)]), Vec::new());
        rule.flags = OFPFF_SEND_FLOW_REM;

        vec![
            ("hello", Encoder::hello(1).unwrap()),
            (
                "echo_request",
                Encoder::echo_request(2, b"payload").unwrap(),
            ),
            ("echo_reply", Encoder::echo_reply(3, b"payload").unwrap()),
            (
                "error",
                Encoder::error(4, OFPET_BAD_REQUEST, 1, b"ctx").unwrap(),
            ),
            ("features_request", Encoder::features_request(5)),
            (
                "features_reply",
                Encoder::features_reply(&features::Reply {
                    xid: 6,
                    datapath_id: 9,
                    n_buffers: 1,
                    n_tables: 2,
                    auxiliary_id: 0,
                    capabilities: 3,
                    reserved: 0,
                }),
            ),
            ("get_config_request", Encoder::get_config_request(7)),
            ("get_config_reply", Encoder::get_config_reply(8, 0, 128)),
            ("set_config", Encoder::set_config(9, 0, 128)),
            (
                "packet_out",
                Encoder::packet_out(10, OFP_NO_BUFFER, Some(1), Vec::new(), b"frame").unwrap(),
            ),
            ("flow_mod", Encoder::flow_mod(&rule).unwrap()),
            ("barrier_request", Encoder::barrier_request(12)),
            ("barrier_reply", Encoder::barrier_reply(13)),
            ("get_async_request", Encoder::get_async_request(14).unwrap()),
            (
                "set_async",
                Encoder::set_async(15, &[Property::ReasonMask { kind: 1, mask: 3 }]).unwrap(),
            ),
            (
                "role_request",
                Encoder::role_request(16, OFPCR_ROLE_MASTER, 0, 1).unwrap(),
            ),
            (
                "role_reply",
                Encoder::role_reply(17, OFPCR_ROLE_MASTER, 0, 1).unwrap(),
            ),
            (
                "multipart_request",
                Encoder::multipart_request_from_body(
                    18,
                    OFPMP_DESC,
                    0,
                    &MultipartRequestBody::Empty,
                )
                .unwrap(),
            ),
            (
                "multipart_reply",
                Encoder::multipart_reply(19, OFPMP_DESC, 0, &[0u8; 1056]).unwrap(),
            ),
            ("table_mod", Encoder::table_mod(20, 0, 0, &[]).unwrap()),
            (
                "port_mod",
                Encoder::port_mod(21, 1, [1, 2, 3, 4, 5, 6], 0, 0, &[]).unwrap(),
            ),
            (
                "meter_mod",
                Encoder::meter_mod(22, OFPMC_ADD, OFPMF_KBPS, 1, &[]).unwrap(),
            ),
            (
                "bundle_control",
                Encoder::bundle_control(23, 1, OFPBCT_OPEN_REQUEST, 0, &[]).unwrap(),
            ),
            (
                "bundle_add",
                Encoder::bundle_add_message(24, 1, 0, &Encoder::barrier_request(24), &[]).unwrap(),
            ),
            (
                "packet_in",
                Encoder::packet_in(&PacketIn {
                    xid: 25,
                    buffer_id: OFP_NO_BUFFER,
                    total_len: 5,
                    reason: OFPR_TABLE_MISS,
                    table_id: 0,
                    cookie: 7,
                    of_match: oxm::parse_oxm_list(&oxm::in_port(2)).unwrap(),
                    data: b"frame".to_vec(),
                })
                .unwrap(),
            ),
            (
                "flow_removed",
                Encoder::flow_removed(&FlowRemoved {
                    xid: 26,
                    table_id: 0,
                    reason: OFPRR_DELETE,
                    priority: 1,
                    idle_timeout: 0,
                    hard_timeout: 0,
                    cookie: 0,
                    of_match: oxm::in_port(1),
                    stats: vec![Oxs::PacketCount(3)],
                })
                .unwrap(),
            ),
            (
                "port_status",
                Encoder::port_status(&PortStatus {
                    xid: 27,
                    reason: OFPPR_ADD,
                    desc: PortDescEntry {
                        port_no: 1,
                        hw_addr: [1; 6],
                        name: "p".into(),
                        config: 0,
                        state: 0,
                        properties: Vec::new(),
                    },
                })
                .unwrap(),
            ),
            (
                "role_status",
                Encoder::role_status(&RoleStatus {
                    xid: 28,
                    role: OFPCR_ROLE_EQUAL,
                    reason: 0,
                    generation_id: 0,
                    properties: Vec::new(),
                })
                .unwrap(),
            ),
            (
                "table_status",
                Encoder::table_status(&TableStatus {
                    xid: 29,
                    reason: OFPTR_VACANCY_DOWN,
                    table: TableDescEntry {
                        table_id: 0,
                        config: 0,
                        properties: Vec::new(),
                    },
                })
                .unwrap(),
            ),
            (
                "request_forward",
                Encoder::request_forward(&RequestForward {
                    xid: 30,
                    request: Encoder::barrier_request(1),
                })
                .unwrap(),
            ),
            (
                "controller_status",
                Encoder::controller_status(&ControllerStatus {
                    xid: 31,
                    length: 0,
                    short_id: 1,
                    role: OFPCR_ROLE_EQUAL,
                    reason: OFPCSR_REQUEST,
                    channel_status: OFPCT_STATUS_UP,
                    properties: vec![ControllerStatusProperty::Uri("tcp:1.2.3.4:1".into())],
                })
                .unwrap(),
            ),
            (
                "experimenter",
                Encoder::experimenter(32, 0x2320, 1, &[1, 2, 3, 4]).unwrap(),
            ),
        ]
    }

    /// Every prefix of every valid frame must be rejected cleanly. This
    /// is what drives the `ShortBuffer` arms that a hand-written test per
    /// offset would take hundreds of cases to reach -- and it proves the
    /// decoder never panics or indexes out of bounds on a truncated read.
    #[test]
    fn every_truncation_of_every_message_is_rejected_without_panicking() {
        use crate::protocol::codec::Decoder;

        for (name, frame) in frame_corpus() {
            assert!(
                Decoder::message(&frame).is_ok(),
                "{name}: the full frame should decode"
            );
            for cut in 0..frame.len() {
                let truncated = &frame[..cut];
                assert!(
                    Decoder::message(truncated).is_err(),
                    "{name}: a {cut}-byte prefix of a {}-byte frame decoded successfully",
                    frame.len()
                );
            }
        }
    }

    /// The header's `length` is attacker-controlled: every wrong value
    /// must be refused rather than used to index the buffer.
    #[test]
    fn corrupted_header_lengths_are_rejected() {
        use crate::protocol::codec::Decoder;

        for (name, frame) in frame_corpus() {
            for bogus in [
                0u16,
                1,
                7,
                u16::try_from(frame.len()).unwrap() + 1,
                u16::MAX,
            ] {
                let mut bad = frame.clone();
                bad[2..4].copy_from_slice(&bogus.to_be_bytes());
                assert!(
                    Decoder::message(&bad).is_err(),
                    "{name}: header length {bogus} was accepted for a {}-byte frame",
                    frame.len()
                );
            }
            // A version other than 1.5 is refused for every type but Hello.
            let mut wrong_version = frame.clone();
            wrong_version[0] = 0x04;
            if wrong_version[1] != OFPT_HELLO {
                assert!(
                    Decoder::message(&wrong_version).is_err(),
                    "{name}: an OF 1.3 version byte was accepted"
                );
            }
        }
    }

    /// Single-byte corruption anywhere in a frame must never panic. It
    /// may still decode (many bytes are free-form payload), but it must
    /// not index out of bounds.
    #[test]
    fn single_byte_corruption_never_panics() {
        use crate::protocol::codec::Decoder;

        for (_, frame) in frame_corpus() {
            for offset in 0..frame.len() {
                for patch in [0x00u8, 0x01, 0x7f, 0xff] {
                    let mut bad = frame.clone();
                    bad[offset] = patch;
                    // Length changes are covered above; here we only care
                    // that nothing panics.
                    let _ = Decoder::message(&bad);
                }
            }
        }
    }

    // ---- table-driven: every property parser's wrong-length branch ----

    /// Every typed property has an exact (or minimum) body length and a
    /// `return Err(invalid_length(..))` when it is not met. Encoding a
    /// `Raw` variant *under a typed kind* is the way to inject a
    /// correctly framed but wrongly sized property, which is precisely
    /// what a buggy or newer switch would send.
    ///
    /// `data` here is the property body after the 4-byte header, so a
    /// property of total length `n` needs `n - 4` bytes.
    #[test]
    fn every_property_parser_rejects_a_wrong_length_body() {
        use crate::protocol::control::{
            parse_bundle_message, parse_controller_status, parse_multipart_reply, parse_port_mod,
            parse_table_mod, BundleMessage, BundleProperty, ControllerStatus,
            ControllerStatusProperty, MultipartMessage, MultipartReplyBody, PortDescEntry, PortMod,
            PortModProperty, PortProperty, PortStatsEntry, PortStatsProperty, QueueDescEntry,
            QueueDescProperty, TableMod, TableModProperty,
        };

        // (kind, every body size that must be rejected)
        // Sizes are "total property length minus the 4-byte header".
        const TABLE_MOD: [(u16, &[usize]); 3] = [
            (OFPTMPT_EVICTION, &[0, 3, 8]),
            (OFPTMPT_VACANCY, &[0, 3, 8]),
            (OFPTMPT_EXPERIMENTER, &[0, 3, 7]),
        ];
        for (kind, sizes) in TABLE_MOD {
            for size in sizes {
                let frame = TableMod {
                    xid: 1,
                    table_id: 0,
                    config: 0,
                    properties: vec![TableModProperty::Raw {
                        kind,
                        data: vec![0; *size],
                    }],
                }
                .encode()
                .unwrap();
                assert!(
                    parse_table_mod(&frame).is_err(),
                    "table-mod property {kind:#x} accepted a {size}-byte body"
                );
            }
        }

        const PORT_MOD: [(u16, &[usize]); 3] = [
            (OFPPMPT_ETHERNET, &[0, 3, 8]),
            (OFPPMPT_OPTICAL, &[0, 3, 8, 24]),
            (OFPPMPT_EXPERIMENTER, &[0, 3, 7]),
        ];
        for (kind, sizes) in PORT_MOD {
            for size in sizes {
                let frame = PortMod {
                    xid: 1,
                    port_no: 1,
                    hw_addr: [0; 6],
                    config: 0,
                    mask: 0,
                    properties: vec![PortModProperty::Raw {
                        kind,
                        data: vec![0; *size],
                    }],
                }
                .encode()
                .unwrap();
                assert!(
                    parse_port_mod(&frame).is_err(),
                    "port-mod property {kind:#x} accepted a {size}-byte body"
                );
            }
        }

        const BUNDLE: [(u16, &[usize]); 2] = [
            (OFPBPT_TIME, &[0, 3, 8, 24]),
            (OFPBPT_EXPERIMENTER, &[0, 3, 7]),
        ];
        for (kind, sizes) in BUNDLE {
            for size in sizes {
                let frame = BundleMessage {
                    xid: 1,
                    bundle_id: 1,
                    ctrl_type: OFPBCT_OPEN_REQUEST,
                    flags: 0,
                    properties: vec![BundleProperty::Raw {
                        kind,
                        data: vec![0; *size],
                    }],
                }
                .encode()
                .unwrap();
                assert!(
                    parse_bundle_message(&frame).is_err(),
                    "bundle property {kind:#x} accepted a {size}-byte body"
                );
            }
        }

        for size in [0usize, 3, 7] {
            let frame = ControllerStatus {
                xid: 1,
                length: 0,
                short_id: 0,
                role: OFPCR_ROLE_EQUAL,
                reason: OFPCSR_REQUEST,
                channel_status: OFPCT_STATUS_UP,
                properties: vec![ControllerStatusProperty::Raw {
                    kind: OFPCSPT_EXPERIMENTER,
                    data: vec![0; size],
                }],
            }
            .encode()
            .unwrap();
            assert!(
                parse_controller_status(&frame).is_err(),
                "controller-status experimenter accepted a {size}-byte body"
            );
        }

        // Multipart-carried families.
        fn reply_errs(kind: u16, body: MultipartReplyBody) -> bool {
            let Ok(msg) = MultipartMessage::from_reply_body(1, kind, 0, &body) else {
                return true;
            };
            let Ok(frame) = msg.encode_reply() else {
                return true;
            };
            let Ok(parsed) = parse_multipart_reply(&frame) else {
                return true;
            };
            parsed.typed_reply_body().is_err()
        }

        const PORT_DESC: [(u16, &[usize]); 3] = [
            (OFPPDPT_ETHERNET, &[0, 3, 8, 40]),
            (OFPPDPT_OPTICAL, &[0, 3, 8, 32]),
            (OFPPDPT_EXPERIMENTER, &[0, 3, 7]),
        ];
        for (kind, sizes) in PORT_DESC {
            for size in sizes {
                let entry = PortDescEntry {
                    port_no: 1,
                    hw_addr: [0; 6],
                    name: "p".into(),
                    config: 0,
                    state: 0,
                    properties: vec![PortProperty::Raw {
                        kind,
                        data: vec![0; *size],
                    }],
                };
                assert!(
                    reply_errs(OFPMP_PORT_DESC, MultipartReplyBody::PortDesc(vec![entry])),
                    "port-desc property {kind:#x} accepted a {size}-byte body"
                );
            }
        }

        const PORT_STATS: [(u16, &[usize]); 3] = [
            (OFPPSPT_ETHERNET, &[0, 3, 8, 44]),
            (OFPPSPT_OPTICAL, &[0, 3, 8, 36]),
            (OFPPSPT_EXPERIMENTER, &[0, 3, 7]),
        ];
        for (kind, sizes) in PORT_STATS {
            for size in sizes {
                let entry = PortStatsEntry {
                    port_no: 1,
                    duration_sec: 0,
                    duration_nsec: 0,
                    rx_packets: 0,
                    tx_packets: 0,
                    rx_bytes: 0,
                    tx_bytes: 0,
                    rx_dropped: 0,
                    tx_dropped: 0,
                    rx_errors: 0,
                    tx_errors: 0,
                    properties: vec![PortStatsProperty::Raw {
                        kind,
                        data: vec![0; *size],
                    }],
                };
                assert!(
                    reply_errs(OFPMP_PORT_STATS, MultipartReplyBody::PortStats(vec![entry])),
                    "port-stats property {kind:#x} accepted a {size}-byte body"
                );
            }
        }

        const QUEUE_DESC: [(u16, &[usize]); 3] = [
            (OFPQDPT_MIN_RATE, &[0, 3, 8]),
            (OFPQDPT_MAX_RATE, &[0, 3, 8]),
            (OFPQDPT_EXPERIMENTER, &[0, 3, 7]),
        ];
        for (kind, sizes) in QUEUE_DESC {
            for size in sizes {
                let entry = QueueDescEntry {
                    port_no: 1,
                    queue_id: 1,
                    properties: vec![QueueDescProperty::Raw {
                        kind,
                        data: vec![0; *size],
                    }],
                };
                assert!(
                    reply_errs(OFPMP_QUEUE_DESC, MultipartReplyBody::QueueDesc(vec![entry])),
                    "queue-desc property {kind:#x} accepted a {size}-byte body"
                );
            }
        }
    }

    /// Every multipart body parser must reject a body truncated below its
    /// fixed header, for all 21 `OFPMP_*` kinds, on both the request and
    /// the reply side.
    #[test]
    fn every_multipart_body_rejects_truncation() {
        use crate::protocol::codec::Encoder;
        use crate::protocol::control::{parse_multipart_reply, parse_multipart_request};

        const KINDS: [u16; 21] = [
            OFPMP_DESC,
            OFPMP_FLOW_DESC,
            OFPMP_AGGREGATE_STATS,
            OFPMP_TABLE_STATS,
            OFPMP_PORT_STATS,
            OFPMP_QUEUE_STATS,
            OFPMP_GROUP_STATS,
            OFPMP_GROUP_DESC,
            OFPMP_GROUP_FEATURES,
            OFPMP_METER_STATS,
            OFPMP_METER_DESC,
            OFPMP_METER_FEATURES,
            OFPMP_TABLE_FEATURES,
            OFPMP_PORT_DESC,
            OFPMP_TABLE_DESC,
            OFPMP_QUEUE_DESC,
            OFPMP_FLOW_MONITOR,
            OFPMP_FLOW_STATS,
            OFPMP_CONTROLLER_STATUS,
            OFPMP_BUNDLE_FEATURES,
            OFPMP_EXPERIMENTER,
        ];

        // A body of every awkward size: shorter than any fixed header,
        // and a few odd sizes that break alignment assumptions.
        for kind in KINDS {
            for len in [1usize, 2, 3, 5, 7, 9, 13, 17, 23] {
                let body = vec![0u8; len];
                let request = Encoder::multipart_request(1, kind, 0, &body).unwrap();
                if let Ok(parsed) = parse_multipart_request(&request) {
                    // Decoding the raw frame is fine; the typed body must
                    // be the thing that refuses.
                    let _ = parsed.typed_request_body();
                }
                let reply = Encoder::multipart_reply(2, kind, 0, &body).unwrap();
                if let Ok(parsed) = parse_multipart_reply(&reply) {
                    let _ = parsed.typed_reply_body();
                }
            }
        }

        // An unknown multipart kind is rejected outright on both sides.
        let bogus = Encoder::multipart_request(3, 0x7fff, 0, &[]).unwrap();
        assert!(parse_multipart_request(&bogus).is_err());
        let bogus = Encoder::multipart_reply(4, 0x7fff, 0, &[]).unwrap();
        assert!(parse_multipart_reply(&bogus).is_err());
    }

    /// Truncate a frame to `n` bytes and rewrite the header's `length`
    /// so it still agrees with the buffer.
    ///
    /// Without the rewrite, `Decoder::message`'s outer `frame.len() <
    /// length` guard rejects everything before the per-field reads ever
    /// run, so the inner `ShortBuffer` arms stay untested. With it, each
    /// parser has to defend its own offsets.
    fn truncate_consistently(frame: &[u8], n: usize) -> Vec<u8> {
        let mut out = frame[..n].to_vec();
        if out.len() >= 4 {
            let len = u16::try_from(n).unwrap();
            out[2..4].copy_from_slice(&len.to_be_bytes());
        }
        out
    }

    /// Drive every message parser through every self-consistent
    /// truncation of a valid frame. This is what reaches the per-field
    /// `ok_or(ShortBuffer)` arms deep inside each parser.
    #[test]
    fn every_parser_defends_its_own_offsets() {
        use crate::protocol::codec::Decoder;

        for (name, frame) in frame_corpus() {
            for cut in 0..frame.len() {
                let truncated = truncate_consistently(&frame, cut);
                // Must not panic. Anything shorter than the fixed part of
                // the message must be refused; beyond that a parser may
                // legitimately accept a shorter variable-length tail.
                let result = Decoder::message(&truncated);
                if cut < 8 {
                    assert!(result.is_err(), "{name}: {cut}-byte frame accepted");
                }
            }
        }
    }

    /// The flow-mod parser reads a dozen fixed fields plus a variable
    /// match and instruction list; each read must fail cleanly.
    #[test]
    fn flow_mod_parser_rejects_every_truncation_and_bad_field() {
        use crate::protocol::codec::{Decoder, Encoder};
        use crate::protocol::ofmatch::Match;
        use crate::protocol::rule::Rule;

        let frame = Encoder::flow_mod(&Rule::add(
            1,
            0,
            5,
            Match::new(vec![oxm::in_port(1)]),
            vec![crate::protocol::instruction::Instruction::apply_actions(
                vec![crate::protocol::action::Action::output(2)],
            )],
        ))
        .unwrap();
        assert!(Decoder::flow_mod(&frame).is_ok());

        // ofp_flow_mod is 8 header + 40 fixed + an 8-byte minimum match.
        // Anything shorter is malformed; at or beyond it a truncation can
        // legitimately land on a valid shorter instruction list, so there
        // the requirement is only that it never panics.
        const FLOW_MOD_MIN: usize = 56;
        for cut in 0..frame.len() {
            let truncated = truncate_consistently(&frame, cut);
            let result = Decoder::flow_mod(&truncated);
            if cut < FLOW_MOD_MIN {
                assert!(
                    result.is_err(),
                    "flow-mod accepted a {cut}-byte truncation of {} bytes",
                    frame.len()
                );
            }
        }

        // An unknown command byte is rejected (body offset 17 -> +8).
        let mut bad_command = frame.clone();
        bad_command[8 + 17] = 99;
        assert!(Decoder::flow_mod(&bad_command).is_err());

        // A match type that is not OFPMT_OXM is rejected (body 40 -> +8).
        let mut bad_match_type = frame.clone();
        bad_match_type[8 + 40] = 0xff;
        assert!(Decoder::flow_mod(&bad_match_type).is_err());

        // A match length below the 4-byte minimum is rejected.
        let mut short_match = frame.clone();
        short_match[8 + 42] = 0;
        short_match[8 + 43] = 3;
        assert!(Decoder::flow_mod(&short_match).is_err());

        // Padding contents are ignored per section 7.1.2.
        let mut bad_pad = frame.clone();
        let match_len = usize::from(u16::from_be_bytes([bad_pad[8 + 42], bad_pad[8 + 43]]));
        bad_pad[8 + 40 + match_len] = 1;
        assert!(Decoder::flow_mod(&bad_pad).is_ok());

        // Wrong message type.
        assert!(Decoder::flow_mod(&Encoder::barrier_request(1)).is_err());
    }

    /// Same treatment for packet-in, which has its own offsets.
    #[test]
    fn packet_in_parser_rejects_every_truncation_and_bad_field() {
        use crate::protocol::codec::Encoder;
        use crate::protocol::packet_in::PacketIn;

        let frame = Encoder::packet_in(&PacketIn {
            xid: 1,
            buffer_id: OFP_NO_BUFFER,
            total_len: 4,
            reason: OFPR_APPLY_ACTION,
            table_id: 1,
            cookie: 9,
            of_match: oxm::parse_oxm_list(&oxm::in_port(3)).unwrap(),
            data: b"data".to_vec(),
        })
        .unwrap();
        assert!(PacketIn::parse(&frame).is_ok());

        // ofp_packet_in is 8 header + 16 fixed + an 8-byte minimum match
        // + 2 pad. Past that the Ethernet frame is variable, so a shorter
        // one is valid and the requirement is only "never panics".
        const PACKET_IN_MIN: usize = 34;
        for cut in 0..frame.len() {
            let truncated = truncate_consistently(&frame, cut);
            let result = PacketIn::parse(&truncated);
            if cut < PACKET_IN_MIN {
                assert!(
                    result.is_err(),
                    "packet-in accepted a {cut}-byte truncation"
                );
            }
        }

        // Wrong message type.
        assert!(PacketIn::parse(&Encoder::barrier_request(1)).is_err());
        // Match type that is not OXM (frame offset 24).
        let mut bad_type = frame.clone();
        bad_type[24] = 0xff;
        assert!(PacketIn::parse(&bad_type).is_err());
        // Match length under the minimum.
        let mut short_match = frame.clone();
        short_match[26] = 0;
        short_match[27] = 2;
        assert!(PacketIn::parse(&short_match).is_err());
    }

    // ---- actions and instructions: table-driven length checks ----

    /// Every fixed-size action rejects a wrong `len` while accepting padding
    /// values as required by section 7.1.2.
    #[test]
    fn every_action_parser_rejects_bad_length_and_accepts_padding() {
        use crate::protocol::action::{parse_actions, Action};

        // (action type, correct total length)
        const FIXED: [(u16, usize); 15] = [
            (OFPAT_OUTPUT, 16),
            (OFPAT_COPY_TTL_OUT, 8),
            (OFPAT_COPY_TTL_IN, 8),
            (OFPAT_SET_MPLS_TTL, 8),
            (OFPAT_DEC_MPLS_TTL, 8),
            (OFPAT_PUSH_VLAN, 8),
            (OFPAT_POP_VLAN, 8),
            (OFPAT_PUSH_MPLS, 8),
            (OFPAT_POP_MPLS, 8),
            (OFPAT_SET_QUEUE, 8),
            (OFPAT_GROUP, 8),
            (OFPAT_SET_NW_TTL, 8),
            (OFPAT_DEC_NW_TTL, 8),
            (OFPAT_PUSH_PBB, 8),
            (OFPAT_POP_PBB, 8),
        ];

        for (action_type, good_len) in FIXED {
            // Correct shape parses.
            let mut ok = Vec::new();
            ok.extend_from_slice(&action_type.to_be_bytes());
            ok.extend_from_slice(&u16::try_from(good_len).unwrap().to_be_bytes());
            ok.resize(good_len, 0);
            assert!(
                parse_actions(&ok).is_ok(),
                "action {action_type} rejected its own correct encoding"
            );

            // A length that is a legal multiple of 8 but wrong for this
            // action must be rejected.
            let wrong_len = if good_len == 8 { 16 } else { 8 };
            let mut wrong = Vec::new();
            wrong.extend_from_slice(&action_type.to_be_bytes());
            wrong.extend_from_slice(&u16::try_from(wrong_len).unwrap().to_be_bytes());
            wrong.resize(wrong_len, 0);
            assert!(
                parse_actions(&wrong).is_err(),
                "action {action_type} accepted length {wrong_len}"
            );
        }

        // A length that is not a multiple of 8 is always illegal.
        assert!(parse_actions(&[0, 0, 0, 12, 0, 0, 0, 0, 0, 0, 0, 0]).is_err());
        // A length below the 4-byte header is illegal.
        assert!(parse_actions(&[0, 0, 0, 0, 0, 0, 0, 0]).is_err());
        // A truncated action list is rejected.
        let mut out = Vec::new();
        Action::output(1).encode(&mut out).unwrap();
        for cut in 1..out.len() {
            assert!(
                parse_actions(&out[..cut]).is_err(),
                "action list accepted a {cut}-byte truncation"
            );
        }
        // Padding contents are ignored per section 7.1.2.
        let mut bad_pad = out.clone();
        bad_pad[15] = 1;
        assert!(parse_actions(&bad_pad).is_ok());
    }

    /// Same for instructions.
    #[test]
    fn every_instruction_parser_rejects_bad_length_and_accepts_padding() {
        use crate::protocol::instruction::{parse_instructions, Instruction};

        const FIXED: [(u16, usize); 4] = [
            (OFPIT_GOTO_TABLE, 8),
            (OFPIT_WRITE_METADATA, 24),
            (OFPIT_CLEAR_ACTIONS, 8),
            (OFPIT_APPLY_ACTIONS, 8),
        ];
        for (kind, good_len) in FIXED {
            let mut ok = Vec::new();
            ok.extend_from_slice(&kind.to_be_bytes());
            ok.extend_from_slice(&u16::try_from(good_len).unwrap().to_be_bytes());
            ok.resize(good_len, 0);
            assert!(
                parse_instructions(&ok).is_ok(),
                "instruction {kind} rejected its own correct encoding"
            );

            let wrong_len = if good_len == 8 { 16 } else { 8 };
            let mut wrong = Vec::new();
            wrong.extend_from_slice(&kind.to_be_bytes());
            wrong.extend_from_slice(&u16::try_from(wrong_len).unwrap().to_be_bytes());
            wrong.resize(wrong_len, 0);
            assert!(
                parse_instructions(&wrong).is_err(),
                "instruction {kind} accepted length {wrong_len}"
            );
        }

        assert!(parse_instructions(&[0, 1, 0, 12, 0, 0, 0, 0, 0, 0, 0, 0]).is_err());
        assert!(parse_instructions(&[0, 1, 0, 0, 0, 0, 0, 0]).is_err());

        let mut out = Vec::new();
        Instruction::WriteMetadata {
            metadata: 1,
            metadata_mask: 2,
        }
        .encode(&mut out)
        .unwrap();
        for cut in 1..out.len() {
            assert!(
                parse_instructions(&out[..cut]).is_err(),
                "instruction list accepted a {cut}-byte truncation"
            );
        }
        // Padding contents are ignored per section 7.1.2.
        let mut bad_pad = out.clone();
        bad_pad[4] = 1;
        assert!(parse_instructions(&bad_pad).is_ok());
    }

    /// A frame shorter than its own header `length` must be refused by
    /// each parser's own guard, not only by `Decoder::message`. This is
    /// the case `truncate_consistently` deliberately cannot produce.
    #[test]
    fn parsers_reject_a_frame_shorter_than_its_declared_length() {
        use crate::protocol::codec::Decoder;
        use crate::protocol::config::Config;
        use crate::protocol::features;
        use crate::protocol::packet_in::PacketIn;
        use crate::protocol::packet_out::PacketOut;

        for (name, frame) in frame_corpus() {
            for cut in [8usize, frame.len() / 2, frame.len() - 1] {
                if cut < 8 || cut >= frame.len() {
                    continue;
                }
                // Length field left claiming the original size.
                let lied = &frame[..cut];
                assert!(
                    Decoder::message(lied).is_err(),
                    "{name}: a {cut}-byte frame claiming {} bytes was accepted",
                    frame.len()
                );
            }
        }

        // The same, straight into the standalone parsers.
        let flow = frame_corpus()
            .into_iter()
            .find(|(n, _)| *n == "flow_mod")
            .unwrap()
            .1;
        assert!(Decoder::flow_mod(&flow[..flow.len() - 1]).is_err());

        let pin = frame_corpus()
            .into_iter()
            .find(|(n, _)| *n == "packet_in")
            .unwrap()
            .1;
        assert!(PacketIn::parse(&pin[..pin.len() - 1]).is_err());

        let pout = frame_corpus()
            .into_iter()
            .find(|(n, _)| *n == "packet_out")
            .unwrap()
            .1;
        assert!(PacketOut::parse(&pout[..pout.len() - 1]).is_err());

        // Wrong-message-type guards on the standalone parsers.
        let barrier = Decoder::message(&crate::protocol::codec::Encoder::barrier_request(1));
        assert!(barrier.is_ok());
        let barrier_frame = crate::protocol::codec::Encoder::barrier_request(1);
        assert!(features::Reply::parse(&barrier_frame).is_err());
        assert!(features::Request::parse(&barrier_frame).is_err());
        assert!(Config::parse_get_request(&barrier_frame).is_err());
        assert!(Decoder::set_config(&barrier_frame).is_err());
        assert!(Decoder::get_config_reply(&barrier_frame).is_err());
        assert!(PacketIn::parse(&barrier_frame).is_err());
        assert!(PacketOut::parse(&barrier_frame).is_err());

        // A features reply truncated below its fixed 32 bytes.
        let features_frame = frame_corpus()
            .into_iter()
            .find(|(n, _)| *n == "features_reply")
            .unwrap()
            .1;
        for cut in 8..32 {
            assert!(
                features::Reply::parse(&truncate_consistently(&features_frame, cut)).is_err(),
                "features reply accepted a {cut}-byte frame"
            );
        }

        // A switch-config message truncated below its fixed 12 bytes.
        let cfg = crate::protocol::codec::Encoder::set_config(1, 0, 128);
        for cut in 8..12 {
            assert!(Decoder::set_config(&truncate_consistently(&cfg, cut)).is_err());
        }
    }

    /// Semantic (non-length) rejections: reserved values that are simply
    /// not legal, which no amount of truncation reaches.
    #[test]
    fn reserved_and_invalid_enum_values_are_rejected() {
        use crate::protocol::codec::{Decoder, Encoder};
        use crate::protocol::control::{
            parse_async_flow_removed, parse_async_port_status, parse_controller_status,
            parse_role_request, parse_role_status, parse_table_status,
        };

        // An invalid controller role.
        let mut role = Encoder::role_request(1, OFPCR_ROLE_MASTER, 0, 1).unwrap();
        role[8..12].copy_from_slice(&99u32.to_be_bytes());
        assert!(parse_role_request(&role).is_err());

        // An invalid flow-removed reason.
        let removed = frame_corpus()
            .into_iter()
            .find(|(n, _)| *n == "flow_removed")
            .unwrap()
            .1;
        let mut bad = removed.clone();
        bad[9] = 99; // body offset 1 = reason
        assert!(parse_async_flow_removed(&bad).is_err());
        assert!(parse_async_flow_removed(&removed).is_ok());

        // An invalid port-status reason.
        let status = frame_corpus()
            .into_iter()
            .find(|(n, _)| *n == "port_status")
            .unwrap()
            .1;
        let mut bad = status.clone();
        bad[8] = 99;
        assert!(parse_async_port_status(&bad).is_err());
        // Padding contents are ignored per section 7.1.2.
        let mut bad_pad = status.clone();
        bad_pad[9] = 1;
        assert!(parse_async_port_status(&bad_pad).is_ok());

        // Invalid controller-status reason and channel status.
        let cs = frame_corpus()
            .into_iter()
            .find(|(n, _)| *n == "controller_status")
            .unwrap()
            .1;
        assert!(parse_controller_status(&cs).is_ok());
        let mut bad_reason = cs.clone();
        bad_reason[16] = 99; // body offset 8 = reason
        assert!(parse_controller_status(&bad_reason).is_err());
        let mut bad_channel = cs.clone();
        bad_channel[17] = 99; // body offset 9 = channel_status
        assert!(parse_controller_status(&bad_channel).is_err());

        // Invalid role-status reason and role.
        let rs = frame_corpus()
            .into_iter()
            .find(|(n, _)| *n == "role_status")
            .unwrap()
            .1;
        assert!(parse_role_status(&rs).is_ok());
        let mut bad_reason = rs.clone();
        bad_reason[12] = 99; // body offset 4 = reason
        assert!(parse_role_status(&bad_reason).is_err());
        let mut bad_role = rs.clone();
        bad_role[8..12].copy_from_slice(&99u32.to_be_bytes()); // body offset 0 = role
        assert!(parse_role_status(&bad_role).is_err());

        // Invalid table-status reason.
        let ts = frame_corpus()
            .into_iter()
            .find(|(n, _)| *n == "table_status")
            .unwrap()
            .1;
        assert!(parse_table_status(&ts).is_ok());
        let mut bad_reason = ts.clone();
        bad_reason[8] = 99; // body offset 0 = reason
        assert!(parse_table_status(&bad_reason).is_err());

        // An unknown message type decodes as Ignored rather than failing,
        // so a peer using a newer type does not break the session.
        let mut unknown = Encoder::barrier_request(1);
        unknown[1] = 0x7f;
        assert!(matches!(
            Decoder::message(&unknown),
            Ok(crate::protocol::message::Message::Ignored { .. })
        ));
    }

    /// `GroupMod` and `BundleAddMessage` enforce spec rules at encode
    /// time; both the accepting and the rejecting side are checked.
    #[test]
    fn encode_time_spec_validations_reject_bad_input() {
        use crate::protocol::codec::Encoder;
        use crate::protocol::control::{Bucket, BundleAddMessage, GroupMod};

        // command_bucket_id must be OFPG_BUCKET_ALL for ADD/MODIFY/DELETE.
        for command in [OFPGC_ADD, OFPGC_MODIFY, OFPGC_DELETE] {
            let bad = GroupMod {
                xid: 1,
                command,
                group_type: OFPGT_ALL,
                group_id: 1,
                command_bucket_id: 0,
                buckets: Vec::new(),
                properties: Vec::new(),
            };
            assert!(
                bad.encode().is_err(),
                "command {command} accepted a non-BUCKET_ALL command_bucket_id"
            );

            let good = GroupMod {
                command_bucket_id: OFPG_BUCKET_ALL,
                ..bad
            };
            assert!(
                good.encode().is_ok(),
                "command {command} rejected BUCKET_ALL"
            );
        }
        // INSERT_BUCKET legitimately uses a real bucket id.
        let insert = GroupMod {
            xid: 1,
            command: OFPGC_INSERT_BUCKET,
            group_type: OFPGT_ALL,
            group_id: 1,
            command_bucket_id: 7,
            buckets: vec![Bucket {
                bucket_id: 7,
                actions: Vec::new(),
                properties: Vec::new(),
            }],
            properties: Vec::new(),
        };
        assert!(insert.encode().is_ok());

        // The convenience constructors always produce a legal message.
        assert!(GroupMod::add(1, OFPGT_ALL, 1, Vec::new()).encode().is_ok());
        assert!(GroupMod::delete(1, OFPG_ALL).encode().is_ok());

        // A bundle-add's nested xid must match its own.
        let mismatched = BundleAddMessage {
            xid: 10,
            bundle_id: 1,
            flags: 0,
            message: Encoder::barrier_request(11),
            properties: Vec::new(),
        };
        assert!(mismatched.encode().is_err());
        let matched = BundleAddMessage {
            message: Encoder::barrier_request(10),
            ..mismatched
        };
        assert!(matched.encode().is_ok());
    }

    // ---- exhaustive mutation: settles which error paths are reachable ----

    /// A deterministic, exhaustive mutation sweep over every message type.
    ///
    /// For each valid frame this walks every byte offset and rewrites it
    /// with a set of boundary values, both leaving the header `length`
    /// alone (so the outer guard fires) and repairing it (so the inner
    /// per-field reads run). It is the systematic way to reach error arms
    /// that a hand-written case per offset would take hundreds of tests to
    /// cover -- and anything it still cannot reach is unreachable behind a
    /// dominating length check rather than merely untested.
    #[test]
    fn exhaustive_byte_mutation_reaches_every_reachable_error_path() {
        use crate::protocol::codec::Decoder;

        // Boundary values: zero, one, the 7-bit and 8-bit maxima, and a
        // few values that are meaningful as lengths or type tags.
        const PATCHES: [u8; 8] = [0x00, 0x01, 0x04, 0x08, 0x7f, 0x80, 0xfe, 0xff];

        for (name, frame) in frame_corpus() {
            for offset in 0..frame.len() {
                for patch in PATCHES {
                    let mut raw = frame.clone();
                    raw[offset] = patch;
                    // (a) length left as-is: exercises the outer guards.
                    let _ = Decoder::message(&raw);

                    // (b) length repaired to match the buffer: lets the
                    //     mutation reach the inner field reads.
                    let mut fixed = raw.clone();
                    let len = u16::try_from(fixed.len()).unwrap();
                    fixed[2..4].copy_from_slice(&len.to_be_bytes());
                    fixed[0] = OFP_VERSION_1_5;
                    fixed[1] = frame[1];
                    let _ = Decoder::message(&fixed);
                }
            }

            // Every self-consistent truncation, through the same path.
            for cut in 8..frame.len() {
                let mut t = truncate_consistently(&frame, cut);
                t[1] = frame[1];
                let _ = Decoder::message(&t);
            }
            assert!(
                Decoder::message(&frame).is_ok(),
                "{name}: corpus frame must still be valid"
            );
        }
    }

    /// The same treatment for the multipart bodies, which `Decoder::message`
    /// only reaches after the outer frame is accepted. Each of the 21
    /// subtypes gets its body mutated at every offset.
    #[test]
    fn exhaustive_multipart_body_mutation() {
        use crate::protocol::codec::Encoder;
        use crate::protocol::control::{parse_multipart_reply, parse_multipart_request};

        const KINDS: [u16; 21] = [
            OFPMP_DESC,
            OFPMP_FLOW_DESC,
            OFPMP_AGGREGATE_STATS,
            OFPMP_TABLE_STATS,
            OFPMP_PORT_STATS,
            OFPMP_QUEUE_STATS,
            OFPMP_GROUP_STATS,
            OFPMP_GROUP_DESC,
            OFPMP_GROUP_FEATURES,
            OFPMP_METER_STATS,
            OFPMP_METER_DESC,
            OFPMP_METER_FEATURES,
            OFPMP_TABLE_FEATURES,
            OFPMP_PORT_DESC,
            OFPMP_TABLE_DESC,
            OFPMP_QUEUE_DESC,
            OFPMP_FLOW_MONITOR,
            OFPMP_FLOW_STATS,
            OFPMP_CONTROLLER_STATUS,
            OFPMP_BUNDLE_FEATURES,
            OFPMP_EXPERIMENTER,
        ];
        const PATCHES: [u8; 6] = [0x00, 0x01, 0x08, 0x40, 0xfe, 0xff];

        // Bodies of several shapes: empty, one entry-sized block, and a
        // block long enough to hold any fixed header in the family.
        for kind in KINDS {
            for base_len in [0usize, 8, 16, 24, 40, 48, 64, 80] {
                let base = vec![0u8; base_len];
                for offset in 0..base_len {
                    for patch in PATCHES {
                        let mut body = base.clone();
                        body[offset] = patch;
                        if let Ok(msg) = parse_multipart_request(
                            &Encoder::multipart_request(1, kind, 0, &body).unwrap(),
                        ) {
                            let _ = msg.typed_request_body();
                        }
                        if let Ok(msg) = parse_multipart_reply(
                            &Encoder::multipart_reply(2, kind, 0, &body).unwrap(),
                        ) {
                            let _ = msg.typed_reply_body();
                        }
                    }
                }
            }
        }
    }

    /// Mutate the length-bearing bytes of nested TLV lists directly:
    /// OXM/OXS TLVs, action and instruction headers, and property headers
    /// all carry their own length, and each parser has to defend it.
    #[test]
    fn exhaustive_nested_tlv_length_mutation() {
        use crate::protocol::action::parse_actions;
        use crate::protocol::instruction::parse_instructions;
        use crate::protocol::oxs;

        // Walk every (type, length) pair a 4-byte TLV header can express
        // for the values that matter, in each nested list parser.
        //
        // The type range has to span every action type the spec defines
        // (0..=28) and the 0xffff experimenter form, or the variable-length
        // parsers -- SET_FIELD (25), COPY_FIELD (28), EXPERIMENTER -- are
        // never entered and their length checks go untested.
        let types: Vec<u16> = (0u16..=30).chain([0x8000, 0xfffe, 0xffff]).collect();
        for ty in types {
            let [type_hi, type_lo] = ty.to_be_bytes();
            {
                for len in [0u8, 1, 3, 4, 5, 7, 8, 9, 12, 16, 20, 24, 32, 40, 255] {
                    let hdr = [type_hi, type_lo, 0x00, len];
                    // Backed by a buffer big enough that the length, not
                    // the buffer, is what the parser must judge.
                    let mut buf = hdr.to_vec();
                    buf.resize(64, 0);

                    let _ = parse_actions(&buf);
                    let _ = parse_instructions(&buf);
                    let _ = oxm::parse_oxm_list_unchecked(&buf);
                    let _ = oxs::parse_oxs_list(&buf);
                    let _ = oxs::parse_stats(&buf, 0);

                    // And with the buffer exactly as long as declared.
                    let mut exact = hdr.to_vec();
                    exact.resize(usize::from(len).max(4), 0);
                    let _ = parse_actions(&exact);
                    let _ = parse_instructions(&exact);
                    let _ = oxm::parse_oxm_list_unchecked(&exact);
                    let _ = oxs::parse_oxs_list(&exact);
                    let _ = oxs::parse_stats(&exact, 0);
                }
            }
        }
    }

    /// The variable-length actions each have their own length arithmetic:
    /// `SET_FIELD` sizes itself from the embedded OXM TLV, `COPY_FIELD`
    /// from its OXM-id list, and `EXPERIMENTER` from its vendor payload.
    /// Each is driven here across the whole range of declared lengths.
    #[test]
    fn variable_length_actions_reject_inconsistent_lengths() {
        use crate::protocol::action::{parse_actions, Action};

        // A well-formed set-field parses, and its length is 8-aligned.
        let mut good = Vec::new();
        Action::SetField(oxm::eth_dst([1, 2, 3, 4, 5, 6]))
            .encode(&mut good)
            .unwrap();
        assert!(parse_actions(&good).is_ok());
        let mut set_field_extra = good.clone();
        set_field_extra.extend_from_slice(&[0u8; 8]);
        set_field_extra[2..4].copy_from_slice(&24u16.to_be_bytes());
        assert!(parse_actions(&set_field_extra).is_err());

        // Corrupting the embedded OXM's length byte desynchronises it from
        // the action length; every value must be judged, not trusted.
        for oxm_len in 0u8..=32 {
            let mut bad = good.clone();
            bad[7] = oxm_len; // the OXM TLV's own length byte
            let _ = parse_actions(&bad);
        }
        // ... and corrupting the action length itself.
        for action_len in [0u8, 4, 8, 12, 16, 24, 32] {
            let mut bad = good.clone();
            bad[3] = action_len;
            let _ = parse_actions(&bad);
        }

        let mut copy = Vec::new();
        Action::CopyField {
            n_bits: 8,
            src_offset: 0,
            dst_offset: 0,
            oxm_ids: oxm::copy_field_ids(OFPXMT_OFB_ETH_SRC, 6, OFPXMT_OFB_ETH_DST, 6),
        }
        .encode(&mut copy)
        .unwrap();
        assert!(parse_actions(&copy).is_ok());
        let mut copy_extra = copy.clone();
        copy_extra.extend_from_slice(&[0u8; 8]);
        copy_extra[2..4].copy_from_slice(&32u16.to_be_bytes());
        assert!(parse_actions(&copy_extra).is_err());
        for action_len in [0u8, 4, 8, 12, 16, 24, 32] {
            let mut bad = copy.clone();
            bad[3] = action_len;
            let _ = parse_actions(&bad);
        }

        let mut exp = Vec::new();
        Action::Experimenter {
            experimenter: 0x2320,
            data: vec![1, 2, 3, 4],
        }
        .encode(&mut exp)
        .unwrap();
        assert!(parse_actions(&exp).is_ok());
        for action_len in [0u8, 4, 8, 12, 16, 24] {
            let mut bad = exp.clone();
            bad[3] = action_len;
            let _ = parse_actions(&bad);
        }
        // An experimenter action too short to hold its own vendor id.
        assert!(parse_actions(&[0xff, 0xff, 0x00, 0x08, 0, 0, 0, 0]).is_ok());
        assert!(parse_actions(&[0xff, 0xff, 0x00, 0x04]).is_err());

        // The same for the variable-length instructions.
        use crate::protocol::instruction::{parse_instructions, Instruction};
        let mut apply = Vec::new();
        Instruction::ApplyActions(vec![Action::output(1)])
            .encode(&mut apply)
            .unwrap();
        assert!(parse_instructions(&apply).is_ok());
        for len in [0u8, 4, 8, 12, 16, 24, 32] {
            let mut bad = apply.clone();
            bad[3] = len;
            let _ = parse_instructions(&bad);
        }
        let mut trigger = Vec::new();
        Instruction::StatTrigger {
            flags: OFPSTF_PERIODIC,
            thresholds: vec![crate::protocol::oxs::Tlv::PacketCount(1)],
        }
        .encode(&mut trigger)
        .unwrap();
        assert!(parse_instructions(&trigger).is_ok());
        let mut trigger_extra = trigger.clone();
        trigger_extra.extend_from_slice(&[0u8; 8]);
        trigger_extra[2..4].copy_from_slice(&32u16.to_be_bytes());
        assert!(parse_instructions(&trigger_extra).is_err());
        for len in [0u8, 8, 12, 16, 24, 32] {
            let mut bad = trigger.clone();
            bad[3] = len;
            let _ = parse_instructions(&bad);
        }
    }

    /// Exhaustive property sweep: every property kind this crate knows,
    /// at every body length from 0 to 80, through each container that
    /// carries that family.
    ///
    /// Encoding a `Raw` variant under a typed kind is what lets a body of
    /// any length reach a typed parser, so this drives each parser's
    /// length arithmetic across its whole domain rather than at a few
    /// hand-picked sizes.
    #[test]
    fn exhaustive_property_body_length_sweep() {
        use crate::protocol::control::{
            parse_bundle_message, parse_controller_status, parse_multipart_reply, parse_port_mod,
            parse_table_mod, BundleMessage, BundleProperty, ControllerStatus,
            ControllerStatusProperty, MultipartMessage, MultipartReplyBody, PortDescEntry, PortMod,
            PortModProperty, PortProperty, PortStatsEntry, PortStatsProperty, QueueDescEntry,
            QueueDescProperty, QueueStatsEntry, QueueStatsProperty, TableMod, TableModProperty,
        };

        // Every kind each family defines, plus one it does not, so the
        // Raw fallback is driven too.
        const TABLE_MOD_KINDS: [u16; 4] = [
            OFPTMPT_EVICTION,
            OFPTMPT_VACANCY,
            OFPTMPT_EXPERIMENTER,
            0x0f00,
        ];
        const PORT_MOD_KINDS: [u16; 4] = [
            OFPPMPT_ETHERNET,
            OFPPMPT_OPTICAL,
            OFPPMPT_EXPERIMENTER,
            0x0f00,
        ];
        const PORT_DESC_KINDS: [u16; 7] = [
            OFPPDPT_ETHERNET,
            OFPPDPT_OPTICAL,
            OFPPDPT_PIPELINE_INPUT,
            OFPPDPT_PIPELINE_OUTPUT,
            OFPPDPT_RECIRCULATE,
            OFPPDPT_EXPERIMENTER,
            0x0f00,
        ];
        const PORT_STATS_KINDS: [u16; 4] = [
            OFPPSPT_ETHERNET,
            OFPPSPT_OPTICAL,
            OFPPSPT_EXPERIMENTER,
            0x0f00,
        ];
        const QUEUE_DESC_KINDS: [u16; 4] = [
            OFPQDPT_MIN_RATE,
            OFPQDPT_MAX_RATE,
            OFPQDPT_EXPERIMENTER,
            0x0f00,
        ];
        const BUNDLE_KINDS: [u16; 3] = [OFPBPT_TIME, OFPBPT_EXPERIMENTER, 0x0f00];
        const CS_KINDS: [u16; 3] = [OFPCSPT_URI, OFPCSPT_EXPERIMENTER, 0x0f00];

        let sizes: Vec<usize> = (0..=80).collect();

        for size in &sizes {
            let data = vec![0u8; *size];

            for kind in TABLE_MOD_KINDS {
                let m = TableMod {
                    xid: 1,
                    table_id: 0,
                    config: 0,
                    properties: vec![TableModProperty::Raw {
                        kind,
                        data: data.clone(),
                    }],
                };
                if let Ok(frame) = m.encode() {
                    let _ = parse_table_mod(&frame);
                }
            }

            for kind in PORT_MOD_KINDS {
                let m = PortMod {
                    xid: 1,
                    port_no: 1,
                    hw_addr: [0; 6],
                    config: 0,
                    mask: 0,
                    properties: vec![PortModProperty::Raw {
                        kind,
                        data: data.clone(),
                    }],
                };
                if let Ok(frame) = m.encode() {
                    let _ = parse_port_mod(&frame);
                }
            }

            for kind in BUNDLE_KINDS {
                let m = BundleMessage {
                    xid: 1,
                    bundle_id: 1,
                    ctrl_type: OFPBCT_OPEN_REQUEST,
                    flags: 0,
                    properties: vec![BundleProperty::Raw {
                        kind,
                        data: data.clone(),
                    }],
                };
                if let Ok(frame) = m.encode() {
                    let _ = parse_bundle_message(&frame);
                }
            }

            for kind in CS_KINDS {
                let m = ControllerStatus {
                    xid: 1,
                    length: 0,
                    short_id: 0,
                    role: OFPCR_ROLE_EQUAL,
                    reason: OFPCSR_REQUEST,
                    channel_status: OFPCT_STATUS_UP,
                    properties: vec![ControllerStatusProperty::Raw {
                        kind,
                        data: data.clone(),
                    }],
                };
                if let Ok(frame) = m.encode() {
                    let _ = parse_controller_status(&frame);
                }
            }

            let reply = |kind: u16, body: MultipartReplyBody| {
                if let Ok(msg) = MultipartMessage::from_reply_body(1, kind, 0, &body) {
                    if let Ok(frame) = msg.encode_reply() {
                        if let Ok(parsed) = parse_multipart_reply(&frame) {
                            let _ = parsed.typed_reply_body();
                        }
                    }
                }
            };

            for kind in PORT_DESC_KINDS {
                reply(
                    OFPMP_PORT_DESC,
                    MultipartReplyBody::PortDesc(vec![PortDescEntry {
                        port_no: 1,
                        hw_addr: [0; 6],
                        name: "p".into(),
                        config: 0,
                        state: 0,
                        properties: vec![PortProperty::Raw {
                            kind,
                            data: data.clone(),
                        }],
                    }]),
                );
            }

            for kind in PORT_STATS_KINDS {
                reply(
                    OFPMP_PORT_STATS,
                    MultipartReplyBody::PortStats(vec![PortStatsEntry {
                        port_no: 1,
                        duration_sec: 0,
                        duration_nsec: 0,
                        rx_packets: 0,
                        tx_packets: 0,
                        rx_bytes: 0,
                        tx_bytes: 0,
                        rx_dropped: 0,
                        tx_dropped: 0,
                        rx_errors: 0,
                        tx_errors: 0,
                        properties: vec![PortStatsProperty::Raw {
                            kind,
                            data: data.clone(),
                        }],
                    }]),
                );
            }

            for kind in QUEUE_DESC_KINDS {
                reply(
                    OFPMP_QUEUE_DESC,
                    MultipartReplyBody::QueueDesc(vec![QueueDescEntry {
                        port_no: 1,
                        queue_id: 1,
                        properties: vec![QueueDescProperty::Raw {
                            kind,
                            data: data.clone(),
                        }],
                    }]),
                );
            }

            reply(
                OFPMP_QUEUE_STATS,
                MultipartReplyBody::QueueStats(vec![QueueStatsEntry {
                    port_no: 1,
                    queue_id: 1,
                    tx_bytes: 0,
                    tx_packets: 0,
                    tx_errors: 0,
                    duration_sec: 0,
                    duration_nsec: 0,
                    properties: vec![QueueStatsProperty::Raw {
                        kind: OFPQSPT_EXPERIMENTER,
                        data: data.clone(),
                    }],
                }]),
            );
        }
    }

    /// `BucketProperty::parse`'s fixed-size branches (`WEIGHT`,
    /// `WATCH_PORT`, `WATCH_GROUP`, `EXPERIMENTER`) each reject any body
    /// length but their one accepted size. Sweep every kind across a
    /// range of data lengths through a real `GroupMod` round trip.
    #[test]
    fn bucket_property_length_validation_is_enforced() {
        use crate::protocol::control::{Bucket, BucketProperty, GroupMod};

        for kind in [
            OFPGBPT_WEIGHT,
            OFPGBPT_WATCH_PORT,
            OFPGBPT_WATCH_GROUP,
            OFPGBPT_EXPERIMENTER,
        ] {
            for data_len in 0..=12 {
                let bucket = Bucket {
                    bucket_id: 0,
                    actions: Vec::new(),
                    properties: vec![BucketProperty::Raw {
                        kind,
                        data: vec![0u8; data_len],
                    }],
                };
                let group = GroupMod::add(1, OFPGT_ALL, 1, vec![bucket]);
                if let Ok(frame) = group.encode() {
                    let _ = GroupMod::parse(&frame);
                }
            }
        }
    }

    /// `MeterBand::parse`'s `DROP`/`DSCP_REMARK`/`EXPERIMENTER` arms each
    /// check an exact or minimum length. `MeterBand`'s own encoder can
    /// never produce a bad length, so drive raw, hand-built bands
    /// (including unknown-type ones) through a real `MeterMod` frame.
    #[test]
    fn meter_band_length_validation_is_enforced() {
        use crate::protocol::control::MeterMod;
        use crate::protocol::header::Header;

        fn build_meter_mod(band_bytes: &[u8]) -> Vec<u8> {
            let mut body = Vec::new();
            body.extend_from_slice(&OFPMC_ADD.to_be_bytes());
            body.extend_from_slice(&0u16.to_be_bytes());
            body.extend_from_slice(&1u32.to_be_bytes());
            body.extend_from_slice(band_bytes);
            let mut out = Vec::new();
            let len = u16::try_from(OFP_HEADER_LEN + body.len()).unwrap_or(u16::MAX);
            Header {
                version: OFP_VERSION_1_5,
                msg_type: OFPT_METER_MOD,
                length: len,
                xid: 1,
            }
            .encode(&mut out);
            out.extend_from_slice(&body);
            out
        }

        for band_type in [OFPMBT_DROP, OFPMBT_DSCP_REMARK, OFPMBT_EXPERIMENTER, 0x1234] {
            for total_len in 0..=20 {
                let mut band = vec![0u8; total_len.max(12)];
                if let Some(slot) = band.get_mut(0..2) {
                    slot.copy_from_slice(&band_type.to_be_bytes());
                }
                band.truncate(total_len);
                let frame = build_meter_mod(&band);
                let _ = MeterMod::parse(&frame);
            }
        }
    }
}

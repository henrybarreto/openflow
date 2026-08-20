#[cfg(test)]
mod tests {
    use crate::protocol::action::{parse_actions, Action};
    use crate::protocol::barrier::{encode_barrier_reply, encode_barrier_request, Barrier};
    use crate::protocol::codec::{Decoder, Encoder};
    use crate::protocol::config::{
        encode_get_config_reply, encode_get_config_request, encode_set, parse_get_config_reply,
        Config,
    };
    use crate::protocol::constants::*;
    use crate::protocol::control::{
        encode_bundle_add_message, encode_get_async_request, encode_meter_mod,
        encode_multipart_reply, encode_multipart_request, encode_port_mod, encode_role_reply,
        encode_role_request, encode_table_mod, parse_async_config_get_reply,
        parse_async_config_set, parse_async_controller_status, parse_async_flow_removed,
        parse_async_port_status, parse_async_request_forward, parse_async_role_status,
        parse_async_table_status, parse_bundle_add_message, parse_bundle_message, parse_group_mod,
        parse_meter_mod, parse_multipart_reply, parse_multipart_request, parse_port_mod,
        parse_role_reply, parse_role_request, parse_table_mod, AsyncConfig, Bucket, BucketCounter,
        BucketProperty, BundleFeaturesProperty, BundleFeaturesReply, BundleFeaturesRequest,
        BundleMessage, BundleProperty, ControllerStatusEntry, ControllerStatusProperty, Desc,
        FlowDesc, FlowMonitorRequest, FlowMonitorUpdate, FlowStatsEntry, FlowStatsRequest,
        GroupDescEntry, GroupFeatures, GroupMod, GroupMultipartRequest, GroupProperty,
        GroupStatsEntry, MeterBand, MeterBandStats, MeterDescEntry, MeterFeatures,
        MeterMultipartRequest, MeterStatsEntry, MultipartMessage, OxmId, PortDescEntry,
        PortModProperty, PortMultipartRequest, PortProperty, PortStatsEntry, PortStatsProperty,
        Property, QueueDescEntry, QueueDescProperty, QueueMultipartRequest, QueueStatsEntry,
        QueueStatsProperty, TableDescEntry, TableFeatureProperty, TableFeaturesEntry,
        TableModProperty, TableStatsEntry, Time, TypeId,
    };
    use crate::protocol::echo::Echo;
    use crate::protocol::error::OfError;
    use crate::protocol::features::Request;
    use crate::protocol::header::Header;
    use crate::protocol::hello::Hello;
    use crate::protocol::instruction::{parse_instructions, Instruction};
    use crate::protocol::message::{decode, Message};
    use crate::protocol::ofmatch::Match;
    use crate::protocol::oxs::Tlv as OxsTlv;
    use crate::protocol::packet_in::PacketIn;
    use crate::protocol::packet_out::PacketOut;
    use crate::protocol::rule::Rule;

    #[test]
    fn test_encode_in_port_1() {
        let oxm = crate::protocol::oxm::in_port(1);
        assert_eq!(oxm, vec![0x80, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x01]);
    }

    #[test]
    fn test_header_parse_rejects_short_buffer() {
        for len in 0..8 {
            let buf = vec![0u8; len];
            assert!(
                matches!(
                    Header::parse(&buf),
                    Err(crate::protocol::error::OfError::ShortBuffer)
                ),
                "buffer of {len} bytes should be rejected as short"
            );
        }
    }

    #[test]
    fn test_header_parse_rejects_length_below_8() {
        for length in 0..8u16 {
            let mut buf = Vec::new();
            Header {
                version: OFP_VERSION_1_5,
                msg_type: OFPT_HELLO,
                length,
                xid: 1,
            }
            .encode(&mut buf);
            assert!(matches!(
                Header::parse(&buf),
                Err(crate::protocol::error::OfError::InvalidLength(l)) if l == length
            ));
        }
    }

    #[test]
    fn decoder_never_panics_on_deterministic_mutations() {
        use std::panic::{catch_unwind, AssertUnwindSafe};

        let corpus = [
            Encoder::hello(1).unwrap(),
            Encoder::features_request(2),
            Encoder::echo_request(3, &[1, 2, 3, 4]).unwrap(),
            Encoder::set_config(4, 0, 128),
            Encoder::get_config_request(5),
            Encoder::barrier_request(6),
            Encoder::role_request(7, OFPCR_ROLE_EQUAL, 9, 0).unwrap(),
            Encoder::flow_mod(&Rule::add(8, 0, 100, Match::any(), Vec::new())).unwrap(),
        ];

        for original in corpus {
            for position in 0..original.len() {
                let mut mutated = original.clone();
                if let Some(byte) = mutated.get_mut(position) {
                    *byte ^= 0x5a;
                }
                assert!(
                    catch_unwind(AssertUnwindSafe(|| Decoder::message(&mutated))).is_ok(),
                    "decoder panicked after mutating byte {position}"
                );
            }
        }

        let mut state = 0x9e37_79b9_u32;
        for _ in 0..4096 {
            state = state.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
            let length = usize::try_from(state & 0x1ff).unwrap_or(0);
            let mut arbitrary = vec![0_u8; length];
            for byte in &mut arbitrary {
                state = state.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
                *byte = u8::try_from(state >> 24).unwrap_or(0);
            }
            assert!(
                catch_unwind(AssertUnwindSafe(|| Decoder::message(&arbitrary))).is_ok(),
                "decoder panicked for deterministic arbitrary frame"
            );
        }
    }

    #[test]
    fn test_features_reply_parse_fixed_bytes() {
        use crate::protocol::features::Reply;

        let mut frame = Vec::new();
        Header {
            version: OFP_VERSION_1_5,
            msg_type: OFPT_FEATURES_REPLY,
            length: 32,
            xid: 55,
        }
        .encode(&mut frame);
        frame.extend_from_slice(&0x0102_0304_0506_0708u64.to_be_bytes()); // datapath_id [8..16]
        frame.extend_from_slice(&99u32.to_be_bytes()); // n_buffers [16..20]
        frame.push(4); // n_tables [20]
        frame.push(7); // auxiliary_id [21]
        frame.extend_from_slice(&[0u8; 2]); // pad [22..24]
        frame.extend_from_slice(&0x0000_003fu32.to_be_bytes()); // capabilities [24..28]
        frame.extend_from_slice(&[0u8; 4]); // reserved [28..32]

        let reply = Reply::parse(&frame).unwrap();
        assert_eq!(reply.xid, 55);
        assert_eq!(reply.datapath_id, 0x0102_0304_0506_0708);
        assert_eq!(reply.n_buffers, 99);
        assert_eq!(reply.n_tables, 4);
        assert_eq!(reply.auxiliary_id, 7);
        assert_eq!(reply.capabilities, 0x0000_003f);
    }

    #[test]
    fn test_features_reply_parse_rejects_invalid_length() {
        use crate::protocol::features::Reply;

        let mut frame = Vec::new();
        Header {
            version: OFP_VERSION_1_5,
            msg_type: OFPT_FEATURES_REPLY,
            length: 31,
            xid: 1,
        }
        .encode(&mut frame);
        frame.extend_from_slice(&[0u8; 23]); // one byte short of the required 32.

        assert!(matches!(
            Reply::parse(&frame),
            Err(crate::protocol::error::OfError::InvalidLength(31))
        ));
    }

    #[test]
    fn decoder_rejects_bodies_on_header_only_messages() {
        for mut frame in [
            Encoder::features_request(1),
            Encoder::get_config_request(2),
            Encoder::get_async_request(3).unwrap(),
            Encoder::barrier_request(4),
            Encoder::barrier_reply(5),
        ] {
            frame[2..4].copy_from_slice(&9u16.to_be_bytes());
            frame.push(0);
            assert!(matches!(
                Decoder::message(&frame),
                Err(OfError::InvalidLength(9))
            ));
        }
    }

    #[test]
    fn hello_rejects_a_non_word_aligned_version_bitmap() {
        let mut frame = Vec::new();
        Header {
            version: OFP_VERSION_1_5,
            msg_type: OFPT_HELLO,
            length: 16,
            xid: 1,
        }
        .encode(&mut frame);
        frame.extend_from_slice(&OFPHET_VERSIONBITMAP.to_be_bytes());
        frame.extend_from_slice(&5u16.to_be_bytes());
        frame.push(OFP_VERSION_1_5);
        frame.extend_from_slice(&[0; 3]);

        assert!(matches!(
            Hello::parse(&frame),
            Err(OfError::InvalidLength(16))
        ));
    }

    #[test]
    fn hello_rejects_bad_message_alignment_and_accepts_element_padding() {
        let mut frame = Vec::new();
        Header {
            version: OFP_VERSION_1_5,
            msg_type: OFPT_HELLO,
            length: 16,
            xid: 1,
        }
        .encode(&mut frame);
        frame.extend_from_slice(&0xffffu16.to_be_bytes());
        frame.extend_from_slice(&4u16.to_be_bytes());
        frame.extend_from_slice(&[1, 0, 0, 0]);
        assert!(Hello::parse(&frame).is_ok());

        frame[2..4].copy_from_slice(&9u16.to_be_bytes());
        frame.truncate(9);
        assert!(Hello::parse(&frame).is_err());
    }

    #[test]
    fn oxm_masked_unknown_fields_require_equal_value_and_mask_lengths() {
        let buf = [0x12, 0x34, 0x03, 0x03, 1, 2, 3];
        assert!(crate::protocol::oxm::parse_oxm_list_unchecked(&buf).is_err());
    }

    #[test]
    fn oxs_rejects_a_non_zero_reserved_bit() {
        let mut frame = crate::protocol::oxs::encode_oxs_list(&[OxsTlv::FlowCount(1)]).unwrap();
        frame[2] |= 1;
        assert!(crate::protocol::oxs::parse_oxs_list(&frame).is_err());
        assert!(crate::protocol::oxs::encode_oxs_list(&[OxsTlv::Raw {
            class: 1,
            field: 0x80,
            data: vec![1],
        }])
        .is_err());
    }

    #[test]
    fn test_oxm_parse_list_round_trips_masked_and_unmasked_fields() {
        use crate::protocol::oxm::{self, Tlv};

        let mut buf = Vec::new();
        buf.extend_from_slice(&oxm::eth_type(ETH_TYPE_IPV4));
        buf.extend_from_slice(&oxm::ip_proto(6));
        buf.extend_from_slice(&oxm::ipv4_src_masked([10, 0, 0, 0], [255, 255, 255, 0]));

        let tlvs = oxm::parse_oxm_list(&buf).unwrap();
        assert_eq!(
            tlvs,
            vec![
                Tlv::Basic {
                    field: OFPXMT_OFB_ETH_TYPE,
                    value: ETH_TYPE_IPV4.to_be_bytes().to_vec(),
                    mask: None,
                },
                Tlv::Basic {
                    field: OFPXMT_OFB_IP_PROTO,
                    value: vec![6],
                    mask: None,
                },
                Tlv::Basic {
                    field: OFPXMT_OFB_IPV4_SRC,
                    value: vec![10, 0, 0, 0],
                    mask: Some(vec![255, 255, 255, 0]),
                },
            ]
        );
    }

    /// `TUNNEL_ID` is one of the spec's 15 maskable basic fields
    /// (`OXM_OF_TUNNEL_ID_W`); it used to be rejected as unmaskable.
    /// 1.5 lets a non-Ethernet pipeline satisfy the IP-family
    /// prerequisites with `PACKET_TYPE` instead of `ETH_TYPE`.
    #[test]
    fn test_oxm_prerequisites_accept_packet_type_instead_of_eth_type() {
        use crate::protocol::constants::{OFPXMT_OFB_IPV4_SRC, OFPXMT_OFB_PACKET_TYPE};
        use crate::protocol::oxm;

        // PACKET_TYPE (1, 0x0800) stands in for eth_type=0x0800.
        let mut buf = oxm::field(OFPXMT_OFB_PACKET_TYPE, &0x0001_0800u32.to_be_bytes()).unwrap();
        buf.extend_from_slice(&oxm::ipv4_src([10, 0, 0, 1]));
        assert!(oxm::parse_oxm_list(&buf).is_ok());

        // The wrong packet type does not.
        let mut wrong = oxm::field(OFPXMT_OFB_PACKET_TYPE, &0x0001_86ddu32.to_be_bytes()).unwrap();
        wrong.extend_from_slice(&oxm::ipv4_src([10, 0, 0, 1]));
        assert!(matches!(
            oxm::parse_oxm_list(&wrong),
            Err(OfError::MissingOxmPrerequisite {
                field: OFPXMT_OFB_IPV4_SRC
            })
        ));

        // PACKET_TYPE must be the first TLV.
        let mut late = oxm::eth_type(ETH_TYPE_IPV4);
        late.extend_from_slice(
            &oxm::field(OFPXMT_OFB_PACKET_TYPE, &0x0001_0800u32.to_be_bytes()).unwrap(),
        );
        assert!(matches!(
            oxm::parse_oxm_list(&late),
            Err(OfError::MissingOxmPrerequisite {
                field: OFPXMT_OFB_PACKET_TYPE
            })
        ));
    }

    #[test]
    fn test_oxm_parse_list_accepts_masked_tunnel_id() {
        use crate::protocol::constants::OFPXMT_OFB_TUNNEL_ID;
        use crate::protocol::oxm::{self, Tlv};

        let buf = oxm::masked_field(
            OFPXMT_OFB_TUNNEL_ID,
            &5u64.to_be_bytes(),
            &u64::MAX.to_be_bytes(),
        )
        .unwrap();

        assert_eq!(
            oxm::parse_oxm_list(&buf).unwrap(),
            vec![Tlv::Basic {
                field: OFPXMT_OFB_TUNNEL_ID,
                value: 5u64.to_be_bytes().to_vec(),
                mask: Some(u64::MAX.to_be_bytes().to_vec()),
            }]
        );
    }

    /// A masked TLV in a class this crate doesn't model (here Nicira's
    /// `OFPXMC_NXM_1` `ct_state`) must still split value from mask.
    #[test]
    fn test_oxm_parse_list_splits_mask_for_unmodelled_class() {
        use crate::protocol::constants::{NXM_NX_CT_STATE, NX_CS_RPL, NX_CS_TRK, OFPXMC_NXM_1};
        use crate::protocol::oxm::{self, Tlv};

        let bits = NX_CS_TRK | NX_CS_RPL;
        let tlvs = oxm::parse_oxm_list(&oxm::ct_state_masked(bits, bits)).unwrap();

        assert_eq!(
            tlvs,
            vec![Tlv::Other {
                class: OFPXMC_NXM_1,
                field: NXM_NX_CT_STATE,
                value: bits.to_be_bytes().to_vec(),
                mask: Some(bits.to_be_bytes().to_vec()),
            }]
        );
    }

    /// Spec 7.2.3.3: when `oxm_hasmask` is 1, `oxm_length` is the field's
    /// value length *doubled* (value bytes followed by mask bytes of the
    /// same width), and is therefore always even.
    #[test]
    fn test_oxm_masked_field_length_is_doubled() {
        use crate::protocol::oxm;

        let encoded = oxm::ipv4_src_masked([10, 0, 0, 0], [255, 255, 255, 0]);
        // TLV header: class(2) + field/hasmask(1) + length(1), then the
        // length byte at offset 3.
        let oxm_length = encoded[3];
        assert_eq!(
            oxm_length, 8,
            "IPv4 is a 4-byte field; masked length must be 2*4=8"
        );
        assert_eq!(encoded.len(), 4 + usize::from(oxm_length));
    }

    #[test]
    fn test_oxm_parse_list_rejects_duplicate_field() {
        let mut buf = Vec::new();
        buf.extend_from_slice(&crate::protocol::oxm::in_port(1));
        buf.extend_from_slice(&crate::protocol::oxm::in_port(2));
        assert!(matches!(
            crate::protocol::oxm::parse_oxm_list(&buf),
            Err(crate::protocol::error::OfError::DuplicateOxmField { .. })
        ));
    }

    #[test]
    fn test_oxm_parse_list_rejects_missing_prerequisite() {
        let buf = crate::protocol::oxm::ip_proto(6);
        assert!(matches!(
            crate::protocol::oxm::parse_oxm_list(&buf),
            Err(crate::protocol::error::OfError::MissingOxmPrerequisite { .. })
        ));
    }

    #[test]
    fn test_oxm_parse_list_rejects_unknown_field_and_bad_mask() {
        use crate::protocol::error::OfError;
        use crate::protocol::oxm::parse_oxm_list;

        // field id 40 is not defined by the spec.
        assert!(matches!(
            parse_oxm_list(&crate::protocol::oxm::field(40, &[0, 0]).unwrap()),
            Err(OfError::UnknownOxmField { .. })
        ));

        // eth_type does not support masking.
        assert!(matches!(
            parse_oxm_list(
                &crate::protocol::oxm::masked_field(
                    OFPXMT_OFB_ETH_TYPE,
                    &[0x08, 0x00],
                    &[0xff, 0xff],
                )
                .unwrap()
            ),
            Err(OfError::InvalidOxmLength)
        ));
    }

    #[test]
    fn test_oxs_list_round_trips_and_rejects_duplicates() {
        use crate::protocol::oxs::{encode_oxs_list, parse_oxs_list};

        let tlvs = vec![
            OxsTlv::Duration { sec: 10, nsec: 20 },
            OxsTlv::PacketCount(100),
            OxsTlv::ByteCount(2000),
        ];
        let encoded = encode_oxs_list(&tlvs).unwrap();
        assert_eq!(parse_oxs_list(&encoded).unwrap(), tlvs);

        let dup = encode_oxs_list(&[OxsTlv::FlowCount(1), OxsTlv::FlowCount(2)]).unwrap();
        assert!(matches!(
            parse_oxs_list(&dup),
            Err(crate::protocol::error::OfError::DuplicateOxmField { .. })
        ));
    }

    #[test]
    fn empty_match_is_8_bytes() {
        let m = Match::any();
        let mut out = Vec::new();
        m.encode(&mut out).unwrap();

        assert_eq!(out.len(), 8);
        assert_eq!(&out[0..2], &1u16.to_be_bytes());
        assert_eq!(&out[2..4], &4u16.to_be_bytes());
    }

    #[test]
    fn output_action_test() {
        let action = Action::output(2);
        let mut out = Vec::new();
        action.encode(&mut out).unwrap();

        assert_eq!(out.len(), 16);
        assert_eq!(&out[0..2], &0u16.to_be_bytes());
        assert_eq!(&out[2..4], &16u16.to_be_bytes());
        assert_eq!(&out[4..8], &2u32.to_be_bytes());
    }

    #[test]
    fn test_standard_actions_encode_and_parse() {
        let actions = vec![
            Action::Output {
                port: 2,
                max_len: 128,
            },
            Action::CopyTtlOut,
            Action::CopyTtlIn,
            Action::SetMplsTtl(64),
            Action::DecMplsTtl,
            Action::PushVlan(0x8100),
            Action::PopVlan,
            Action::PushMpls(0x8847),
            Action::PopMpls(0x0800),
            Action::SetQueue(7),
            Action::Group(9),
            Action::SetNwTtl(32),
            Action::DecNwTtl,
            Action::SetField(crate::protocol::oxm::eth_type(ETH_TYPE_IPV4)),
            Action::PushPbb(0x88e7),
            Action::PopPbb,
            Action::CopyField {
                n_bits: 16,
                src_offset: 0,
                dst_offset: 8,
                oxm_ids: crate::protocol::oxm::copy_field_ids(
                    OFPXMT_OFB_ETH_SRC,
                    6,
                    OFPXMT_OFB_ETH_DST,
                    6,
                ),
            },
            Action::Meter(5),
            Action::Experimenter {
                experimenter: 0x0102_0304,
                data: vec![1, 2, 3, 4, 0, 0, 0, 0],
            },
        ];

        let mut encoded = Vec::new();
        for action in &actions {
            action.encode(&mut encoded).unwrap();
        }

        let parsed = parse_actions(&encoded).unwrap();
        assert_eq!(parsed, actions);
    }

    #[test]
    fn test_action_parser_rejects_bad_length_and_accepts_padding() {
        let err = parse_actions(&[0, 0, 0, 7, 0, 0, 0, 0]).unwrap_err();
        assert!(matches!(
            err,
            crate::protocol::error::OfError::InvalidLength(7)
        ));

        let mut output = Vec::new();
        Action::output(2).encode(&mut output).unwrap();
        output[15] = 1;
        assert!(parse_actions(&output).is_ok());

        let mut set_field = Vec::new();
        Action::SetField(crate::protocol::oxm::eth_type(ETH_TYPE_IPV4))
            .encode(&mut set_field)
            .unwrap();
        set_field[7] = 4;
        assert!(matches!(
            parse_actions(&set_field),
            Err(crate::protocol::error::OfError::InvalidOxmLength)
        ));

        let mut copy_field = Vec::new();
        Action::CopyField {
            n_bits: 16,
            src_offset: 0,
            dst_offset: 0,
            oxm_ids: crate::protocol::oxm::copy_field_ids(
                OFPXMT_OFB_ETH_SRC,
                6,
                OFPXMT_OFB_ETH_DST,
                6,
            ),
        }
        .encode(&mut copy_field)
        .unwrap();
        copy_field[4..6].copy_from_slice(&49u16.to_be_bytes());
        assert!(matches!(
            parse_actions(&copy_field),
            Err(crate::protocol::error::OfError::InvalidValue {
                field: "copy_field_bit_range",
                ..
            })
        ));
    }

    #[test]
    fn test_unknown_action_encode_is_aligned() {
        let action = Action::Unknown {
            action_type: 0xBEEF,
            data: vec![1, 2, 3],
        };

        let mut encoded = Vec::new();
        action.encode(&mut encoded).unwrap();

        assert_eq!(encoded.len(), 8);
        assert_eq!(&encoded[0..2], &0xBEEF_u16.to_be_bytes());
        assert_eq!(&encoded[2..4], &8u16.to_be_bytes());

        let parsed = parse_actions(&encoded).unwrap();
        match &parsed[0] {
            Action::Unknown { action_type, data } => {
                assert_eq!(*action_type, 0xBEEF);
                assert_eq!(data, &vec![1, 2, 3, 0]);
            }
            other => panic!("expected unknown action, got {other:?}"),
        }
    }

    #[test]
    fn test_standard_instructions_encode_and_parse() {
        let instructions = vec![
            Instruction::GotoTable(2),
            Instruction::WriteMetadata {
                metadata: 0x0102_0304_0506_0708,
                metadata_mask: 0xffff_ffff_0000_0000,
            },
            Instruction::WriteActions(vec![Action::SetQueue(3)]),
            Instruction::ApplyActions(vec![Action::output(4)]),
            Instruction::ClearActions,
            Instruction::StatTrigger {
                flags: OFPSTF_PERIODIC,
                thresholds: vec![OxsTlv::PacketCount(1000), OxsTlv::ByteCount(50_000)],
            },
            Instruction::Experimenter {
                experimenter: 0x0102_0304,
                data: vec![1, 2, 3, 4, 0, 0, 0, 0],
            },
        ];

        let mut encoded = Vec::new();
        for instruction in &instructions {
            instruction.encode(&mut encoded).unwrap();
        }

        let parsed = parse_instructions(&encoded).unwrap();
        assert_eq!(parsed, instructions);
    }

    #[test]
    fn test_instruction_parser_accepts_padding() {
        let mut encoded = Vec::new();
        Instruction::GotoTable(2).encode(&mut encoded).unwrap();
        encoded[7] = 1;

        assert!(parse_instructions(&encoded).is_ok());
    }

    #[test]
    fn test_unknown_instruction_encode_is_aligned() {
        let instruction = Instruction::Unknown {
            instruction_type: 0xBEEF,
            data: vec![1, 2, 3],
        };

        let mut encoded = Vec::new();
        instruction.encode(&mut encoded).unwrap();

        assert_eq!(encoded.len(), 8);
        assert_eq!(&encoded[0..2], &0xBEEF_u16.to_be_bytes());
        assert_eq!(&encoded[2..4], &8u16.to_be_bytes());

        let parsed = parse_instructions(&encoded).unwrap();
        match &parsed[0] {
            Instruction::Unknown {
                instruction_type,
                data,
            } => {
                assert_eq!(*instruction_type, 0xBEEF);
                assert_eq!(data, &vec![1, 2, 3, 0]);
            }
            other => panic!("expected unknown instruction, got {other:?}"),
        }
    }

    #[test]
    fn test_flow_mod_add() {
        let xid = 10;
        let fm = Rule::add(
            xid,
            0,
            100,
            Match::any(),
            vec![Instruction::apply_actions(vec![Action::output(2)])],
        );
        let encoded = fm.encode().unwrap();

        let header = Header::parse(&encoded[0..8]).unwrap();
        assert_eq!(header.msg_type, OFPT_FLOW_MOD);
        assert_eq!(header.xid, xid);

        // Command is at offset 8+8+8=24 (cookie(8) + cookie_mask(8) = 16 bytes, then table(1) + command(1))
        // Actual offset: header(8) + cookie(8) + mask(8) = 24.
        // table_id(24) + command(25).
        assert_eq!(encoded[25], OFPFC_ADD);

        let parsed = Decoder::flow_mod(&encoded).unwrap();
        assert_eq!(parsed.xid, xid);
        assert_eq!(parsed.table_id, 0);
        assert_eq!(parsed.command, OFPFC_ADD);
        assert_eq!(parsed.priority, 100);
        assert_eq!(parsed.instructions.len(), 1);
    }

    #[test]
    fn test_packet_in_parse() {
        let mut frame = Vec::new();
        // header: 8 bytes
        // fixed part: 16 bytes (buffer_id(4) + total_len(2) + reason(1) + table_id(1) + cookie(8))
        // match header: 4 bytes (type(2) + len(2))
        // Total so far: 8 + 16 + 4 = 28 bytes.
        let match_len = 4;
        let padded_match_len = 8;
        let payload = b"abc";
        let total_len = 8 + 16 + padded_match_len + 2 + payload.len();

        Header {
            version: OFP_VERSION_1_5,
            msg_type: OFPT_PACKET_IN,
            length: total_len as u16,
            xid: 1,
        }
        .encode(&mut frame);

        frame.extend_from_slice(&[0u8; 16]); // fixed
        frame[12..14].copy_from_slice(&(payload.len() as u16).to_be_bytes());
        frame.extend_from_slice(&1u16.to_be_bytes()); // type=1
        frame.extend_from_slice(&(match_len as u16).to_be_bytes());
        frame.extend_from_slice(&[0u8; 4]); // Padded to 8
        frame.extend_from_slice(&[0u8; 2]); // Padding
        frame.extend_from_slice(payload);
        frame.extend_from_slice(b"trailing bytes");

        let pkt = PacketIn::parse(&frame).unwrap();
        assert_eq!(pkt.xid, 1);
        assert_eq!(pkt.data, payload);
    }

    /// A packet-in's match may carry any pipeline field the switch
    /// knows, not just the two with named accessors; all of them must
    /// survive the parse.
    /// Every message type now encodes *and* decodes, including the
    /// switch-side halves a controller-only build used to skip.
    #[test]
    fn test_switch_side_encode_decode_round_trips() {
        use crate::protocol::config::Config;
        use crate::protocol::control::{
            parse_async_flow_removed, parse_async_port_status, parse_async_request_forward,
            parse_async_role_status, ControllerStatus, FlowRemoved, PortStatus, RequestForward,
            RoleStatus,
        };
        use crate::protocol::features::{Reply, Request as FeaturesRequest};
        use crate::protocol::packet_out::PacketOut;

        // OFPT_FEATURES_REQUEST / _REPLY
        let features_request = FeaturesRequest::new(11);
        assert_eq!(
            FeaturesRequest::parse(&features_request.encode()).unwrap(),
            features_request
        );
        let reply = Reply {
            xid: 12,
            datapath_id: 0x0000_0000_0000_00ff,
            n_buffers: 256,
            n_tables: 254,
            auxiliary_id: 0,
            capabilities: OFPC_FLOW_STATS | OFPC_TABLE_STATS,
            reserved: 0,
        };
        let Message::FeaturesReply(parsed) = decode(&reply.encode()).unwrap() else {
            panic!("expected a features reply");
        };
        assert_eq!(parsed, reply);

        // OFPT_GET_CONFIG_REQUEST / OFPT_SET_CONFIG
        assert_eq!(
            Config::parse_get_request(&Config::get_request(13)).unwrap(),
            13
        );
        let config = Config::new(14, OFPC_FRAG_REASM, 128);
        let Message::SetConfig(parsed) = decode(&config.encode_set()).unwrap() else {
            panic!("expected a set-config");
        };
        assert_eq!(parsed, config);

        // OFPT_PACKET_OUT
        let packet_out = PacketOut::new(
            15,
            OFP_NO_BUFFER,
            Some(3),
            vec![Action::output(2), Action::SetQueue(1)],
            b"payload".to_vec(),
        );
        let Message::PacketOut(parsed) = decode(&packet_out.encode().unwrap()).unwrap() else {
            panic!("expected a packet-out");
        };
        assert_eq!(parsed.buffer_id, packet_out.buffer_id);
        assert_eq!(parsed.actions, packet_out.actions);
        assert_eq!(parsed.of_match, packet_out.of_match);
        assert_eq!(parsed.data, b"payload");

        // OFPT_PACKET_IN
        let packet_in = PacketIn {
            xid: 16,
            buffer_id: OFP_NO_BUFFER,
            total_len: 5,
            reason: OFPR_APPLY_ACTION,
            table_id: 1,
            cookie: 77,
            of_match: crate::protocol::oxm::parse_oxm_list(&crate::protocol::oxm::in_port(9))
                .unwrap(),
            data: b"frame".to_vec(),
        };
        let reparsed = PacketIn::parse(&packet_in.encode().unwrap()).unwrap();
        assert_eq!(reparsed.in_port(), Some(9));
        assert_eq!(reparsed.cookie, 77);
        assert_eq!(reparsed.data, b"frame");

        // OFPT_FLOW_REMOVED
        let removed = FlowRemoved {
            xid: 17,
            table_id: 2,
            reason: OFPRR_IDLE_TIMEOUT,
            priority: 10,
            idle_timeout: 30,
            hard_timeout: 0,
            cookie: 5,
            of_match: crate::protocol::oxm::in_port(1),
            stats: vec![OxsTlv::PacketCount(4)],
        };
        assert_eq!(
            parse_async_flow_removed(&removed.encode().unwrap()).unwrap(),
            removed
        );

        // OFPT_PORT_STATUS
        let status = PortStatus {
            xid: 18,
            reason: OFPPR_MODIFY,
            desc: PortDescEntry {
                port_no: 4,
                hw_addr: [1, 2, 3, 4, 5, 6],
                name: "eth0".into(),
                config: 0,
                state: 0,
                properties: vec![],
            },
        };
        assert_eq!(
            parse_async_port_status(&status.encode().unwrap()).unwrap(),
            status
        );

        // OFPT_ROLE_STATUS
        let role_status = RoleStatus {
            xid: 19,
            role: OFPCR_ROLE_MASTER,
            reason: 0,
            generation_id: 42,
            properties: vec![],
        };
        assert_eq!(
            parse_async_role_status(&role_status.encode().unwrap()).unwrap(),
            role_status
        );

        // OFPT_REQUESTFORWARD carries a whole nested message.
        let forward = RequestForward {
            xid: 20,
            request: encode_barrier_request(99),
        };
        assert_eq!(
            parse_async_request_forward(&forward.encode().unwrap()).unwrap(),
            forward
        );

        // OFPT_CONTROLLER_STATUS
        let controller_status = ControllerStatus {
            xid: 21,
            length: 0,
            short_id: 1,
            role: OFPCR_ROLE_EQUAL,
            reason: OFPCSR_REQUEST,
            channel_status: OFPCT_STATUS_UP,
            properties: vec![ControllerStatusProperty::Uri("tls:10.0.0.1:6653".into())],
        };
        let reparsed = parse_async_controller_status(&controller_status.encode().unwrap()).unwrap();
        assert_eq!(reparsed.properties, controller_status.properties);
        assert_eq!(reparsed.short_id, 1);

        // OFPT_EXPERIMENTER
        let experimenter = Encoder::experimenter(22, 0x0000_2320, 7, &[1, 2, 3, 4]).unwrap();
        let Message::Experimenter {
            experimenter: id,
            exp_type,
            data,
            ..
        } = decode(&experimenter).unwrap()
        else {
            panic!("expected an experimenter message");
        };
        assert_eq!((id, exp_type, data), (0x0000_2320, 7, vec![1, 2, 3, 4]));
    }

    #[test]
    fn test_packet_in_keeps_whole_match() {
        use crate::protocol::constants::{OFPXMT_OFB_METADATA, OFPXMT_OFB_TUNNEL_ID};

        let mut oxms = crate::protocol::oxm::in_port(7);
        oxms.extend_from_slice(
            &crate::protocol::oxm::field(OFPXMT_OFB_METADATA, &9u64.to_be_bytes()).unwrap(),
        );
        oxms.extend_from_slice(
            &crate::protocol::oxm::field(OFPXMT_OFB_TUNNEL_ID, &4242u64.to_be_bytes()).unwrap(),
        );
        let match_len = 4 + oxms.len();
        let padded = match_len.div_ceil(8) * 8;
        let payload = b"hello";

        let mut frame = Vec::new();
        Header {
            version: OFP_VERSION_1_5,
            msg_type: OFPT_PACKET_IN,
            length: u16::try_from(24 + padded + 2 + payload.len()).unwrap(),
            xid: 3,
        }
        .encode(&mut frame);
        frame.extend_from_slice(&[0u8; 16]);
        frame[12..14].copy_from_slice(&(payload.len() as u16).to_be_bytes());
        frame.extend_from_slice(&OFPMT_OXM.to_be_bytes());
        frame.extend_from_slice(&u16::try_from(match_len).unwrap().to_be_bytes());
        frame.extend_from_slice(&oxms);
        frame.extend_from_slice(&vec![0u8; padded - match_len]);
        frame.extend_from_slice(&[0u8; 2]);
        frame.extend_from_slice(payload);

        let pkt = PacketIn::parse(&frame).unwrap();
        assert_eq!(pkt.in_port(), Some(7));
        assert_eq!(pkt.metadata(), Some(9));
        assert_eq!(
            pkt.field(OFPXMT_OFB_TUNNEL_ID),
            Some(4242u64.to_be_bytes().as_slice())
        );
        assert_eq!(pkt.of_match.len(), 3);
        assert_eq!(pkt.data, payload);
    }

    #[test]
    fn test_barrier_request_and_reply_encode() {
        let req = encode_barrier_request(7);
        let req_header = Header::parse(&req).unwrap();
        assert_eq!(req_header.msg_type, OFPT_BARRIER_REQUEST);
        assert_eq!(req_header.xid, 7);

        let reply = encode_barrier_reply(7);
        let reply_header = Header::parse(&reply).unwrap();
        assert_eq!(reply_header.msg_type, OFPT_BARRIER_REPLY);
        assert_eq!(reply_header.xid, 7);
    }

    #[test]
    fn test_object_style_message_encoders() {
        let hello = Hello::new(61).encode().unwrap();
        let hello_header = Header::parse(&hello).unwrap();
        assert_eq!(hello_header.msg_type, OFPT_HELLO);
        assert_eq!(hello_header.xid, 61);

        let echo = Echo::new(62, b"payload".to_vec()).encode_request().unwrap();
        let echo_header = Header::parse(&echo).unwrap();
        assert_eq!(echo_header.msg_type, OFPT_ECHO_REQUEST);
        assert_eq!(&echo[8..], b"payload");

        let barrier = Barrier::new(63).encode_reply();
        let barrier_header = Header::parse(&barrier).unwrap();
        assert_eq!(barrier_header.msg_type, OFPT_BARRIER_REPLY);

        let features = Request::new(64).encode();
        let features_header = Header::parse(&features).unwrap();
        assert_eq!(features_header.msg_type, OFPT_FEATURES_REQUEST);

        let config = Config::new(65, 1, 256).encode_set();
        let config_header = Header::parse(&config).unwrap();
        assert_eq!(config_header.msg_type, OFPT_SET_CONFIG);
        assert_eq!(&config[8..10], &1u16.to_be_bytes());

        let packet_out = PacketOut::new(
            66,
            OFP_NO_BUFFER,
            Some(9),
            vec![Action::output(OFPP_FLOOD)],
            b"frame".to_vec(),
        )
        .encode()
        .unwrap();
        let packet_out_header = Header::parse(&packet_out).unwrap();
        assert_eq!(packet_out_header.msg_type, OFPT_PACKET_OUT);
        assert!(packet_out.ends_with(b"frame"));
    }

    #[test]
    fn test_decode_experimenter_and_barrier_request() {
        let mut exp = Vec::new();
        Header {
            version: OFP_VERSION_1_5,
            msg_type: OFPT_EXPERIMENTER,
            length: 16,
            xid: 11,
        }
        .encode(&mut exp);
        exp.extend_from_slice(&0x0102_0304u32.to_be_bytes());
        exp.extend_from_slice(&0x0506_0708u32.to_be_bytes());

        match decode(&exp).unwrap() {
            Message::Experimenter {
                xid,
                experimenter,
                exp_type,
                data,
            } => {
                assert_eq!(xid, 11);
                assert_eq!(experimenter, 0x0102_0304);
                assert_eq!(exp_type, 0x0506_0708);
                assert!(data.is_empty());
            }
            _ => panic!("expected experimenter message"),
        }

        let barrier = encode_barrier_request(9);
        match decode(&barrier).unwrap() {
            Message::BarrierRequest { xid } => assert_eq!(xid, 9),
            _ => panic!("expected barrier request"),
        }
    }

    #[test]
    fn test_error_message_encode_and_parse() {
        let encoded = Encoder::error(44, 1, 2, b"bad").unwrap();
        let parsed = Decoder::error(&encoded).unwrap();
        assert_eq!(parsed.xid, 44);
        assert_eq!(parsed.error_type, 1);
        assert_eq!(parsed.code, 2);
        assert_eq!(parsed.data, b"bad");

        match Decoder::message(&encoded).unwrap() {
            Message::Error(msg) => {
                assert_eq!(msg.error_type, 1);
                assert_eq!(msg.code, 2);
            }
            _ => panic!("expected error message"),
        }
    }

    #[test]
    fn test_error_experimenter_id_and_data_accessors() {
        use crate::protocol::constants::OFPET_EXPERIMENTER;

        let mut data = 0xdead_beefu32.to_be_bytes().to_vec();
        data.extend_from_slice(b"payload");
        let encoded = Encoder::error(1, OFPET_EXPERIMENTER, 7, &data).unwrap();
        let parsed = Decoder::error(&encoded).unwrap();

        assert_eq!(parsed.experimenter_id(), Some(0xdead_beef));
        assert_eq!(parsed.experimenter_data(), Some(&b"payload"[..]));

        let non_experimenter = Encoder::error(1, 1, 2, b"bad").unwrap();
        let parsed = Decoder::error(&non_experimenter).unwrap();
        assert_eq!(parsed.experimenter_id(), None);
        assert_eq!(parsed.experimenter_data(), None);
    }

    #[test]
    fn test_error_type_round_trips_known_and_unknown_codes() {
        use crate::protocol::error_msg::{
            BadActionCode, BundleFailedCode, ErrorMessage, ErrorType,
        };

        let msg = ErrorMessage::from_kind(
            9,
            ErrorType::BadAction(BadActionCode::BadOutPort),
            vec![1, 2, 3],
        );
        assert_eq!(msg.error_type, OFPET_BAD_ACTION);
        assert_eq!(msg.code, OFPBAC_BAD_OUT_PORT);
        assert_eq!(msg.kind(), ErrorType::BadAction(BadActionCode::BadOutPort));

        let msg =
            ErrorMessage::from_kind(10, ErrorType::BundleFailed(BundleFailedCode::BadId), vec![]);
        assert_eq!(msg.error_type, OFPET_BUNDLE_FAILED);
        assert_eq!(msg.code, OFPBFC_BAD_ID);

        // Unrecognized type/code pairs must decode losslessly rather than error,
        // since a switch may send codes newer than this crate knows about.
        let unknown = ErrorType::parse(0x1234, 0x5678);
        assert_eq!(
            unknown,
            ErrorType::Unknown {
                error_type: 0x1234,
                code: 0x5678
            }
        );
        assert_eq!(unknown.as_wire(), (0x1234, 0x5678));

        let unknown_code = ErrorType::parse(OFPET_BAD_ACTION, 0xffff);
        assert_eq!(
            unknown_code,
            ErrorType::BadAction(BadActionCode::Unknown(0xffff))
        );
        assert_eq!(unknown_code.as_wire(), (OFPET_BAD_ACTION, 0xffff));
    }

    /// Every `OFPET_*` category must round-trip through `ErrorType::parse`/
    /// `as_wire` with its correct numeric wire value. A transposed code
    /// constant in `error_msg.rs` (e.g. two codes swapped within one
    /// category) would slip past `test_error_type_round_trips_known_and_unknown_codes`,
    /// which only exercises 2 of the 18 `OFPET_*` categories.
    #[test]
    fn test_error_type_covers_all_categories() {
        use crate::protocol::error_msg::{
            AsyncConfigFailedCode, BadInstructionCode, BadMatchCode, BadPropertyCode,
            BadRequestCode, ErrorType, FlowModFailedCode, FlowMonitorFailedCode,
            GroupModFailedCode, HelloFailedCode, MeterModFailedCode, PortModFailedCode,
            QueueOpFailedCode, RoleRequestFailedCode, SwitchConfigFailedCode,
            TableFeaturesFailedCode, TableModFailedCode,
        };

        let cases: Vec<(ErrorType, u16, u16)> = vec![
            (
                ErrorType::HelloFailed(HelloFailedCode::Incompatible),
                OFPET_HELLO_FAILED,
                OFPHFC_INCOMPATIBLE,
            ),
            (
                ErrorType::BadRequest(BadRequestCode::BadVersion),
                OFPET_BAD_REQUEST,
                OFPBRC_BAD_VERSION,
            ),
            (
                ErrorType::BadInstruction(BadInstructionCode::UnknownInst),
                OFPET_BAD_INSTRUCTION,
                OFPBIC_UNKNOWN_INST,
            ),
            (
                ErrorType::BadMatch(BadMatchCode::BadType),
                OFPET_BAD_MATCH,
                OFPBMC_BAD_TYPE,
            ),
            (
                ErrorType::FlowModFailed(FlowModFailedCode::TableFull),
                OFPET_FLOW_MOD_FAILED,
                OFPFMFC_TABLE_FULL,
            ),
            (
                ErrorType::GroupModFailed(GroupModFailedCode::GroupExists),
                OFPET_GROUP_MOD_FAILED,
                OFPGMFC_GROUP_EXISTS,
            ),
            (
                ErrorType::PortModFailed(PortModFailedCode::BadPort),
                OFPET_PORT_MOD_FAILED,
                OFPPMFC_BAD_PORT,
            ),
            (
                ErrorType::TableModFailed(TableModFailedCode::BadTable),
                OFPET_TABLE_MOD_FAILED,
                OFPTMFC_BAD_TABLE,
            ),
            (
                ErrorType::QueueOpFailed(QueueOpFailedCode::BadPort),
                OFPET_QUEUE_OP_FAILED,
                OFPQOFC_BAD_PORT,
            ),
            (
                ErrorType::SwitchConfigFailed(SwitchConfigFailedCode::BadFlags),
                OFPET_SWITCH_CONFIG_FAILED,
                OFPSCFC_BAD_FLAGS,
            ),
            (
                ErrorType::RoleRequestFailed(RoleRequestFailedCode::Stale),
                OFPET_ROLE_REQUEST_FAILED,
                OFPRRFC_STALE,
            ),
            (
                ErrorType::MeterModFailed(MeterModFailedCode::UnknownFailure),
                OFPET_METER_MOD_FAILED,
                OFPMMFC_UNKNOWN,
            ),
            (
                ErrorType::TableFeaturesFailed(TableFeaturesFailedCode::BadTable),
                OFPET_TABLE_FEATURES_FAILED,
                OFPTFFC_BAD_TABLE,
            ),
            (
                ErrorType::BadProperty(BadPropertyCode::BadType),
                OFPET_BAD_PROPERTY,
                OFPBPC_BAD_TYPE,
            ),
            (
                ErrorType::AsyncConfigFailed(AsyncConfigFailedCode::Invalid),
                OFPET_ASYNC_CONFIG_FAILED,
                OFPACFC_INVALID,
            ),
            (
                ErrorType::FlowMonitorFailed(FlowMonitorFailedCode::UnknownFailure),
                OFPET_FLOW_MONITOR_FAILED,
                OFPMOFC_UNKNOWN,
            ),
        ];

        for (kind, expected_type, expected_code) in cases {
            assert_eq!(kind.as_wire(), (expected_type, expected_code));
            assert_eq!(ErrorType::parse(expected_type, expected_code), kind);
        }
    }

    #[test]
    fn test_decoder_respects_header_length() {
        let mut echo = Encoder::echo_request(45, b"abc").unwrap();
        echo.extend_from_slice(b"trailing bytes from caller buffer");

        match Decoder::message(&echo).unwrap() {
            Message::EchoRequest { xid, payload } => {
                assert_eq!(xid, 45);
                assert_eq!(payload, b"abc");
            }
            _ => panic!("expected echo request"),
        }
    }

    #[test]
    fn test_get_config_encode_and_parse() {
        let req = encode_get_config_request(3);
        let req_header = Header::parse(&req).unwrap();
        assert_eq!(req_header.msg_type, OFPT_GET_CONFIG_REQUEST);
        assert_eq!(req_header.xid, 3);

        let reply = encode_get_config_reply(4, 0x0001, 128);
        let reply_header = Header::parse(&reply).unwrap();
        assert_eq!(reply_header.msg_type, OFPT_GET_CONFIG_REPLY);
        assert_eq!(reply_header.xid, 4);

        let parsed = parse_get_config_reply(&reply).unwrap();
        assert_eq!(parsed.flags, 0x0001);
        assert_eq!(parsed.miss_send_len, 128);

        let set = encode_set(5, 0x0002, OFP_DEFAULT_MISS_SEND_LEN);
        let set_header = Header::parse(&set).unwrap();
        assert_eq!(set_header.msg_type, OFPT_SET_CONFIG);
        assert_eq!(set_header.xid, 5);
    }

    #[test]
    fn test_encoder_decoder_facade_round_trips_core_messages() {
        let echo = Encoder::echo_request(41, b"abc").unwrap();
        match Decoder::message(&echo).unwrap() {
            Message::EchoRequest { xid, payload } => {
                assert_eq!(xid, 41);
                assert_eq!(payload, b"abc");
            }
            _ => panic!("expected echo request"),
        }

        let barrier = Encoder::barrier_reply(42);
        match Decoder::message(&barrier).unwrap() {
            Message::BarrierReply { xid } => assert_eq!(xid, 42),
            _ => panic!("expected barrier reply"),
        }

        let actions = vec![Action::output(7), Action::SetQueue(3)];
        let mut action_bytes = Vec::new();
        for action in &actions {
            let _ = action.encode(&mut action_bytes);
        }
        assert_eq!(Decoder::actions(&action_bytes).unwrap(), actions);

        let role = Encoder::role_request(43, OFPCR_ROLE_MASTER, 2, 99).unwrap();
        let parsed = Decoder::role_request(&role).unwrap();
        assert_eq!(parsed.xid, 43);
        assert_eq!(parsed.role, OFPCR_ROLE_MASTER);
        assert_eq!(parsed.short_id, 2);
        assert_eq!(parsed.generation_id, 99);
    }

    #[test]
    fn test_multipart_request_reply_encode_and_parse() {
        let req = encode_multipart_request(6, OFPMP_DESC, OFPMPF_REQ_MORE, b"body").unwrap();
        let req_header = Header::parse(&req).unwrap();
        assert_eq!(req_header.msg_type, OFPT_MULTIPART_REQUEST);
        let parsed_req = parse_multipart_request(&req).unwrap();
        assert_eq!(parsed_req.kind, OFPMP_DESC);
        assert_eq!(parsed_req.flags, OFPMPF_REQ_MORE);
        assert_eq!(parsed_req.body, b"body");

        let reply =
            encode_multipart_reply(7, OFPMP_TABLE_STATS, OFPMPF_REPLY_MORE, b"reply").unwrap();
        let reply_header = Header::parse(&reply).unwrap();
        assert_eq!(reply_header.msg_type, OFPT_MULTIPART_REPLY);
        let parsed_reply = parse_multipart_reply(&reply).unwrap();
        assert_eq!(parsed_reply.kind, OFPMP_TABLE_STATS);
        assert_eq!(parsed_reply.flags, OFPMPF_REPLY_MORE);
        assert_eq!(parsed_reply.body, b"reply");
    }

    fn round_trip_request(
        kind: u16,
        body: crate::protocol::control::MultipartRequestBody,
    ) -> crate::protocol::control::MultipartRequestBody {
        let msg = MultipartMessage::from_request_body(1, kind, 0, &body).unwrap();
        let encoded = msg.encode_request().unwrap();
        let parsed = parse_multipart_request(&encoded).unwrap();
        assert_eq!(parsed.kind, kind);
        parsed.typed_request_body().unwrap()
    }

    fn round_trip_reply(
        kind: u16,
        body: crate::protocol::control::MultipartReplyBody,
    ) -> crate::protocol::control::MultipartReplyBody {
        let msg = MultipartMessage::from_reply_body(1, kind, 0, &body).unwrap();
        let encoded = msg.encode_reply().unwrap();
        let parsed = parse_multipart_reply(&encoded).unwrap();
        assert_eq!(parsed.kind, kind);
        parsed.typed_reply_body().unwrap()
    }

    #[test]
    fn test_multipart_desc_round_trips() {
        use crate::protocol::control::MultipartReplyBody;

        let desc = Desc {
            mfr_desc: "acme".into(),
            hw_desc: "switch-1".into(),
            sw_desc: "openflow-rs".into(),
            serial_num: "SN1".into(),
            dp_desc: "lab bridge".into(),
        };
        assert_eq!(
            round_trip_reply(OFPMP_DESC, MultipartReplyBody::Desc(desc.clone())),
            MultipartReplyBody::Desc(desc)
        );
    }

    #[test]
    fn test_multipart_flow_stats_request_round_trips_for_all_three_kinds() {
        use crate::protocol::control::MultipartRequestBody;

        let request = FlowStatsRequest {
            table_id: OFPTT_ALL,
            out_port: OFPP_ANY,
            out_group: OFPG_ANY,
            cookie: 0,
            cookie_mask: 0,
            of_match: crate::protocol::oxm::eth_type(ETH_TYPE_IPV4),
        };
        for kind in [OFPMP_FLOW_DESC, OFPMP_FLOW_STATS, OFPMP_AGGREGATE_STATS] {
            assert_eq!(
                round_trip_request(kind, MultipartRequestBody::FlowStats(request.clone())),
                MultipartRequestBody::FlowStats(request.clone())
            );
        }
    }

    #[test]
    fn test_multipart_flow_desc_and_flow_stats_reply_round_trip() {
        use crate::protocol::control::MultipartReplyBody;

        let flow_desc = FlowDesc {
            table_id: 0,
            priority: 100,
            idle_timeout: 5,
            hard_timeout: 10,
            flags: 0,
            importance: 0,
            cookie: 42,
            of_match: crate::protocol::oxm::in_port(1),
            stats: vec![OxsTlv::PacketCount(7), OxsTlv::ByteCount(700)],
            instructions: vec![Instruction::apply_actions(vec![Action::output(2)])],
        };
        assert_eq!(
            round_trip_reply(
                OFPMP_FLOW_DESC,
                MultipartReplyBody::FlowDesc(vec![flow_desc.clone()])
            ),
            MultipartReplyBody::FlowDesc(vec![flow_desc])
        );

        let flow_stats = FlowStatsEntry {
            table_id: 0,
            reason: 0,
            priority: 100,
            of_match: crate::protocol::oxm::in_port(1),
            stats: vec![OxsTlv::FlowCount(3)],
        };
        assert_eq!(
            round_trip_reply(
                OFPMP_FLOW_STATS,
                MultipartReplyBody::FlowStats(vec![flow_stats.clone()])
            ),
            MultipartReplyBody::FlowStats(vec![flow_stats])
        );
    }

    #[test]
    fn test_multipart_table_stats_round_trips() {
        use crate::protocol::control::MultipartReplyBody;

        let entry = TableStatsEntry {
            table_id: 3,
            active_count: 7,
            lookup_count: 100,
            matched_count: 90,
        };
        assert_eq!(
            round_trip_reply(
                OFPMP_TABLE_STATS,
                MultipartReplyBody::TableStats(vec![entry.clone()])
            ),
            MultipartReplyBody::TableStats(vec![entry])
        );
    }

    #[test]
    fn test_multipart_port_stats_round_trips() {
        use crate::protocol::control::MultipartReplyBody;

        assert_eq!(
            round_trip_request(
                OFPMP_PORT_STATS,
                crate::protocol::control::MultipartRequestBody::Port(PortMultipartRequest {
                    port_no: 5
                })
            ),
            crate::protocol::control::MultipartRequestBody::Port(PortMultipartRequest {
                port_no: 5
            })
        );

        let entry = PortStatsEntry {
            port_no: 5,
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
                    flags: OFPOSF_RX_TUNE | OFPOSF_TX_PWR,
                    tx_freq_lmda: 10,
                    tx_offset: 11,
                    tx_grid_span: 12,
                    rx_freq_lmda: 13,
                    rx_offset: 14,
                    rx_grid_span: 15,
                    tx_pwr: 16,
                    rx_pwr: 17,
                    bias_current: 18,
                    temperature: 19,
                },
            ],
        };
        assert_eq!(
            round_trip_reply(
                OFPMP_PORT_STATS,
                MultipartReplyBody::PortStats(vec![entry.clone()])
            ),
            MultipartReplyBody::PortStats(vec![entry])
        );
    }

    #[test]
    fn test_multipart_queue_stats_and_desc_round_trip() {
        use crate::protocol::control::{MultipartReplyBody, MultipartRequestBody};

        let request = QueueMultipartRequest {
            port_no: 1,
            queue_id: 2,
        };
        assert_eq!(
            round_trip_request(
                OFPMP_QUEUE_STATS,
                MultipartRequestBody::Queue(request.clone())
            ),
            MultipartRequestBody::Queue(request.clone())
        );

        let stats = QueueStatsEntry {
            port_no: 1,
            queue_id: 2,
            tx_bytes: 3,
            tx_packets: 4,
            tx_errors: 5,
            duration_sec: 6,
            duration_nsec: 7,
            properties: vec![QueueStatsProperty::Experimenter {
                experimenter: 0x0000_2320,
                exp_type: 2,
                data: vec![1, 2, 3, 4],
            }],
        };
        assert_eq!(
            round_trip_reply(
                OFPMP_QUEUE_STATS,
                MultipartReplyBody::QueueStats(vec![stats.clone()])
            ),
            MultipartReplyBody::QueueStats(vec![stats])
        );

        let desc = QueueDescEntry {
            port_no: 1,
            queue_id: 2,
            properties: vec![
                QueueDescProperty::MinRate(100),
                QueueDescProperty::MaxRate(OFPQ_MAX_RATE_UNCFG),
            ],
        };
        assert_eq!(
            round_trip_reply(
                OFPMP_QUEUE_DESC,
                MultipartReplyBody::QueueDesc(vec![desc.clone()])
            ),
            MultipartReplyBody::QueueDesc(vec![desc])
        );
    }

    #[test]
    fn test_multipart_group_stats_desc_and_features_round_trip() {
        use crate::protocol::control::{MultipartReplyBody, MultipartRequestBody};

        assert_eq!(
            round_trip_request(
                OFPMP_GROUP_STATS,
                MultipartRequestBody::Group(GroupMultipartRequest { group_id: 9 })
            ),
            MultipartRequestBody::Group(GroupMultipartRequest { group_id: 9 })
        );

        let stats = GroupStatsEntry {
            group_id: 9,
            ref_count: 1,
            packet_count: 2,
            byte_count: 3,
            duration_sec: 4,
            duration_nsec: 5,
            bucket_stats: vec![BucketCounter {
                packet_count: 6,
                byte_count: 7,
            }],
        };
        assert_eq!(
            round_trip_reply(
                OFPMP_GROUP_STATS,
                MultipartReplyBody::GroupStats(vec![stats.clone()])
            ),
            MultipartReplyBody::GroupStats(vec![stats])
        );

        let desc = GroupDescEntry {
            group_type: OFPGT_ALL,
            group_id: 9,
            buckets: vec![Bucket {
                bucket_id: 1,
                actions: vec![Action::output(2)],
                properties: vec![BucketProperty::Weight(1)],
            }],
            properties: vec![],
        };
        assert_eq!(
            round_trip_reply(
                OFPMP_GROUP_DESC,
                MultipartReplyBody::GroupDesc(vec![desc.clone()])
            ),
            MultipartReplyBody::GroupDesc(vec![desc])
        );

        let features = GroupFeatures {
            types: 1,
            capabilities: 2,
            max_groups: [1, 2, 3, 4],
            actions: [5, 6, 7, 8],
        };
        assert_eq!(
            round_trip_reply(
                OFPMP_GROUP_FEATURES,
                MultipartReplyBody::GroupFeatures(features.clone())
            ),
            MultipartReplyBody::GroupFeatures(features)
        );
    }

    #[test]
    fn test_multipart_meter_stats_desc_and_features_round_trip() {
        use crate::protocol::control::{MultipartReplyBody, MultipartRequestBody};

        assert_eq!(
            round_trip_request(
                OFPMP_METER_STATS,
                MultipartRequestBody::Meter(MeterMultipartRequest { meter_id: 3 })
            ),
            MultipartRequestBody::Meter(MeterMultipartRequest { meter_id: 3 })
        );

        let stats = MeterStatsEntry {
            meter_id: 3,
            ref_count: 1,
            packet_in_count: 2,
            byte_in_count: 3,
            duration_sec: 4,
            duration_nsec: 5,
            band_stats: vec![MeterBandStats {
                packet_band_count: 6,
                byte_band_count: 7,
            }],
        };
        assert_eq!(
            round_trip_reply(
                OFPMP_METER_STATS,
                MultipartReplyBody::MeterStats(vec![stats.clone()])
            ),
            MultipartReplyBody::MeterStats(vec![stats])
        );

        let desc = MeterDescEntry {
            flags: 1,
            meter_id: 3,
            bands: vec![MeterBand::Drop {
                rate: 100,
                burst_size: 10,
            }],
        };
        assert_eq!(
            round_trip_reply(
                OFPMP_METER_DESC,
                MultipartReplyBody::MeterDesc(vec![desc.clone()])
            ),
            MultipartReplyBody::MeterDesc(vec![desc])
        );

        let features = MeterFeatures {
            max_meter: 100,
            band_types: 1,
            capabilities: 2,
            max_bands: 3,
            max_color: 4,
            features: 5,
        };
        assert_eq!(
            round_trip_reply(
                OFPMP_METER_FEATURES,
                MultipartReplyBody::MeterFeatures(features.clone())
            ),
            MultipartReplyBody::MeterFeatures(features)
        );
    }

    #[test]
    fn test_multipart_table_features_and_port_desc_and_table_desc_round_trip() {
        use crate::protocol::control::MultipartReplyBody;

        let table_features = TableFeaturesEntry {
            table_id: 0,
            command: 0,
            features: 0,
            name: "table0".into(),
            metadata_match: u64::MAX,
            metadata_write: u64::MAX,
            capabilities: 0,
            max_entries: 1024,
            properties: vec![
                TableFeatureProperty::Instructions {
                    kind: OFPTFPT_INSTRUCTIONS,
                    ids: vec![
                        TypeId {
                            kind: 4,
                            data: vec![],
                        },
                        TypeId {
                            kind: 0xffff,
                            data: vec![0, 0, 0x23, 0x20],
                        },
                    ],
                },
                TableFeatureProperty::NextTables {
                    kind: OFPTFPT_NEXT_TABLES,
                    table_ids: vec![1, 2, 3],
                },
                TableFeatureProperty::Actions {
                    kind: OFPTFPT_APPLY_ACTIONS,
                    ids: vec![TypeId {
                        kind: 0,
                        data: vec![],
                    }],
                },
                TableFeatureProperty::Oxm {
                    kind: OFPTFPT_MATCH,
                    oxm_ids: vec![
                        OxmId {
                            header: 0x8000_0004,
                            experimenter: None,
                        },
                        OxmId {
                            header: 0xffff_0208,
                            experimenter: Some(0x0000_2320),
                        },
                    ],
                },
                TableFeatureProperty::PacketTypes(vec![0, 0x0001_0800]),
                TableFeatureProperty::Experimenter {
                    kind: OFPTFPT_EXPERIMENTER,
                    experimenter: 0x0000_2320,
                    exp_type: 7,
                    data: vec![9, 9, 9, 9],
                },
            ],
        };
        assert_eq!(
            round_trip_reply(
                OFPMP_TABLE_FEATURES,
                MultipartReplyBody::TableFeatures(vec![table_features.clone()])
            ),
            MultipartReplyBody::TableFeatures(vec![table_features])
        );

        let port_desc = PortDescEntry {
            port_no: 1,
            hw_addr: [1, 2, 3, 4, 5, 6],
            name: "eth0".into(),
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
                PortProperty::Recirculate(vec![7, 8]),
                PortProperty::Experimenter {
                    experimenter: 9,
                    exp_type: 10,
                    data: vec![11, 12, 13, 14],
                },
            ],
        };
        assert_eq!(
            round_trip_reply(
                OFPMP_PORT_DESC,
                MultipartReplyBody::PortDesc(vec![port_desc.clone()])
            ),
            MultipartReplyBody::PortDesc(vec![port_desc])
        );

        let table_desc = TableDescEntry {
            table_id: 0,
            config: 0,
            properties: vec![],
        };
        assert_eq!(
            round_trip_reply(
                OFPMP_TABLE_DESC,
                MultipartReplyBody::TableDesc(vec![table_desc.clone()])
            ),
            MultipartReplyBody::TableDesc(vec![table_desc])
        );
    }

    #[test]
    fn test_multipart_flow_monitor_and_controller_status_and_bundle_features_round_trip() {
        use crate::protocol::control::{MultipartReplyBody, MultipartRequestBody};

        let request = FlowMonitorRequest {
            monitor_id: 1,
            out_port: OFPP_ANY,
            out_group: OFPG_ANY,
            flags: 0,
            table_id: OFPTT_ALL,
            command: 0,
            of_match: vec![],
        };
        assert_eq!(
            round_trip_request(
                OFPMP_FLOW_MONITOR,
                MultipartRequestBody::FlowMonitor(request.clone())
            ),
            MultipartRequestBody::FlowMonitor(request)
        );

        // One of each ofp_flow_update_* payload shape.
        let updates = vec![
            FlowMonitorUpdate::Full {
                event: OFPFME_ADDED,
                table_id: 2,
                reason: 0,
                idle_timeout: 5,
                hard_timeout: 10,
                priority: 100,
                cookie: 42,
                of_match: crate::protocol::oxm::in_port(1),
                instructions: vec![Instruction::apply_actions(vec![Action::output(3)])],
            },
            FlowMonitorUpdate::Full {
                event: OFPFME_REMOVED,
                table_id: 0,
                reason: OFPRR_DELETE,
                idle_timeout: 0,
                hard_timeout: 0,
                priority: 1,
                cookie: 7,
                of_match: Vec::new(),
                instructions: Vec::new(),
            },
            FlowMonitorUpdate::Abbrev { xid: 0xdead_beef },
            FlowMonitorUpdate::Paused {
                event: OFPFME_PAUSED,
            },
        ];
        assert_eq!(
            round_trip_reply(
                OFPMP_FLOW_MONITOR,
                MultipartReplyBody::FlowMonitor(updates.clone())
            ),
            MultipartReplyBody::FlowMonitor(updates)
        );

        let status = ControllerStatusEntry {
            short_id: 1,
            role: OFPCR_ROLE_EQUAL,
            reason: OFPCSR_REQUEST,
            channel_status: OFPCT_STATUS_UP,
            properties: vec![],
        };
        assert_eq!(
            round_trip_reply(
                OFPMP_CONTROLLER_STATUS,
                MultipartReplyBody::ControllerStatus(vec![status.clone()])
            ),
            MultipartReplyBody::ControllerStatus(vec![status])
        );

        let bundle_request = BundleFeaturesRequest {
            feature_request_flags: 0,
            properties: vec![BundleFeaturesProperty::Experimenter {
                experimenter: 0x0000_2320,
                exp_type: 3,
                data: Vec::new(),
            }],
        };
        assert_eq!(
            round_trip_request(
                OFPMP_BUNDLE_FEATURES,
                MultipartRequestBody::BundleFeatures(bundle_request.clone())
            ),
            MultipartRequestBody::BundleFeatures(bundle_request)
        );

        let bundle_reply = BundleFeaturesReply {
            capabilities: OFPBF_ATOMIC,
            properties: vec![BundleFeaturesProperty::Time {
                sched_accuracy: Time {
                    seconds: 0,
                    nanoseconds: 1000,
                },
                sched_max_future: Time {
                    seconds: 60,
                    nanoseconds: 0,
                },
                sched_max_past: Time {
                    seconds: 5,
                    nanoseconds: 0,
                },
                timestamp: Time {
                    seconds: 1_700_000_000,
                    nanoseconds: 42,
                },
            }],
        };
        assert_eq!(
            round_trip_reply(
                OFPMP_BUNDLE_FEATURES,
                MultipartReplyBody::BundleFeatures(bundle_reply.clone())
            ),
            MultipartReplyBody::BundleFeatures(bundle_reply)
        );
    }

    #[test]
    fn test_multipart_experimenter_round_trips_raw() {
        use crate::protocol::control::{MultipartReplyBody, MultipartRequestBody};

        assert_eq!(
            round_trip_request(
                OFPMP_EXPERIMENTER,
                MultipartRequestBody::Experimenter(vec![1, 2, 3])
            ),
            MultipartRequestBody::Experimenter(vec![1, 2, 3])
        );
        assert_eq!(
            round_trip_reply(
                OFPMP_EXPERIMENTER,
                MultipartReplyBody::Experimenter(vec![4, 5, 6])
            ),
            MultipartReplyBody::Experimenter(vec![4, 5, 6])
        );
    }

    #[test]
    fn test_role_request_reply_encode_and_parse() {
        let req = encode_role_request(8, OFPCR_ROLE_MASTER, 9, 10).unwrap();
        let parsed_req = parse_role_request(&req).unwrap();
        assert_eq!(parsed_req.role, OFPCR_ROLE_MASTER);
        assert_eq!(parsed_req.short_id, 9);
        assert_eq!(parsed_req.generation_id, 10);

        let reply = encode_role_reply(11, OFPCR_ROLE_SLAVE, 12, 13).unwrap();
        let parsed_reply = parse_role_reply(&reply).unwrap();
        assert_eq!(parsed_reply.role, OFPCR_ROLE_SLAVE);
        assert_eq!(parsed_reply.short_id, 12);
        assert_eq!(parsed_reply.generation_id, 13);
    }

    #[test]
    fn test_async_config_encode_and_parse() {
        let get = encode_get_async_request(14).unwrap();
        let hdr = Header::parse(&get).unwrap();
        assert_eq!(hdr.msg_type, OFPT_GET_ASYNC_REQUEST);

        let props = vec![Property::ReasonMask {
            kind: OFPACPT_PACKET_IN_MASTER,
            mask: 0x3f,
        }];
        let reply = AsyncConfig {
            xid: 15,
            properties: props.clone(),
        }
        .encode_get_reply()
        .unwrap();
        let parsed_reply = parse_async_config_get_reply(&reply).unwrap();
        assert_eq!(parsed_reply.properties, props);

        let set = AsyncConfig {
            xid: 16,
            properties: vec![Property::ReasonMask {
                kind: OFPACPT_PORT_STATUS_SLAVE,
                mask: 0x7,
            }],
        }
        .encode_set()
        .unwrap();
        let parsed_set = parse_async_config_set(&set).unwrap();
        assert_eq!(
            parsed_set.properties,
            vec![Property::ReasonMask {
                kind: OFPACPT_PORT_STATUS_SLAVE,
                mask: 0x7
            }]
        );
    }

    #[test]
    fn test_table_port_group_meter_encode_and_parse() {
        let table_props = vec![
            TableModProperty::Eviction {
                flags: OFPTMPEF_IMPORTANCE,
            },
            TableModProperty::Vacancy {
                vacancy_down: 10,
                vacancy_up: 90,
                vacancy: 0,
            },
        ];
        let table = encode_table_mod(17, 2, 0x1122_3344, &table_props).unwrap();
        let parsed_table = parse_table_mod(&table).unwrap();
        assert_eq!(parsed_table.table_id, 2);
        assert_eq!(parsed_table.config, 0x1122_3344);
        assert_eq!(parsed_table.properties, table_props);

        let port_props = vec![
            PortModProperty::Ethernet {
                advertise: OFPPF_1GB_FD | OFPPF_FIBER,
            },
            PortModProperty::Optical {
                configure: OFPOPF_TX_TUNE,
                freq_lmda: 1_930_000,
                fl_offset: -12,
                grid_span: 50,
                tx_pwr: 3,
            },
        ];
        let port = encode_port_mod(
            18,
            5,
            [1, 2, 3, 4, 5, 6],
            0x0102_0304,
            0x0506_0708,
            &port_props,
        )
        .unwrap();
        let parsed_port = parse_port_mod(&port).unwrap();
        assert_eq!(parsed_port.port_no, 5);
        assert_eq!(parsed_port.hw_addr, [1, 2, 3, 4, 5, 6]);
        assert_eq!(parsed_port.config, 0x0102_0304);
        assert_eq!(parsed_port.properties, port_props);
        assert_eq!(parsed_port.mask, 0x0506_0708);

        let group = GroupMod {
            xid: 19,
            command: OFPGC_INSERT_BUCKET,
            group_type: 2,
            group_id: 33,
            // INSERT_BUCKET is the command that actually uses
            // command_bucket_id; ADD/MODIFY/DELETE must send BUCKET_ALL.
            command_bucket_id: 44,
            buckets: vec![Bucket {
                bucket_id: 1,
                actions: vec![Action::output(5)],
                properties: vec![BucketProperty::Weight(3)],
            }],
            properties: vec![GroupProperty::Experimenter {
                experimenter: 7,
                exp_type: 1,
                data: vec![9, 9, 9, 9],
            }],
        }
        .encode()
        .unwrap();
        let parsed_group = parse_group_mod(&group).unwrap();
        assert_eq!(parsed_group.command, OFPGC_INSERT_BUCKET);
        assert_eq!(parsed_group.group_type, 2);
        assert_eq!(parsed_group.group_id, 33);
        assert_eq!(parsed_group.command_bucket_id, 44);
        assert_eq!(parsed_group.buckets.len(), 1);
        assert_eq!(parsed_group.buckets[0].bucket_id, 1);
        assert_eq!(parsed_group.buckets[0].actions, vec![Action::output(5)]);
        assert_eq!(
            parsed_group.buckets[0].properties,
            vec![BucketProperty::Weight(3)]
        );
        assert_eq!(
            parsed_group.properties,
            vec![GroupProperty::Experimenter {
                experimenter: 7,
                exp_type: 1,
                data: vec![9, 9, 9, 9],
            }]
        );

        let meter = encode_meter_mod(
            20,
            OFPMC_ADD,
            7,
            55,
            &[MeterBand::Drop {
                rate: 100,
                burst_size: 10,
            }],
        )
        .unwrap();
        let parsed_meter = parse_meter_mod(&meter).unwrap();
        assert_eq!(parsed_meter.command, OFPMC_ADD);
        assert_eq!(parsed_meter.flags, 7);
        assert_eq!(parsed_meter.meter_id, 55);
        assert_eq!(
            parsed_meter.bands,
            vec![MeterBand::Drop {
                rate: 100,
                burst_size: 10,
            }]
        );
    }

    /// Round-trip tests (above) only prove the encoder and parser agree
    /// with *each other*; they'd pass even if both were wrong the same way
    /// (e.g. swapped field offsets). These assert against literal expected
    /// byte layouts per the OF1.5 `ofp_table_mod`/`ofp_port_mod`/
    /// `ofp_group_mod`/`ofp_meter_mod`/`ofp_role_request` C structs.
    #[test]
    fn test_table_port_group_meter_role_encode_fixed_bytes() {
        // ofp_table_mod: header(8) + table_id(1) + pad(3) + config(4).
        let table = encode_table_mod(17, 2, 0x1122_3344, &[]).unwrap();
        assert_eq!(table.len(), 16);
        assert_eq!(table[8], 2); // table_id
        assert_eq!(&table[9..12], &[0, 0, 0]); // pad
        assert_eq!(&table[12..16], &0x1122_3344u32.to_be_bytes()); // config

        // ofp_port_mod: header(8) + port_no(4) + pad(4) + hw_addr(6) + pad(2)
        // + config(4) + mask(4).
        let port =
            encode_port_mod(18, 5, [1, 2, 3, 4, 5, 6], 0x0102_0304, 0x0506_0708, &[]).unwrap();
        assert_eq!(port.len(), 32);
        assert_eq!(&port[8..12], &5u32.to_be_bytes()); // port_no
        assert_eq!(&port[12..16], &[0, 0, 0, 0]); // pad
        assert_eq!(&port[16..22], &[1, 2, 3, 4, 5, 6]); // hw_addr
        assert_eq!(&port[22..24], &[0, 0]); // pad
        assert_eq!(&port[24..28], &0x0102_0304u32.to_be_bytes()); // config
        assert_eq!(&port[28..32], &0x0506_0708u32.to_be_bytes()); // mask

        // ofp_group_mod: header(8) + command(2) + type(1) + pad(1) +
        // group_id(4) + bucket_array_len(2) + pad(2) + command_bucket_id(4).
        let group = GroupMod {
            xid: 19,
            command: OFPGC_ADD,
            group_type: 2,
            group_id: 33,
            command_bucket_id: OFPG_BUCKET_ALL,
            buckets: vec![],
            properties: vec![],
        }
        .encode()
        .unwrap();
        assert_eq!(group.len(), 24);
        assert_eq!(&group[8..10], &OFPGC_ADD.to_be_bytes());
        assert_eq!(group[10], 2); // group_type
        assert_eq!(group[11], 0); // pad
        assert_eq!(&group[12..16], &33u32.to_be_bytes()); // group_id
        assert_eq!(&group[16..18], &0u16.to_be_bytes()); // bucket_array_len (no buckets)
        assert_eq!(&group[18..20], &[0, 0]); // pad
        assert_eq!(&group[20..24], &OFPG_BUCKET_ALL.to_be_bytes()); // command_bucket_id

        // ofp_meter_mod: header(8) + command(2) + flags(2) + meter_id(4).
        let meter = encode_meter_mod(20, OFPMC_ADD, 7, 55, &[]).unwrap();
        assert_eq!(meter.len(), 16);
        assert_eq!(&meter[8..10], &OFPMC_ADD.to_be_bytes());
        assert_eq!(&meter[10..12], &7u16.to_be_bytes());
        assert_eq!(&meter[12..16], &55u32.to_be_bytes());

        // ofp_role_request: header(8) + role(4) + short_id(2) + pad(2) +
        // generation_id(8).
        let role = encode_role_request(21, OFPCR_ROLE_MASTER, 9, 0x0102_0304_0506_0708).unwrap();
        assert_eq!(role.len(), 24);
        assert_eq!(&role[8..12], &OFPCR_ROLE_MASTER.to_be_bytes());
        assert_eq!(&role[12..14], &9u16.to_be_bytes());
        assert_eq!(&role[14..16], &[0, 0]);
        assert_eq!(&role[16..24], &0x0102_0304_0506_0708u64.to_be_bytes());
    }

    /// `OFPGC_*` group-mod commands are 0-3,5 (4 is unassigned) — parsing
    /// an unassigned command value must be rejected, not silently accepted.
    #[test]
    fn test_group_mod_rejects_invalid_command() {
        let mut group = Vec::new();
        Header {
            version: OFP_VERSION_1_5,
            msg_type: OFPT_GROUP_MOD,
            length: 24,
            xid: 1,
        }
        .encode(&mut group);
        group.extend_from_slice(&4u16.to_be_bytes()); // unassigned command value
        group.push(0);
        group.push(0);
        group.extend_from_slice(&[0u8; 4]); // group_id
        group.extend_from_slice(&[0u8; 2]); // bucket_array_len
        group.extend_from_slice(&[0u8; 2]); // pad
        group.extend_from_slice(&[0u8; 4]); // command_bucket_id

        let err = parse_group_mod(&group).unwrap_err();
        assert!(matches!(
            err,
            crate::protocol::error::OfError::InvalidValue {
                field: "group_command",
                value: 4
            }
        ));
    }

    /// `OFPFC_*` flow-mod commands are 0-4; anything else must be rejected.
    #[test]
    fn test_flow_mod_rejects_invalid_command() {
        let xid = 99;
        let mut fm = Rule::add(xid, 0, 0, Match::any(), vec![]).encode().unwrap();
        // The command byte lives at frame offset 25 (header 8 + body
        // offset 17), per the layout `test_flow_mod_add` also checks.
        fm[25] = 5;
        let err = crate::protocol::rule::Entry::parse(&fm).unwrap_err();
        assert!(matches!(
            err,
            crate::protocol::error::OfError::InvalidValue {
                field: "flow_mod_command",
                value: 5
            }
        ));
    }

    #[test]
    fn test_bundle_control_and_add_message_encode_and_parse() {
        let control = BundleMessage {
            xid: 21,
            bundle_id: 99,
            ctrl_type: 0,
            flags: OFPBF_ATOMIC | OFPBF_ORDERED,
            properties: vec![BundleProperty::Time {
                scheduled_time: Time {
                    seconds: 1_700_000_000,
                    nanoseconds: 500,
                },
            }],
        }
        .encode()
        .unwrap();
        let parsed_control = parse_bundle_message(&control).unwrap();
        assert_eq!(parsed_control.bundle_id, 99);
        assert_eq!(parsed_control.ctrl_type, 0);
        assert_eq!(parsed_control.flags, OFPBF_ATOMIC | OFPBF_ORDERED);
        assert_eq!(
            parsed_control.properties,
            vec![BundleProperty::Time {
                scheduled_time: Time {
                    seconds: 1_700_000_000,
                    nanoseconds: 500,
                },
            }]
        );

        // The nested message's xid must equal the bundle-add's own xid.
        let nested = encode_barrier_request(23);
        let add_props = vec![BundleProperty::Experimenter {
            experimenter: 0x0000_2320,
            exp_type: 1,
            data: vec![7, 7, 7, 7],
        }];
        let add = encode_bundle_add_message(23, 99, 0, &nested, &add_props).unwrap();
        let parsed_add = parse_bundle_add_message(&add).unwrap();
        assert_eq!(parsed_add.bundle_id, 99);
        assert_eq!(parsed_add.flags, 0);
        assert_eq!(parsed_add.message, nested);
        assert_eq!(parsed_add.properties, add_props);
    }

    #[test]
    fn test_invalid_reserved_values_are_rejected() {
        let mut multipart = Vec::new();
        Header {
            version: OFP_VERSION_1_5,
            msg_type: OFPT_MULTIPART_REQUEST,
            length: 16,
            xid: 30,
        }
        .encode(&mut multipart);
        multipart.extend_from_slice(&0x1234u16.to_be_bytes());
        multipart.extend_from_slice(&0u16.to_be_bytes());
        multipart.extend_from_slice(&[0u8; 4]);
        let err = parse_multipart_request(&multipart).unwrap_err();
        assert!(matches!(
            err,
            crate::protocol::error::OfError::InvalidValue {
                field: "multipart_type",
                value: 0x1234
            }
        ));

        let mut role = Vec::new();
        Header {
            version: OFP_VERSION_1_5,
            msg_type: OFPT_ROLE_REQUEST,
            length: 24,
            xid: 31,
        }
        .encode(&mut role);
        role.extend_from_slice(&9u32.to_be_bytes());
        role.extend_from_slice(&1u16.to_be_bytes());
        role.extend_from_slice(&[0u8; 2]);
        role.extend_from_slice(&0u64.to_be_bytes());
        let err = parse_role_request(&role).unwrap_err();
        assert!(matches!(
            err,
            crate::protocol::error::OfError::InvalidValue {
                field: "role",
                value: 9
            }
        ));
    }

    #[test]
    fn test_async_status_parsers() {
        // ofp_flow_removed (1.5.1): table_id(1)@0, reason(1)@1,
        // priority(2)@2, idle_timeout(2)@4, hard_timeout(2)@6,
        // cookie(8)@8, match@16, then ofp_stats. The 1.3-era inline
        // duration/packet/byte counters live in that ofp_stats now.
        let mut flow_removed = Vec::new();
        Header {
            version: OFP_VERSION_1_5,
            msg_type: OFPT_FLOW_REMOVED,
            length: 48,
            xid: 50,
        }
        .encode(&mut flow_removed);
        flow_removed.push(1); // table_id
        flow_removed.push(OFPRR_DELETE); // reason
        flow_removed.extend_from_slice(&100u16.to_be_bytes()); // priority
        flow_removed.extend_from_slice(&1u16.to_be_bytes()); // idle_timeout
        flow_removed.extend_from_slice(&2u16.to_be_bytes()); // hard_timeout
        flow_removed.extend_from_slice(&0x0102_0304_0506_0708u64.to_be_bytes()); // cookie
        flow_removed.extend_from_slice(&OFPMT_OXM.to_be_bytes()); // empty match
        flow_removed.extend_from_slice(&4u16.to_be_bytes());
        flow_removed.extend_from_slice(&[0u8; 4]);
        let packet_count =
            crate::protocol::oxs::encode_oxs_list(&[OxsTlv::PacketCount(300)]).unwrap();
        flow_removed.extend_from_slice(&[0u8; 2]); // ofp_stats reserved
        flow_removed
            .extend_from_slice(&u16::try_from(4 + packet_count.len()).unwrap().to_be_bytes());
        flow_removed.extend_from_slice(&packet_count);
        while !flow_removed.len().is_multiple_of(8) {
            flow_removed.push(0);
        }
        let parsed_flow = parse_async_flow_removed(&flow_removed).unwrap();
        assert_eq!(parsed_flow.xid, 50);
        assert_eq!(parsed_flow.cookie, 0x0102_0304_0506_0708);
        assert_eq!(parsed_flow.priority, 100);
        assert_eq!(parsed_flow.reason, OFPRR_DELETE);
        assert_eq!(parsed_flow.table_id, 1);
        assert_eq!(parsed_flow.idle_timeout, 1);
        assert_eq!(parsed_flow.hard_timeout, 2);
        assert_eq!(parsed_flow.stats, vec![OxsTlv::PacketCount(300)]);

        let mut port_status = Vec::new();
        Header {
            version: OFP_VERSION_1_5,
            msg_type: OFPT_PORT_STATUS,
            length: 56,
            xid: 51,
        }
        .encode(&mut port_status);
        port_status.push(OFPPR_MODIFY);
        port_status.extend_from_slice(&[0u8; 7]);
        port_status.extend_from_slice(&[0u8; 40]);
        assert_eq!(
            parse_async_port_status(&port_status).unwrap().reason,
            OFPPR_MODIFY
        );

        let mut role_status = Vec::new();
        Header {
            version: OFP_VERSION_1_5,
            msg_type: OFPT_ROLE_STATUS,
            length: 24,
            xid: 52,
        }
        .encode(&mut role_status);
        role_status.extend_from_slice(&OFPCR_ROLE_MASTER.to_be_bytes());
        role_status.push(OFPCRR_CONFIG);
        role_status.extend_from_slice(&[0u8; 3]);
        role_status.extend_from_slice(&9u64.to_be_bytes());
        assert_eq!(
            parse_async_role_status(&role_status).unwrap().role,
            OFPCR_ROLE_MASTER
        );

        let mut table_status = Vec::new();
        Header {
            version: OFP_VERSION_1_5,
            msg_type: OFPT_TABLE_STATUS,
            length: 24,
            xid: 53,
        }
        .encode(&mut table_status);
        table_status.push(OFPTR_VACANCY_UP);
        table_status.extend_from_slice(&[0u8; 7]);
        table_status.extend_from_slice(&[0u8; 8]);
        assert_eq!(
            parse_async_table_status(&table_status).unwrap().reason,
            OFPTR_VACANCY_UP
        );

        let nested = GroupMod {
            xid: 54,
            command: OFPGC_DELETE,
            group_type: 0,
            group_id: OFPG_ALL,
            command_bucket_id: OFPG_BUCKET_ALL,
            buckets: vec![],
            properties: vec![],
        }
        .encode()
        .unwrap();
        let mut request_forward = Vec::new();
        Header {
            version: OFP_VERSION_1_5,
            msg_type: OFPT_REQUESTFORWARD,
            length: (8 + nested.len()) as u16,
            xid: 55,
        }
        .encode(&mut request_forward);
        request_forward.extend_from_slice(&nested);
        assert_eq!(
            parse_async_request_forward(&request_forward)
                .unwrap()
                .request
                .len(),
            nested.len()
        );

        let mut controller_status = Vec::new();
        Header {
            version: OFP_VERSION_1_5,
            msg_type: OFPT_CONTROLLER_STATUS,
            length: 24,
            xid: 56,
        }
        .encode(&mut controller_status);
        controller_status.extend_from_slice(&16u16.to_be_bytes());
        controller_status.extend_from_slice(&7u16.to_be_bytes());
        controller_status.extend_from_slice(&OFPCR_ROLE_EQUAL.to_be_bytes());
        controller_status.push(OFPCSR_ROLE);
        controller_status.push(OFPCT_STATUS_UP);
        controller_status.extend_from_slice(&[0u8; 6]);
        let parsed_controller = parse_async_controller_status(&controller_status).unwrap();
        assert_eq!(parsed_controller.short_id, 7);
        assert_eq!(parsed_controller.reason, OFPCSR_ROLE);
    }

    #[test]
    fn test_packet_in_rejects_invalid_match() {
        let mut frame = Vec::new();
        Header {
            version: OFP_VERSION_1_5,
            msg_type: OFPT_PACKET_IN,
            length: 34,
            xid: 1,
        }
        .encode(&mut frame);
        frame.extend_from_slice(&[0u8; 16]);
        frame.extend_from_slice(&1u16.to_be_bytes());
        frame.extend_from_slice(&8u16.to_be_bytes());
        frame.extend_from_slice(&[0u8; 4]);
        frame.extend_from_slice(&[0u8; 2]);

        let err = PacketIn::parse(&frame).unwrap_err();
        assert!(matches!(
            err,
            crate::protocol::error::OfError::InvalidOxmLength
        ));
    }

    #[test]
    fn test_packet_in_accepts_non_zero_padding() {
        let mut frame = Vec::new();
        Header {
            version: OFP_VERSION_1_5,
            msg_type: OFPT_PACKET_IN,
            length: 34,
            xid: 2,
        }
        .encode(&mut frame);
        frame.extend_from_slice(&[0u8; 16]);
        frame.extend_from_slice(&1u16.to_be_bytes());
        frame.extend_from_slice(&4u16.to_be_bytes());
        frame.extend_from_slice(&[0u8; 4]);
        frame.extend_from_slice(&[0u8; 2]);
        frame[28] = 1;

        assert!(PacketIn::parse(&frame).is_ok());
    }

    #[test]
    fn packet_in_rejects_data_longer_than_total_length() {
        let packet = PacketIn {
            xid: 1,
            buffer_id: OFP_NO_BUFFER,
            total_len: 4,
            reason: OFPR_APPLY_ACTION,
            table_id: 1,
            cookie: 0,
            of_match: crate::protocol::oxm::parse_oxm_list(&crate::protocol::oxm::in_port(1))
                .unwrap(),
            data: b"data".to_vec(),
        };
        let mut frame = packet.encode().unwrap();
        frame[12..14].copy_from_slice(&3u16.to_be_bytes());
        assert!(PacketIn::parse(&frame).is_err());

        let invalid = PacketIn {
            total_len: 3,
            ..packet
        };
        assert!(invalid.encode().is_err());
    }

    #[test]
    fn buffered_packet_out_rejects_inline_data() {
        let mut frame = PacketOut::new(1, 7, Some(3), Vec::new(), Vec::new())
            .encode()
            .unwrap();
        frame.extend_from_slice(b"data");
        let length = u16::try_from(frame.len()).unwrap();
        frame[2..4].copy_from_slice(&length.to_be_bytes());
        assert!(PacketOut::parse(&frame).is_err());
    }

    #[test]
    fn test_hello_encode_advertises_version_bitmap() {
        let frame = Hello::new(42).encode().unwrap();
        let hello = Hello::parse(&frame).unwrap();
        assert_eq!(hello.xid, 42);
        assert_eq!(hello.version, OFP_VERSION_1_5);
        let bitmap = hello.version_bitmap.expect("version bitmap element");
        assert_eq!(bitmap[0] & (1 << OFP_VERSION_1_5), 1 << OFP_VERSION_1_5);

        // decode() must also surface the bitmap on Message::Hello.
        match decode(&frame).unwrap() {
            Message::Hello {
                version,
                version_bitmap,
                ..
            } => {
                assert_eq!(version, OFP_VERSION_1_5);
                assert_eq!(version_bitmap, Some(bitmap));
            }
            other => panic!("expected Hello, got {other:?}"),
        }
    }

    #[test]
    fn test_hello_parse_ignores_unknown_elements() {
        let mut frame = Vec::new();
        Header {
            version: OFP_VERSION_1_5,
            msg_type: OFPT_HELLO,
            length: 24,
            xid: 7,
        }
        .encode(&mut frame);
        // Unknown element type 0xffff, length 4 (header only), no payload.
        frame.extend_from_slice(&0xffffu16.to_be_bytes());
        frame.extend_from_slice(&4u16.to_be_bytes());
        frame.extend_from_slice(&[0u8; 4]); // pad unknown element to 8 bytes
                                            // Known version-bitmap element advertising only 1.0 (bit 1).
        frame.extend_from_slice(&OFPHET_VERSIONBITMAP.to_be_bytes());
        frame.extend_from_slice(&8u16.to_be_bytes());
        frame.extend_from_slice(&(1u32 << 1).to_be_bytes());

        let hello = Hello::parse(&frame).unwrap();
        assert_eq!(hello.version_bitmap, Some(vec![1 << 1]));
    }

    #[test]
    fn test_version_negotiation_compatibility() {
        use crate::protocol::hello::is_version_compatible;

        // Peer advertises a bitmap including 1.5: compatible.
        assert!(is_version_compatible(
            OFP_VERSION_1_5,
            Some(&[1 << OFP_VERSION_1_5])
        ));
        // Peer advertises a bitmap without 1.5 (e.g. only 1.0/1.3): incompatible.
        assert!(!is_version_compatible(0x04, Some(&[(1 << 1) | (1 << 4)])));
        // No bitmap, peer header version >= 1.5: compatible (min(6, peer) == 6).
        assert!(is_version_compatible(0x06, None));
        assert!(is_version_compatible(0x07, None));
        // No bitmap, peer header version < 1.5: incompatible.
        assert!(!is_version_compatible(0x01, None));
    }

    #[test]
    fn test_non_hello_message_with_wrong_version_is_rejected() {
        let mut frame = Vec::new();
        Header {
            version: 0x01,
            msg_type: OFPT_ECHO_REQUEST,
            length: 8,
            xid: 1,
        }
        .encode(&mut frame);

        let err = decode(&frame).unwrap_err();
        assert!(matches!(
            err,
            crate::protocol::error::OfError::UnsupportedVersion(0x01)
        ));
    }
}

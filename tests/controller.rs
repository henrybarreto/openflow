//! In-process integration tests: a fake switch on one end of a duplex
//! stream, this crate's controller on the other.
#![cfg(not(clippy))]

use openflow::controller::switch::ConnectionLimits;
use openflow::protocol::codec::Encoder;
use openflow::protocol::{
    barrier::encode_barrier_request, config::encode_get_config_reply, constants::*,
    control::Property, echo::encode_echo_request, header::Header, hello::encode_frame,
    io::read_frame, oxm,
};
use std::sync::Once;
use std::time::Duration;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;
use tokio::time::timeout;

const SERVER_ADDR: &str = "127.0.0.1:6653";
const LIMITED_SERVER_ADDR: &str = "127.0.0.1:6654";

static SERVER_START: Once = Once::new();
static LIMITED_SERVER_START: Once = Once::new();

fn ensure_server_at(addr: &'static str, limits: ConnectionLimits, start: &Once) {
    start.call_once(move || {
        std::thread::spawn(move || {
            let rt = tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()
                .unwrap();

            rt.block_on(async {
                openflow::controller::server::run_with_limits(addr, limits)
                    .await
                    .unwrap();
            });
        });

        std::thread::sleep(Duration::from_millis(300));
    });
}

fn limited_server_limits() -> ConnectionLimits {
    ConnectionLimits {
        max_open_bundles: 1,
        max_messages_per_bundle: 2,
        max_total_bundle_bytes: 8,
        max_mac_entries: 2,
    }
}

async fn connect_switch_at(
    addr: &'static str,
    limits: ConnectionLimits,
    start: &Once,
) -> TcpStream {
    ensure_server_at(addr, limits, start);

    for _ in 0..40 {
        match TcpStream::connect(addr).await {
            Ok(stream) => return stream,
            Err(_) => tokio::time::sleep(Duration::from_millis(25)).await,
        }
    }

    panic!("failed to connect fake switch");
}

async fn connect_switch() -> TcpStream {
    connect_switch_at(SERVER_ADDR, ConnectionLimits::default(), &SERVER_START).await
}

async fn connect_limited_switch() -> TcpStream {
    connect_switch_at(
        LIMITED_SERVER_ADDR,
        limited_server_limits(),
        &LIMITED_SERVER_START,
    )
    .await
}

async fn read_frame_timeout(stream: &mut TcpStream) -> Vec<u8> {
    timeout(Duration::from_millis(500), read_frame(stream))
        .await
        .unwrap()
        .unwrap()
}

async fn open_running_switch() -> TcpStream {
    let mut stream = connect_switch().await;

    complete_handshake(&mut stream).await;
    stream
}

async fn open_limited_running_switch() -> TcpStream {
    let mut stream = connect_limited_switch().await;

    complete_handshake(&mut stream).await;
    stream
}

async fn complete_handshake(stream: &mut TcpStream) {
    let hello = read_frame_timeout(stream).await;
    let hello_hdr = Header::parse(&hello).unwrap();
    assert_eq!(hello_hdr.msg_type, OFPT_HELLO);

    stream.write_all(&encode_frame(1).unwrap()).await.unwrap();

    let features_req = read_frame_timeout(stream).await;
    let features_hdr = Header::parse(&features_req).unwrap();
    assert_eq!(features_hdr.msg_type, OFPT_FEATURES_REQUEST);

    let mut reply = Vec::new();
    Header {
        version: OFP_VERSION_1_5,
        msg_type: OFPT_FEATURES_REPLY,
        length: 32,
        xid: features_hdr.xid,
    }
    .encode(&mut reply);
    reply.extend_from_slice(&0x0011_2233_4455_6677u64.to_be_bytes());
    reply.extend_from_slice(&0u32.to_be_bytes());
    reply.push(254);
    reply.push(0);
    reply.extend_from_slice(&[0u8; 2]);
    reply.extend_from_slice(&0x0000_0001u32.to_be_bytes());
    reply.extend_from_slice(&[0u8; 4]);
    stream.write_all(&reply).await.unwrap();

    let set_config = read_frame_timeout(stream).await;
    let set_hdr = Header::parse(&set_config).unwrap();
    assert_eq!(set_hdr.msg_type, OFPT_SET_CONFIG);

    let get_config_req = read_frame_timeout(stream).await;
    let get_config_hdr = Header::parse(&get_config_req).unwrap();
    assert_eq!(get_config_hdr.msg_type, OFPT_GET_CONFIG_REQUEST);

    stream
        .write_all(&encode_get_config_reply(
            get_config_hdr.xid,
            0,
            OFP_DEFAULT_MISS_SEND_LEN,
        ))
        .await
        .unwrap();

    let flow_mod = read_frame_timeout(stream).await;
    let flow_mod_hdr = Header::parse(&flow_mod).unwrap();
    assert_eq!(flow_mod_hdr.msg_type, OFPT_FLOW_MOD);
}

fn ethernet_frame(dst: [u8; 6], src: [u8; 6], eth_type: u16) -> Vec<u8> {
    let mut frame = Vec::with_capacity(14);
    frame.extend_from_slice(&dst);
    frame.extend_from_slice(&src);
    frame.extend_from_slice(&eth_type.to_be_bytes());
    frame
}

fn packet_in_frame(xid: u32, buffer_id: u32, in_port: Option<u32>, data: &[u8]) -> Vec<u8> {
    let mut match_block = Vec::new();
    match_block.extend_from_slice(&OFPMT_OXM.to_be_bytes());
    match_block.extend_from_slice(&0u16.to_be_bytes());

    if let Some(port) = in_port {
        match_block.extend_from_slice(&oxm::in_port(port));
    }

    let match_len = match_block.len() as u16;
    match_block[2..4].copy_from_slice(&match_len.to_be_bytes());

    let padded_match_len = match_block.len().div_ceil(8) * 8;
    match_block.resize(padded_match_len, 0);

    let length = 8 + 16 + match_block.len() + 2 + data.len();
    let mut frame = Vec::with_capacity(length);
    Header {
        version: OFP_VERSION_1_5,
        msg_type: OFPT_PACKET_IN,
        length: length as u16,
        xid,
    }
    .encode(&mut frame);

    frame.extend_from_slice(&buffer_id.to_be_bytes());
    frame.extend_from_slice(&(data.len() as u16).to_be_bytes());
    frame.push(0);
    frame.push(0);
    frame.extend_from_slice(&0u64.to_be_bytes());
    frame.extend_from_slice(&match_block);
    frame.extend_from_slice(&[0u8; 2]);
    frame.extend_from_slice(data);

    frame
}

fn experimenter_frame(xid: u32, experimenter: u32, exp_type: u32) -> Vec<u8> {
    let mut frame = Vec::new();
    Header {
        version: OFP_VERSION_1_5,
        msg_type: OFPT_EXPERIMENTER,
        length: 16,
        xid,
    }
    .encode(&mut frame);
    frame.extend_from_slice(&experimenter.to_be_bytes());
    frame.extend_from_slice(&exp_type.to_be_bytes());
    frame
}

fn error_frame(xid: u32, data: &[u8]) -> Vec<u8> {
    let mut frame = Vec::new();
    Header {
        version: OFP_VERSION_1_5,
        msg_type: OFPT_ERROR,
        length: (8 + data.len()) as u16,
        xid,
    }
    .encode(&mut frame);
    frame.extend_from_slice(data);
    frame
}

fn features_reply_frame(xid: u32) -> Vec<u8> {
    let mut reply = Vec::new();
    Header {
        version: OFP_VERSION_1_5,
        msg_type: OFPT_FEATURES_REPLY,
        length: 32,
        xid,
    }
    .encode(&mut reply);
    reply.extend_from_slice(&0x0011_2233_4455_6677u64.to_be_bytes());
    reply.extend_from_slice(&0u32.to_be_bytes());
    reply.push(254);
    reply.push(0);
    reply.extend_from_slice(&[0u8; 2]);
    reply.extend_from_slice(&0x0000_0001u32.to_be_bytes());
    reply.extend_from_slice(&[0u8; 4]);
    reply
}

fn packet_out_port(frame: &[u8]) -> u32 {
    u32::from_be_bytes(frame[36..40].try_into().unwrap())
}

fn async_reason_property(kind: u16, mask: u32) -> Property {
    Property::ReasonMask { kind, mask }
}

// Handshake and lifecycle
#[tokio::test]
async fn hello_and_features() {
    let mut stream = open_running_switch().await;

    let reply = packet_in_frame(
        44,
        OFP_NO_BUFFER,
        Some(1),
        &ethernet_frame(
            [0xff; 6],
            [0x00, 0x11, 0x22, 0x33, 0x44, 0x55],
            ETH_TYPE_IPV4,
        ),
    );
    stream.write_all(&reply).await.unwrap();

    let pkt_out = read_frame_timeout(&mut stream).await;
    let hdr = Header::parse(&pkt_out).unwrap();
    assert_eq!(hdr.msg_type, OFPT_PACKET_OUT);
    assert_eq!(packet_out_port(&pkt_out), OFPP_FLOOD);
}

/// A reply belongs to the request with the same XID. A mismatched reply could
/// otherwise make the controller configure a datapath using stale data.
#[tokio::test]
async fn features_reply_with_wrong_xid_is_rejected_and_connection_closed() {
    let mut stream = connect_switch().await;
    let _ = read_frame_timeout(&mut stream).await;
    stream.write_all(&encode_frame(1).unwrap()).await.unwrap();

    let features_request = read_frame_timeout(&mut stream).await;
    let xid = Header::parse(&features_request).unwrap().xid;
    stream
        .write_all(&features_reply_frame(xid.wrapping_add(1)))
        .await
        .unwrap();

    let mut buf = [0u8; 1];
    let read = timeout(
        Duration::from_millis(500),
        tokio::io::AsyncReadExt::read(&mut stream, &mut buf),
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(read, 0, "connection should close after a mismatched XID");
}

#[tokio::test]
async fn get_config_reply_with_wrong_xid_is_rejected_and_connection_closed() {
    let mut stream = connect_switch().await;
    let _ = read_frame_timeout(&mut stream).await;
    stream.write_all(&encode_frame(1).unwrap()).await.unwrap();

    let features_request = read_frame_timeout(&mut stream).await;
    let features_xid = Header::parse(&features_request).unwrap().xid;
    stream
        .write_all(&features_reply_frame(features_xid))
        .await
        .unwrap();
    let _ = read_frame_timeout(&mut stream).await; // set-config
    let get_config = read_frame_timeout(&mut stream).await;
    let get_config_xid = Header::parse(&get_config).unwrap().xid;
    stream
        .write_all(&encode_get_config_reply(
            get_config_xid.wrapping_add(1),
            0,
            OFP_DEFAULT_MISS_SEND_LEN,
        ))
        .await
        .unwrap();

    let mut buf = [0u8; 1];
    let read = timeout(
        Duration::from_millis(500),
        tokio::io::AsyncReadExt::read(&mut stream, &mut buf),
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(read, 0, "connection should close after a mismatched XID");
}

#[tokio::test]
async fn echo_reply() {
    let mut stream = open_running_switch().await;

    let xid = 100;
    let payload = b"ping";
    stream
        .write_all(&encode_echo_request(xid, payload).unwrap())
        .await
        .unwrap();

    let frame = read_frame_timeout(&mut stream).await;
    let hdr = Header::parse(&frame).unwrap();
    assert_eq!(hdr.msg_type, OFPT_ECHO_REPLY);
    assert_eq!(hdr.xid, xid);
    assert_eq!(&frame[8..], payload);
}

#[tokio::test]
async fn barrier_reply() {
    let mut stream = open_running_switch().await;

    stream.write_all(&encode_barrier_request(77)).await.unwrap();

    let frame = read_frame_timeout(&mut stream).await;
    let hdr = Header::parse(&frame).unwrap();
    assert_eq!(hdr.msg_type, OFPT_BARRIER_REPLY);
    assert_eq!(hdr.xid, 77);
}

#[tokio::test]
async fn role_reply() {
    let mut stream = open_running_switch().await;

    stream
        .write_all(&Encoder::role_request(501, OFPCR_ROLE_MASTER, 7, 99).unwrap())
        .await
        .unwrap();

    let frame = read_frame_timeout(&mut stream).await;
    let hdr = Header::parse(&frame).unwrap();
    assert_eq!(hdr.msg_type, OFPT_ROLE_REPLY);
    assert_eq!(hdr.xid, 501);
    assert_eq!(
        u32::from_be_bytes(frame[8..12].try_into().unwrap()),
        OFPCR_ROLE_MASTER
    );
    assert_eq!(u16::from_be_bytes(frame[12..14].try_into().unwrap()), 7);
    assert_eq!(u64::from_be_bytes(frame[16..24].try_into().unwrap()), 99);
}

#[tokio::test]
async fn stale_role_request_is_rejected_without_changing_role() {
    let mut stream = open_running_switch().await;

    stream
        .write_all(&Encoder::role_request(502, OFPCR_ROLE_MASTER, 7, 99).unwrap())
        .await
        .unwrap();
    let promoted = read_frame_timeout(&mut stream).await;
    assert_eq!(Header::parse(&promoted).unwrap().msg_type, OFPT_ROLE_REPLY);

    stream
        .write_all(&Encoder::role_request(503, OFPCR_ROLE_SLAVE, 8, 98).unwrap())
        .await
        .unwrap();
    let stale = read_frame_timeout(&mut stream).await;
    let stale_hdr = Header::parse(&stale).unwrap();
    assert_eq!(stale_hdr.msg_type, OFPT_ERROR);
    assert_eq!(stale_hdr.xid, 503);
    assert_eq!(
        u16::from_be_bytes(stale[8..10].try_into().unwrap()),
        OFPET_ROLE_REQUEST_FAILED
    );
    assert_eq!(
        u16::from_be_bytes(stale[10..12].try_into().unwrap()),
        OFPRRFC_STALE
    );

    // A failed request must leave the previous master role and generation in place.
    stream
        .write_all(&Encoder::role_request(504, OFPCR_ROLE_NOCHANGE, 0, 0).unwrap())
        .await
        .unwrap();
    let current = read_frame_timeout(&mut stream).await;
    assert_eq!(Header::parse(&current).unwrap().msg_type, OFPT_ROLE_REPLY);
    assert_eq!(
        u32::from_be_bytes(current[8..12].try_into().unwrap()),
        OFPCR_ROLE_MASTER
    );
    assert_eq!(u64::from_be_bytes(current[16..24].try_into().unwrap()), 99);
}

#[tokio::test]
async fn role_generation_id_accepts_wraparound_and_rejects_old_value() {
    let mut stream = open_running_switch().await;
    let before_wrap = u64::MAX - 1;

    stream
        .write_all(&Encoder::role_request(505, OFPCR_ROLE_MASTER, 7, before_wrap).unwrap())
        .await
        .unwrap();
    let first = read_frame_timeout(&mut stream).await;
    assert_eq!(Header::parse(&first).unwrap().msg_type, OFPT_ROLE_REPLY);

    // The sequence advances across u64::MAX to zero, which is newer by a
    // wrapping signed distance of two.
    stream
        .write_all(&Encoder::role_request(506, OFPCR_ROLE_SLAVE, 7, 0).unwrap())
        .await
        .unwrap();
    let wrapped = read_frame_timeout(&mut stream).await;
    assert_eq!(Header::parse(&wrapped).unwrap().msg_type, OFPT_ROLE_REPLY);
    assert_eq!(u64::from_be_bytes(wrapped[16..24].try_into().unwrap()), 0);

    // MAX is now one step behind zero and must be rejected as stale.
    stream
        .write_all(&Encoder::role_request(507, OFPCR_ROLE_MASTER, 7, u64::MAX).unwrap())
        .await
        .unwrap();
    let stale = read_frame_timeout(&mut stream).await;
    assert_eq!(Header::parse(&stale).unwrap().msg_type, OFPT_ERROR);
    assert_eq!(
        u16::from_be_bytes(stale[10..12].try_into().unwrap()),
        OFPRRFC_STALE
    );
}

#[tokio::test]
async fn async_config_round_trip() {
    let mut stream = open_running_switch().await;

    stream
        .write_all(&Encoder::get_async_request(511).unwrap())
        .await
        .unwrap();
    let frame = read_frame_timeout(&mut stream).await;
    let hdr = Header::parse(&frame).unwrap();
    assert_eq!(hdr.msg_type, OFPT_GET_ASYNC_REPLY);
    assert_eq!(hdr.xid, 511);
    assert!(frame.len() > 8);

    let property = async_reason_property(OFPACPT_PACKET_IN_MASTER, 0x3f);
    let property_bytes = vec![
        (OFPACPT_PACKET_IN_MASTER >> 8) as u8,
        OFPACPT_PACKET_IN_MASTER as u8,
        0x00,
        0x08,
        0x00,
        0x00,
        0x00,
        0x3f,
    ];
    stream
        .write_all(&Encoder::set_async(512, &[property.clone()]).unwrap())
        .await
        .unwrap();

    stream
        .write_all(&Encoder::get_async_request(513).unwrap())
        .await
        .unwrap();
    let frame = read_frame_timeout(&mut stream).await;
    let hdr = Header::parse(&frame).unwrap();
    assert_eq!(hdr.msg_type, OFPT_GET_ASYNC_REPLY);
    assert_eq!(hdr.xid, 513);
    assert!(matches!(
        &property,
        Property::ReasonMask {
            kind: OFPACPT_PACKET_IN_MASTER,
            mask: 0x3f,
        }
    ));
    assert!(frame
        .windows(property_bytes.len())
        .any(|window| window == property_bytes.as_slice()));
}

// Bundle workflows
#[tokio::test]
async fn bundle_open_add_close_commit() {
    let mut stream = open_running_switch().await;

    stream
        .write_all(
            &Encoder::bundle_control(521, 0xabc, OFPBCT_OPEN_REQUEST, OFPBF_ORDERED, &[]).unwrap(),
        )
        .await
        .unwrap();
    let open_reply = read_frame_timeout(&mut stream).await;
    assert_eq!(
        Header::parse(&open_reply).unwrap().msg_type,
        OFPT_BUNDLE_CONTROL
    );
    assert_eq!(
        u16::from_be_bytes(open_reply[12..14].try_into().unwrap()),
        OFPBCT_OPEN_REPLY
    );

    // A bundle-add's nested message must carry the same xid.
    let nested = encode_barrier_request(523);
    stream
        .write_all(&Encoder::bundle_add_message(523, 0xabc, OFPBF_ORDERED, &nested, &[]).unwrap())
        .await
        .unwrap();

    stream
        .write_all(
            &Encoder::bundle_control(524, 0xabc, OFPBCT_CLOSE_REQUEST, OFPBF_ORDERED, &[]).unwrap(),
        )
        .await
        .unwrap();
    let close_reply = read_frame_timeout(&mut stream).await;
    assert_eq!(
        u16::from_be_bytes(close_reply[12..14].try_into().unwrap()),
        OFPBCT_CLOSE_REPLY
    );

    stream
        .write_all(
            &Encoder::bundle_control(525, 0xabc, OFPBCT_COMMIT_REQUEST, OFPBF_ORDERED, &[])
                .unwrap(),
        )
        .await
        .unwrap();
    let staged = read_frame_timeout(&mut stream).await;
    let staged_hdr = Header::parse(&staged).unwrap();
    assert_eq!(staged_hdr.msg_type, OFPT_BARRIER_REQUEST);
    assert_eq!(staged_hdr.xid, 523);

    let commit_reply = read_frame_timeout(&mut stream).await;
    let commit_hdr = Header::parse(&commit_reply).unwrap();
    assert_eq!(commit_hdr.msg_type, OFPT_BUNDLE_CONTROL);
    assert_eq!(commit_hdr.xid, 525);
    assert_eq!(
        u16::from_be_bytes(commit_reply[12..14].try_into().unwrap()),
        OFPBCT_COMMIT_REPLY
    );
}

#[tokio::test]
async fn bundle_add_for_unknown_bundle_is_rejected() {
    let mut stream = open_running_switch().await;

    // A bundle-add's nested message must carry the same xid.
    let nested = encode_barrier_request(610);
    stream
        .write_all(&Encoder::bundle_add_message(610, 0xdef, OFPBF_ORDERED, &nested, &[]).unwrap())
        .await
        .unwrap();
    let error = read_frame_timeout(&mut stream).await;
    let error_hdr = Header::parse(&error).unwrap();
    assert_eq!(error_hdr.msg_type, OFPT_ERROR);
    assert_eq!(error_hdr.xid, 610);
    assert_eq!(
        u16::from_be_bytes(error[8..10].try_into().unwrap()),
        OFPET_BUNDLE_FAILED
    );
    assert_eq!(
        u16::from_be_bytes(error[10..12].try_into().unwrap()),
        OFPBFC_BAD_ID
    );

    // Rejection must not implicitly create a bundle that can later commit.
    stream
        .write_all(
            &Encoder::bundle_control(612, 0xdef, OFPBCT_COMMIT_REQUEST, OFPBF_ORDERED, &[])
                .unwrap(),
        )
        .await
        .unwrap();

    let error = read_frame_timeout(&mut stream).await;
    let error_hdr = Header::parse(&error).unwrap();
    assert_eq!(error_hdr.msg_type, OFPT_ERROR);
    assert_eq!(error_hdr.xid, 612);
    assert_eq!(
        u16::from_be_bytes(error[10..12].try_into().unwrap()),
        OFPBFC_BAD_ID
    );
}

#[tokio::test]
async fn bundle_errors_for_duplicate_open_and_closed_add() {
    let mut stream = open_running_switch().await;

    stream
        .write_all(&Encoder::bundle_control(620, 0xaaa, OFPBCT_OPEN_REQUEST, 0, &[]).unwrap())
        .await
        .unwrap();
    let open_reply = read_frame_timeout(&mut stream).await;
    assert_eq!(
        Header::parse(&open_reply).unwrap().msg_type,
        OFPT_BUNDLE_CONTROL
    );

    stream
        .write_all(&Encoder::bundle_control(621, 0xaaa, OFPBCT_OPEN_REQUEST, 0, &[]).unwrap())
        .await
        .unwrap();
    let duplicate = read_frame_timeout(&mut stream).await;
    let duplicate_hdr = Header::parse(&duplicate).unwrap();
    assert_eq!(duplicate_hdr.msg_type, OFPT_ERROR);
    assert_eq!(
        u16::from_be_bytes(duplicate[8..10].try_into().unwrap()),
        OFPET_BUNDLE_FAILED
    );
    assert_eq!(
        u16::from_be_bytes(duplicate[10..12].try_into().unwrap()),
        OFPBFC_BAD_ID
    );

    stream
        .write_all(&Encoder::bundle_control(622, 0xbbb, OFPBCT_OPEN_REQUEST, 0, &[]).unwrap())
        .await
        .unwrap();
    let open_reply = read_frame_timeout(&mut stream).await;
    assert_eq!(
        Header::parse(&open_reply).unwrap().msg_type,
        OFPT_BUNDLE_CONTROL
    );

    // A bundle-add's nested message must carry the same xid.
    let nested = encode_barrier_request(625);
    stream
        .write_all(&Encoder::bundle_control(624, 0xbbb, OFPBCT_CLOSE_REQUEST, 0, &[]).unwrap())
        .await
        .unwrap();
    let close_reply = read_frame_timeout(&mut stream).await;
    assert_eq!(
        u16::from_be_bytes(close_reply[12..14].try_into().unwrap()),
        OFPBCT_CLOSE_REPLY
    );

    stream
        .write_all(&Encoder::bundle_add_message(625, 0xbbb, 0, &nested, &[]).unwrap())
        .await
        .unwrap();
    let closed = read_frame_timeout(&mut stream).await;
    let closed_hdr = Header::parse(&closed).unwrap();
    assert_eq!(closed_hdr.msg_type, OFPT_ERROR);
    assert_eq!(
        u16::from_be_bytes(closed[8..10].try_into().unwrap()),
        OFPET_BUNDLE_FAILED
    );
    assert_eq!(
        u16::from_be_bytes(closed[10..12].try_into().unwrap()),
        OFPBFC_BUNDLE_CLOSED
    );
}

#[tokio::test]
async fn bundle_limits_reject_before_retaining_messages() {
    let mut stream = open_limited_running_switch().await;

    stream
        .write_all(&Encoder::bundle_control(630, 0x100, OFPBCT_OPEN_REQUEST, 0, &[]).unwrap())
        .await
        .unwrap();
    let open_reply = read_frame_timeout(&mut stream).await;
    assert_eq!(
        u16::from_be_bytes(open_reply[12..14].try_into().unwrap()),
        OFPBCT_OPEN_REPLY
    );

    stream
        .write_all(&Encoder::bundle_control(631, 0x200, OFPBCT_OPEN_REQUEST, 0, &[]).unwrap())
        .await
        .unwrap();
    let too_many_bundles = read_frame_timeout(&mut stream).await;
    assert_eq!(
        u16::from_be_bytes(too_many_bundles[10..12].try_into().unwrap()),
        OFPBFC_OUT_OF_BUNDLES
    );

    let first = encode_barrier_request(632);
    stream
        .write_all(&Encoder::bundle_add_message(632, 0x100, 0, &first, &[]).unwrap())
        .await
        .unwrap();

    // The first 8-byte nested message fills the connection-wide byte budget.
    let second = encode_barrier_request(633);
    stream
        .write_all(&Encoder::bundle_add_message(633, 0x100, 0, &second, &[]).unwrap())
        .await
        .unwrap();
    let too_many_messages = read_frame_timeout(&mut stream).await;
    assert_eq!(
        u16::from_be_bytes(too_many_messages[10..12].try_into().unwrap()),
        OFPBFC_MSG_TOO_MANY
    );

    stream
        .write_all(&Encoder::bundle_control(634, 0x100, OFPBCT_CLOSE_REQUEST, 0, &[]).unwrap())
        .await
        .unwrap();
    let _ = read_frame_timeout(&mut stream).await;
    stream
        .write_all(&Encoder::bundle_control(635, 0x100, OFPBCT_COMMIT_REQUEST, 0, &[]).unwrap())
        .await
        .unwrap();
    let staged = read_frame_timeout(&mut stream).await;
    assert_eq!(Header::parse(&staged).unwrap().xid, 632);
    let commit_reply = read_frame_timeout(&mut stream).await;
    assert_eq!(
        u16::from_be_bytes(commit_reply[12..14].try_into().unwrap()),
        OFPBCT_COMMIT_REPLY
    );
}

#[tokio::test]
async fn mac_table_evicts_deterministically_at_limit() {
    let mut stream = open_limited_running_switch().await;
    let mac_a = [0, 0, 0, 0, 0, 1];
    let mac_b = [0, 0, 0, 0, 0, 2];
    let mac_c = [0, 0, 0, 0, 0, 3];

    for (xid, port, src) in [(640, 1, mac_a), (641, 2, mac_b), (642, 3, mac_c)] {
        stream
            .write_all(&packet_in_frame(
                xid,
                OFP_NO_BUFFER,
                Some(port),
                &ethernet_frame([0xff; 6], src, ETH_TYPE_ARP),
            ))
            .await
            .unwrap();
        let flood = read_frame_timeout(&mut stream).await;
        assert_eq!(Header::parse(&flood).unwrap().msg_type, OFPT_PACKET_OUT);
    }

    // MAC A is the deterministic eviction victim, while B remains learned.
    stream
        .write_all(&packet_in_frame(
            643,
            OFP_NO_BUFFER,
            Some(3),
            &ethernet_frame(mac_a, mac_c, ETH_TYPE_IPV4),
        ))
        .await
        .unwrap();
    let flood = read_frame_timeout(&mut stream).await;
    assert_eq!(Header::parse(&flood).unwrap().msg_type, OFPT_PACKET_OUT);
    assert_eq!(packet_out_port(&flood), OFPP_FLOOD);

    stream
        .write_all(&packet_in_frame(
            644,
            OFP_NO_BUFFER,
            Some(3),
            &ethernet_frame(mac_b, mac_c, ETH_TYPE_IPV4),
        ))
        .await
        .unwrap();
    let flow_mod = read_frame_timeout(&mut stream).await;
    assert_eq!(Header::parse(&flow_mod).unwrap().msg_type, OFPT_FLOW_MOD);
    let packet_out = read_frame_timeout(&mut stream).await;
    assert_eq!(packet_out_port(&packet_out), 2);
}

#[tokio::test]
async fn barrier_reply_follows_prior_packet_out() {
    let mut stream = open_running_switch().await;

    stream
        .write_all(&packet_in_frame(
            401,
            OFP_NO_BUFFER,
            Some(1),
            &ethernet_frame(
                [0xff; 6],
                [0x10, 0x11, 0x12, 0x13, 0x14, 0x15],
                ETH_TYPE_IPV4,
            ),
        ))
        .await
        .unwrap();
    stream
        .write_all(&encode_barrier_request(402))
        .await
        .unwrap();

    let packet_out = read_frame_timeout(&mut stream).await;
    assert_eq!(
        Header::parse(&packet_out).unwrap().msg_type,
        OFPT_PACKET_OUT
    );

    let barrier = read_frame_timeout(&mut stream).await;
    let barrier_hdr = Header::parse(&barrier).unwrap();
    assert_eq!(barrier_hdr.msg_type, OFPT_BARRIER_REPLY);
    assert_eq!(barrier_hdr.xid, 402);
}

// Message tolerance
#[tokio::test]
async fn experimenter_is_ignored() {
    let mut stream = open_running_switch().await;

    stream
        .write_all(&experimenter_frame(99, 0x0102_0304, 0x0506_0708))
        .await
        .unwrap();

    let silent = timeout(Duration::from_millis(200), read_frame(&mut stream)).await;
    assert!(silent.is_err());

    stream
        .write_all(&encode_echo_request(101, b"alive").unwrap())
        .await
        .unwrap();
    let frame = read_frame_timeout(&mut stream).await;
    let hdr = Header::parse(&frame).unwrap();
    assert_eq!(hdr.msg_type, OFPT_ECHO_REPLY);
    assert_eq!(hdr.xid, 101);
}

#[tokio::test]
async fn error_message_is_tolerated() {
    let mut stream = open_running_switch().await;

    stream
        .write_all(&error_frame(202, b"\x01\x02\x03\x04"))
        .await
        .unwrap();

    stream
        .write_all(&encode_echo_request(203, b"still here").unwrap())
        .await
        .unwrap();
    let frame = read_frame_timeout(&mut stream).await;
    let hdr = Header::parse(&frame).unwrap();
    assert_eq!(hdr.msg_type, OFPT_ECHO_REPLY);
    assert_eq!(hdr.xid, 203);
}

// Learning-switch behavior
#[tokio::test]
async fn packet_in_missing_in_port_and_short_payload_are_ignored() {
    let mut stream = open_running_switch().await;

    let valid_data = ethernet_frame(
        [0xff; 6],
        [0x40, 0x41, 0x42, 0x43, 0x44, 0x45],
        ETH_TYPE_IPV4,
    );
    stream
        .write_all(&packet_in_frame(301, OFP_NO_BUFFER, None, &valid_data))
        .await
        .unwrap();

    let no_in_port = timeout(Duration::from_millis(200), read_frame(&mut stream)).await;
    assert!(no_in_port.is_err());

    let short_eth = vec![0u8; 10];
    stream
        .write_all(&packet_in_frame(302, OFP_NO_BUFFER, Some(1), &short_eth))
        .await
        .unwrap();

    let malformed = timeout(Duration::from_millis(200), read_frame(&mut stream)).await;
    assert!(malformed.is_err());
}

#[tokio::test]
async fn packet_in_buffered_flood_omits_packet_data() {
    let mut stream = open_running_switch().await;

    let data = ethernet_frame(
        [0xff; 6],
        [0x02, 0x00, 0x00, 0x00, 0x00, 0x01],
        ETH_TYPE_ARP,
    );
    let reply = packet_in_frame(88, 0x1122_3344, Some(1), &data);
    stream.write_all(&reply).await.unwrap();

    let pkt_out = read_frame_timeout(&mut stream).await;
    let hdr = Header::parse(&pkt_out).unwrap();
    assert_eq!(hdr.msg_type, OFPT_PACKET_OUT);
    assert_eq!(hdr.length, 48);
    assert_eq!(packet_out_port(&pkt_out), OFPP_FLOOD);
}

#[tokio::test]
async fn packet_in_unknown_destination_floods() {
    let mut stream = open_running_switch().await;

    let data = ethernet_frame(
        [0x10, 0x10, 0x10, 0x10, 0x10, 0x10],
        [0x20, 0x20, 0x20, 0x20, 0x20, 0x20],
        ETH_TYPE_IPV4,
    );
    stream
        .write_all(&packet_in_frame(55, OFP_NO_BUFFER, Some(3), &data))
        .await
        .unwrap();

    let pkt_out = read_frame_timeout(&mut stream).await;
    let hdr = Header::parse(&pkt_out).unwrap();
    assert_eq!(hdr.msg_type, OFPT_PACKET_OUT);
    assert_eq!(packet_out_port(&pkt_out), OFPP_FLOOD);
    assert_eq!(hdr.length, (48 + data.len()) as u16);
}

#[tokio::test]
async fn packet_in_known_destination_unicast() {
    let mut stream = open_running_switch().await;

    let mac_b = [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x02];
    let mac_a = [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x01];
    let mac_c = [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x03];

    let learn_b = ethernet_frame([0xff; 6], mac_b, ETH_TYPE_ARP);
    stream
        .write_all(&packet_in_frame(201, OFP_NO_BUFFER, Some(2), &learn_b))
        .await
        .unwrap();
    let flood = read_frame_timeout(&mut stream).await;
    assert_eq!(Header::parse(&flood).unwrap().msg_type, OFPT_PACKET_OUT);

    let data = ethernet_frame(mac_b, mac_a, ETH_TYPE_IPV4);
    stream
        .write_all(&packet_in_frame(202, OFP_NO_BUFFER, Some(1), &data))
        .await
        .unwrap();

    let flow_mod = read_frame_timeout(&mut stream).await;
    let flow_mod_hdr = Header::parse(&flow_mod).unwrap();
    assert_eq!(flow_mod_hdr.msg_type, OFPT_FLOW_MOD);
    assert!(flow_mod.windows(6).any(|w| w == mac_b));

    let pkt_out = read_frame_timeout(&mut stream).await;
    let hdr = Header::parse(&pkt_out).unwrap();
    assert_eq!(hdr.msg_type, OFPT_PACKET_OUT);
    assert_eq!(packet_out_port(&pkt_out), 2);
    assert_eq!(hdr.length, (48 + data.len()) as u16);

    let same_port = ethernet_frame(mac_b, mac_c, ETH_TYPE_IPV4);
    stream
        .write_all(&packet_in_frame(203, OFP_NO_BUFFER, Some(2), &same_port))
        .await
        .unwrap();

    let silent = timeout(Duration::from_millis(200), read_frame(&mut stream)).await;
    assert!(silent.is_err());
}

// Disconnect and reuse
#[tokio::test]
async fn disconnect_is_clean() {
    let stream = open_running_switch().await;
    drop(stream);

    let mut second = open_running_switch().await;
    second
        .write_all(&encode_echo_request(333, b"ok").unwrap())
        .await
        .unwrap();
    let frame = read_frame_timeout(&mut second).await;
    let hdr = Header::parse(&frame).unwrap();
    assert_eq!(hdr.msg_type, OFPT_ECHO_REPLY);
    assert_eq!(hdr.xid, 333);
}

#[tokio::test]
async fn sequential_switches_do_not_share_learning_state() {
    let mut first = open_running_switch().await;
    let learned_mac = [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x44];
    let learn = ethernet_frame([0xff; 6], learned_mac, ETH_TYPE_ARP);
    first
        .write_all(&packet_in_frame(501, OFP_NO_BUFFER, Some(2), &learn))
        .await
        .unwrap();
    let _ = read_frame_timeout(&mut first).await;
    drop(first);

    let mut second = open_running_switch().await;
    let probe = ethernet_frame(
        learned_mac,
        [0x55, 0x55, 0x55, 0x55, 0x55, 0x55],
        ETH_TYPE_IPV4,
    );
    second
        .write_all(&packet_in_frame(502, OFP_NO_BUFFER, Some(1), &probe))
        .await
        .unwrap();

    let pkt_out = read_frame_timeout(&mut second).await;
    let hdr = Header::parse(&pkt_out).unwrap();
    assert_eq!(hdr.msg_type, OFPT_PACKET_OUT);
    assert_eq!(packet_out_port(&pkt_out), OFPP_FLOOD);
}

/// Spec 6.3.3: if the negotiated `OpenFlow` version isn't supported, the
/// recipient must reply with `OFPET_HELLO_FAILED`/`OFPHFC_INCOMPATIBLE` and
/// terminate the connection. This is only reachable through the real
/// socket-handling loop (`src/controller/server.rs`), not the pure
/// `is_version_compatible` unit tests, so it belongs here.
#[tokio::test]
async fn hello_with_incompatible_version_is_rejected_and_connection_closed() {
    let mut stream = connect_switch().await;

    let hello = read_frame_timeout(&mut stream).await;
    let hello_hdr = Header::parse(&hello).unwrap();
    assert_eq!(hello_hdr.msg_type, OFPT_HELLO);

    // OpenFlow 1.0 header, no version bitmap element: incompatible with
    // this controller, which only ever speaks 1.5.
    let mut incompatible_hello = Vec::new();
    Header {
        version: 0x01,
        msg_type: OFPT_HELLO,
        length: 8,
        xid: 42,
    }
    .encode(&mut incompatible_hello);
    stream.write_all(&incompatible_hello).await.unwrap();

    let fail = read_frame_timeout(&mut stream).await;
    let fail_hdr = Header::parse(&fail).unwrap();
    assert_eq!(fail_hdr.msg_type, OFPT_ERROR);
    let error_type = u16::from_be_bytes([fail[8], fail[9]]);
    let code = u16::from_be_bytes([fail[10], fail[11]]);
    assert_eq!(error_type, OFPET_HELLO_FAILED);
    assert_eq!(code, OFPHFC_INCOMPATIBLE);

    // The connection must be terminated: the next read observes EOF.
    let mut buf = [0u8; 1];
    let n = timeout(
        Duration::from_millis(500),
        tokio::io::AsyncReadExt::read(&mut stream, &mut buf),
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(n, 0, "connection should be closed after HelloFailed");
}

use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpListener;
use tokio::sync::Semaphore;
use tracing::{error, info};

use crate::controller::ethernet::Frame;
use crate::controller::switch::{BundleRecord, Connection, ConnectionLimits, State};
use crate::protocol::action::Action;
use crate::protocol::codec::{Decoder, Encoder};
use crate::protocol::constants::OFPP_FLOOD;
use crate::protocol::constants::{
    OFPBCT_CLOSE_REPLY, OFPBCT_CLOSE_REQUEST, OFPBCT_COMMIT_REPLY, OFPBCT_COMMIT_REQUEST,
    OFPBCT_DISCARD_REPLY, OFPBCT_DISCARD_REQUEST, OFPBCT_OPEN_REPLY, OFPBCT_OPEN_REQUEST,
    OFPBFC_BAD_ID, OFPBFC_BUNDLE_CLOSED, OFPBFC_MSG_TOO_MANY, OFPBFC_OUT_OF_BUNDLES,
    OFPCR_ROLE_EQUAL, OFPCR_ROLE_MASTER, OFPCR_ROLE_NOCHANGE, OFPCR_ROLE_SLAVE,
    OFPET_BUNDLE_FAILED, OFPET_HELLO_FAILED, OFPET_ROLE_REQUEST_FAILED, OFPHFC_INCOMPATIBLE,
    OFPRRFC_STALE,
};
use crate::protocol::control::{default_async_properties, encode_get_async_reply_properties};
use crate::protocol::error::Result;
use crate::protocol::instruction::Instruction;
use crate::protocol::io::{write_frame, FrameReader, DEFAULT_MAX_FRAME_SIZE};
use crate::protocol::message::Message;
use crate::protocol::ofmatch::Match;
use crate::protocol::packet_in::PacketIn;
use crate::protocol::packet_out::PacketOut;
use crate::protocol::rule::Rule;

use std::collections::HashMap;
use std::fmt::Display;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

static NEXT_SWITCH_ID: AtomicU64 = AtomicU64::new(1);
static LAST_PEER_EVENT_LOG_SECOND: AtomicU64 = AtomicU64::new(0);

const OPENFLOW_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
const OPENFLOW_READ_TIMEOUT: Duration = Duration::from_secs(30);
const DEFAULT_MAX_CONNECTIONS: usize = 256;

trait OpenFlowStream: AsyncWrite + Unpin + Send {}

impl<T> OpenFlowStream for T where T: AsyncWrite + Unpin + Send {}

async fn send_frame<S: OpenFlowStream>(sw: &mut Connection<S>, frame: Vec<u8>) -> Result<()> {
    write_frame(&mut sw.stream, &frame).await?;
    Ok(())
}

fn log_peer_event(message: impl Display) {
    let second = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| duration.as_secs());
    let previous = LAST_PEER_EVENT_LOG_SECOND.load(Ordering::Relaxed);
    if previous == second
        || LAST_PEER_EVENT_LOG_SECOND
            .compare_exchange(previous, second, Ordering::Relaxed, Ordering::Relaxed)
            .is_err()
    {
        return;
    }
    info!(message = %message, "peer-controlled OpenFlow event");
}

const fn property_kind(property: &crate::protocol::control::Property) -> u16 {
    match property {
        crate::protocol::control::Property::ReasonMask { kind, .. }
        | crate::protocol::control::Property::Experimenter { kind, .. }
        | crate::protocol::control::Property::Raw { kind, .. } => *kind,
    }
}

/// Run the controller accept loop.
///
/// # Errors
///
/// Returns an error if the listener cannot bind or a switch session fails.
pub async fn run(addr: &str) -> Result<()> {
    run_with_limits(addr, ConnectionLimits::default()).await
}

/// Run the controller accept loop with explicit per-connection resource
/// limits.
///
/// # Errors
///
/// Returns an error if the listener cannot bind or a switch session fails.
pub async fn run_with_limits(addr: &str, limits: ConnectionLimits) -> Result<()> {
    let listener = TcpListener::bind(addr).await?;
    let connection_slots = std::sync::Arc::new(Semaphore::new(DEFAULT_MAX_CONNECTIONS));
    info!("OpenFlow 1.5 controller listening on {}", addr);

    loop {
        let (stream, peer) = listener.accept().await?;
        info!("switch TCP connection from {}", peer);

        let Ok(permit) = std::sync::Arc::clone(&connection_slots).try_acquire_owned() else {
            info!(
                "rejecting switch TCP connection from {}: connection limit reached",
                peer
            );
            drop(stream);
            continue;
        };

        tokio::spawn(async move {
            let _permit = permit;
            if let Err(e) = handle_switch(stream, limits).await {
                error!("switch handler error: {:?}", e);
            }
        });
    }
}

/// Run the controller accept loop over TLS.
///
/// The caller supplies a fully configured rustls server policy, including the
/// certificate and any client-authentication policy. No plaintext listener is
/// opened by this function.
///
/// # Errors
///
/// Returns an error if the listener cannot bind. Individual TLS or switch
/// sessions are logged and do not terminate the accept loop.
#[cfg(feature = "tls")]
pub async fn run_tls(addr: &str, config: std::sync::Arc<rustls::ServerConfig>) -> Result<()> {
    run_tls_with_limits(addr, config, ConnectionLimits::default()).await
}

/// Run the TLS controller accept loop with explicit per-connection resource
/// limits.
///
/// # Errors
///
/// Returns an error if the listener cannot bind. Individual TLS or switch
/// sessions are logged and do not terminate the accept loop.
#[cfg(feature = "tls")]
pub async fn run_tls_with_limits(
    addr: &str,
    config: std::sync::Arc<rustls::ServerConfig>,
    limits: ConnectionLimits,
) -> Result<()> {
    let listener = TcpListener::bind(addr).await?;
    let connection_slots = std::sync::Arc::new(Semaphore::new(DEFAULT_MAX_CONNECTIONS));
    info!("OpenFlow 1.5 TLS controller listening on {}", addr);

    loop {
        let (stream, peer) = listener.accept().await?;
        let Ok(permit) = std::sync::Arc::clone(&connection_slots).try_acquire_owned() else {
            info!(
                "rejecting switch TLS connection from {}: connection limit reached",
                peer
            );
            drop(stream);
            continue;
        };
        let config = std::sync::Arc::clone(&config);
        info!("switch TLS connection from {}", peer);
        tokio::spawn(async move {
            let _permit = permit;
            let stream = match crate::tls::accept_stream(stream, config).await {
                Ok(stream) => stream,
                Err(error) => {
                    error!("TLS handshake from {} failed: {}", peer, error);
                    return;
                }
            };
            if let Err(error) = handle_switch(stream, limits).await {
                error!("TLS switch handler error: {:?}", error);
            }
        });
    }
}

async fn handle_switch<S>(stream: S, limits: ConnectionLimits) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    let id = NEXT_SWITCH_ID.fetch_add(1, Ordering::Relaxed);

    let (reader, writer) = tokio::io::split(stream);

    let mut sw = Connection {
        id,
        datapath_id: None,
        n_buffers: None,
        n_tables: None,
        auxiliary_id: None,
        capabilities: None,
        config_flags: None,
        miss_send_len: None,
        role: OFPCR_ROLE_EQUAL,
        short_id: 0,
        generation_id: u64::MAX,
        generation_id_defined: false,
        async_config: default_async_properties(),
        bundles: HashMap::new(),
        state: State::Connected,
        stream: writer,
        next_xid: 1,
        mac_table: HashMap::new(),
    };

    let hello_xid = sw.next_xid();
    send_frame(&mut sw, Encoder::hello(hello_xid)?).await?;
    let mut reader = FrameReader::with_max_frame_size(reader, DEFAULT_MAX_FRAME_SIZE);

    loop {
        let frame = if matches!(&sw.state, State::Running) {
            reader
                .read_frame_with_timeout(OPENFLOW_READ_TIMEOUT)
                .await?
        } else {
            reader
                .read_frame_with_timeout(OPENFLOW_HANDSHAKE_TIMEOUT)
                .await?
        };
        let Some(frame) = frame else {
            info!("switch TCP connection closed");
            return Ok(());
        };
        let msg = Decoder::message(&frame)?;
        handle_message(&mut sw, msg, &limits).await?;
    }
}

const fn requires_running_state(msg: &Message) -> bool {
    matches!(
        msg,
        Message::PacketIn(_)
            | Message::BarrierRequest { .. }
            | Message::BarrierReply { .. }
            | Message::GetAsyncRequest { .. }
            | Message::SetAsync { .. }
            | Message::RoleRequest(_)
            | Message::RoleStatus(_)
            | Message::BundleControl(_)
            | Message::BundleAddMessage(_)
    )
}

async fn handle_message<S: OpenFlowStream>(
    sw: &mut Connection<S>,
    msg: Message,
    limits: &ConnectionLimits,
) -> Result<()> {
    ensure_message_allowed(sw, &msg)?;

    match msg {
        Message::Hello {
            version,
            version_bitmap,
            ..
        } => handle_hello(sw, version, version_bitmap).await,
        Message::EchoRequest { xid, payload } => handle_echo_request(sw, xid, payload).await,
        Message::FeaturesReply(reply) => handle_features_reply(sw, reply).await,
        Message::GetConfigReply(reply) => handle_get_config_reply(sw, reply).await,
        Message::PacketIn(pkt) => handle_packet_in_message(sw, &pkt, limits).await,
        Message::Error(msg) => {
            log_peer_event(format_args!(
                "OpenFlow ERROR xid={} type={} code={} data={:02x?}",
                msg.xid, msg.error_type, msg.code, msg.data
            ));
            Ok(())
        }
        Message::BarrierRequest { xid } => handle_barrier_request(sw, xid).await,
        Message::BarrierReply { xid } => {
            log_peer_event(format_args!("barrier reply xid={xid}"));
            Ok(())
        }
        Message::GetAsyncRequest { xid } => handle_get_async_request(sw, xid).await,
        Message::SetAsync { xid, properties } => {
            handle_set_async(sw, xid, properties);
            Ok(())
        }
        Message::RoleRequest(msg) => handle_role_request(sw, msg).await,
        Message::RoleStatus(msg) => {
            handle_role_status(sw, &msg);
            Ok(())
        }
        Message::BundleControl(msg) => handle_bundle_control(sw, msg, limits).await,
        Message::BundleAddMessage(msg) => handle_bundle_add_message(sw, msg, limits).await,
        Message::EchoReply { .. }
        | Message::FeaturesRequest { .. }
        | Message::GetConfigRequest { .. }
        | Message::SetConfig(_)
        | Message::PacketOut(_)
        | Message::FlowMod(_)
        | Message::FlowRemoved(_)
        | Message::PortStatus(_)
        | Message::GroupMod(_)
        | Message::PortMod(_)
        | Message::TableMod(_)
        | Message::MultipartRequest(_)
        | Message::MultipartReply(_)
        | Message::RoleReply(_)
        | Message::GetAsyncReply { .. }
        | Message::TableStatus(_)
        | Message::RequestForward(_)
        | Message::ControllerStatus(_)
        | Message::MeterMod(_)
        | Message::Experimenter { .. }
        | Message::Ignored { .. } => {
            log_peer_event("ignored OpenFlow message");
            Ok(())
        }
    }
}

const fn ensure_message_allowed<S>(sw: &Connection<S>, msg: &Message) -> Result<()> {
    if requires_running_state(msg) && !matches!(sw.state, State::Running) {
        return Err(crate::protocol::error::OfError::InvalidValue {
            field: "message before handshake completion",
            value: 0,
        });
    }
    Ok(())
}

async fn handle_hello<S: OpenFlowStream>(
    sw: &mut Connection<S>,
    version: u8,
    version_bitmap: Option<Vec<u32>>,
) -> Result<()> {
    if !matches!(sw.state, State::Connected) {
        return Err(crate::protocol::error::OfError::InvalidValue {
            field: "hello state",
            value: 0,
        });
    }

    if !crate::protocol::hello::is_version_compatible(version, version_bitmap.as_deref()) {
        let xid = sw.next_xid();
        send_frame(
            sw,
            Encoder::error(
                xid,
                OFPET_HELLO_FAILED,
                OFPHFC_INCOMPATIBLE,
                b"no compatible OpenFlow version (this controller only speaks 1.5)",
            )?,
        )
        .await?;
        return Err(crate::protocol::error::OfError::UnsupportedVersion(version));
    }

    let features_xid = sw.next_xid();
    send_frame(sw, Encoder::features_request(features_xid)).await?;

    sw.state = State::HelloDone { features_xid };
    Ok(())
}

async fn handle_echo_request<S: OpenFlowStream>(
    sw: &mut Connection<S>,
    xid: u32,
    payload: Vec<u8>,
) -> Result<()> {
    let reply = Encoder::echo_reply(xid, &payload)?;
    send_frame(sw, reply).await?;
    Ok(())
}

async fn handle_features_reply<S: OpenFlowStream>(
    sw: &mut Connection<S>,
    reply: crate::protocol::features::Reply,
) -> Result<()> {
    let State::HelloDone { features_xid } = sw.state else {
        return Err(crate::protocol::error::OfError::InvalidValue {
            field: "features reply state",
            value: u64::from(reply.xid),
        });
    };
    if reply.xid != features_xid {
        return Err(crate::protocol::error::OfError::InvalidValue {
            field: "features reply xid",
            value: u64::from(reply.xid),
        });
    }

    sw.datapath_id = Some(reply.datapath_id);
    sw.n_buffers = Some(reply.n_buffers);
    sw.n_tables = Some(reply.n_tables);
    sw.auxiliary_id = Some(reply.auxiliary_id);
    sw.capabilities = Some(reply.capabilities);
    info!(
        "switch features: dpid={:016x}, tables={}, buffers={}",
        reply.datapath_id, reply.n_tables, reply.n_buffers
    );

    let set_config = Encoder::set_config(
        sw.next_xid(),
        0,
        crate::protocol::constants::OFP_DEFAULT_MISS_SEND_LEN,
    );
    send_frame(sw, set_config).await?;

    let get_config_xid = sw.next_xid();
    send_frame(sw, Encoder::get_config_request(get_config_xid)).await?;
    sw.state = State::FeaturesKnown { get_config_xid };

    Ok(())
}

async fn handle_get_config_reply<S: OpenFlowStream>(
    sw: &mut Connection<S>,
    reply: crate::protocol::config::Config,
) -> Result<()> {
    let State::FeaturesKnown { get_config_xid } = sw.state else {
        return Err(crate::protocol::error::OfError::InvalidValue {
            field: "get-config reply state",
            value: u64::from(reply.xid),
        });
    };
    if reply.xid != get_config_xid {
        return Err(crate::protocol::error::OfError::InvalidValue {
            field: "get-config reply xid",
            value: u64::from(reply.xid),
        });
    }

    sw.config_flags = Some(reply.flags);
    sw.miss_send_len = Some(reply.miss_send_len);

    info!(
        "switch config: flags=0x{:04x}, miss_send_len={}",
        reply.flags, reply.miss_send_len
    );

    let fm = Encoder::table_miss_to_controller(sw.next_xid())?;
    write_frame(&mut sw.stream, &fm).await?;

    sw.state = State::Running;
    Ok(())
}

/// What the learning switch decided to do with a packet-in.
///
/// The variants carry already-encoded frames, ready to write to the
/// switch.
pub enum Decision {
    /// Nothing to send -- the packet had no usable ingress port or
    /// Ethernet header.
    Ignore,
    /// Destination not yet learned: flood the packet out every port.
    Flood(Vec<u8>),
    /// Destination known: install a flow for it and forward this packet.
    Unicast {
        /// An `OFPT_FLOW_MOD` teaching the switch this destination.
        flow_mod: Vec<u8>,
        /// An `OFPT_PACKET_OUT` forwarding the packet that triggered it.
        packet_out: Vec<u8>,
    },
}

/// Learning-switch policy: learn the source MAC, then flood or forward.
///
/// Updates `sw`'s MAC table as a side effect. Returns [`Decision::Ignore`]
/// when the packet-in carries no `IN_PORT` or no parseable Ethernet
/// header.
///
/// # Errors
///
/// Returns an error if the forwarding frames cannot be encoded.
pub fn handle_packet_in<S>(sw: &mut Connection<S>, pkt: &PacketIn) -> Result<Decision> {
    handle_packet_in_with_limits(sw, pkt, &ConnectionLimits::default())
}

/// Learning-switch policy with an explicit MAC table limit.
///
/// New MAC addresses evict the lexicographically smallest existing address
/// when the limit is full. This keeps the table strictly bounded while making
/// eviction deterministic even though the backing map is hash-based.
///
/// # Errors
///
/// Returns an error if the forwarding frames cannot be encoded.
pub fn handle_packet_in_with_limits<S>(
    sw: &mut Connection<S>,
    pkt: &PacketIn,
    limits: &ConnectionLimits,
) -> Result<Decision> {
    let Some(in_port) = pkt.in_port() else {
        return Ok(Decision::Ignore);
    };

    let Some(eth) = Frame::parse(&pkt.data) else {
        return Ok(Decision::Ignore);
    };

    if limits.max_mac_entries != 0 {
        if sw.mac_table.len() >= limits.max_mac_entries && !sw.mac_table.contains_key(&eth.src) {
            if let Some(evicted) = sw.mac_table.keys().min().copied() {
                sw.mac_table.remove(&evicted);
            }
        }
        while sw.mac_table.len() > limits.max_mac_entries {
            let Some(evicted) = sw.mac_table.keys().min().copied() else {
                break;
            };
            sw.mac_table.remove(&evicted);
        }
        sw.mac_table.insert(eth.src, in_port);
    } else {
        sw.mac_table.clear();
    }

    if eth.is_broadcast() {
        let po = PacketOut::new(
            sw.next_xid(),
            pkt.buffer_id,
            Some(in_port),
            vec![Action::output(OFPP_FLOOD)],
            pkt.data.clone(),
        )
        .encode()?;

        return Ok(Decision::Flood(po));
    }

    if let Some(out_port) = sw.mac_table.get(&eth.dst).copied() {
        if out_port == in_port {
            return Ok(Decision::Ignore);
        }

        let fm = Rule::add(
            sw.next_xid(),
            0,
            100,
            Match::new(vec![crate::protocol::oxm::eth_dst(eth.dst)]),
            vec![Instruction::apply_actions(vec![Action::output(out_port)])],
        )
        .encode()?;

        let po = PacketOut::new(
            sw.next_xid(),
            pkt.buffer_id,
            Some(in_port),
            vec![Action::output(out_port)],
            pkt.data.clone(),
        )
        .encode()?;

        return Ok(Decision::Unicast {
            flow_mod: fm,
            packet_out: po,
        });
    }

    let po = PacketOut::new(
        sw.next_xid(),
        pkt.buffer_id,
        Some(in_port),
        vec![Action::output(OFPP_FLOOD)],
        pkt.data.clone(),
    )
    .encode()?;

    Ok(Decision::Flood(po))
}

async fn handle_packet_in_message<S: OpenFlowStream>(
    sw: &mut Connection<S>,
    pkt: &crate::protocol::packet_in::PacketIn,
    limits: &ConnectionLimits,
) -> Result<()> {
    match handle_packet_in_with_limits(sw, pkt, limits)? {
        Decision::Ignore => Ok(()),
        Decision::Flood(po) => {
            send_frame(sw, po).await?;
            Ok(())
        }
        Decision::Unicast {
            flow_mod,
            packet_out,
        } => {
            send_frame(sw, flow_mod).await?;
            send_frame(sw, packet_out).await?;
            Ok(())
        }
    }
}

async fn handle_barrier_request<S: OpenFlowStream>(sw: &mut Connection<S>, xid: u32) -> Result<()> {
    send_frame(sw, Encoder::barrier_reply(xid)).await?;
    Ok(())
}

async fn handle_get_async_request<S: OpenFlowStream>(
    sw: &mut Connection<S>,
    xid: u32,
) -> Result<()> {
    send_frame(
        sw,
        encode_get_async_reply_properties(xid, &sw.async_config)?,
    )
    .await?;
    Ok(())
}

fn handle_set_async<S>(
    sw: &mut Connection<S>,
    xid: u32,
    properties: Vec<crate::protocol::control::Property>,
) {
    for property in properties {
        if let Some(existing) = sw
            .async_config
            .iter_mut()
            .find(|existing| property_kind(existing) == property_kind(&property))
        {
            *existing = property;
        } else {
            sw.async_config.push(property);
        }
    }
    info!("updated async config xid={}", xid);
}

fn handle_role_status<S>(sw: &mut Connection<S>, msg: &crate::protocol::control::RoleStatus) {
    sw.role = msg.role;
    sw.generation_id = msg.generation_id;
    sw.generation_id_defined = true;
    info!("role status xid={} role={}", msg.xid, msg.role);
}

async fn handle_role_request<S: OpenFlowStream>(
    sw: &mut Connection<S>,
    msg: crate::protocol::control::RoleRequest,
) -> Result<()> {
    if matches!(msg.role, OFPCR_ROLE_MASTER | OFPCR_ROLE_SLAVE)
        && sw.generation_id_defined
        && generation_is_stale(msg.generation_id, sw.generation_id)
    {
        // A stale request must not alter either the role or the short id.
        // This is an error reply rather than a role reply, per §7.3.8.
        send_frame(
            sw,
            Encoder::error(msg.xid, OFPET_ROLE_REQUEST_FAILED, OFPRRFC_STALE, &[])?,
        )
        .await?;
        return Ok(());
    }

    if msg.role != OFPCR_ROLE_NOCHANGE {
        sw.role = msg.role;
        sw.short_id = msg.short_id;
        if matches!(msg.role, OFPCR_ROLE_MASTER | OFPCR_ROLE_SLAVE) {
            sw.generation_id = msg.generation_id;
            sw.generation_id_defined = true;
        }
    }
    send_frame(
        sw,
        Encoder::role_reply(msg.xid, sw.role, sw.short_id, sw.generation_id)?,
    )
    .await?;
    Ok(())
}

/// `OpenFlow` compares generation ids as wrapping signed sequence numbers.
/// A negative signed distance means that `candidate` is older than `current`.
const fn generation_is_stale(candidate: u64, current: u64) -> bool {
    candidate.wrapping_sub(current).cast_signed() < 0
}

async fn handle_bundle_open<S: OpenFlowStream>(
    sw: &mut Connection<S>,
    msg: &crate::protocol::control::BundleMessage,
    limits: &ConnectionLimits,
) -> Result<()> {
    if sw.bundles.contains_key(&msg.bundle_id) {
        info!("bundle open for existing bundle_id={}", msg.bundle_id);
        return send_bundle_failed(sw, msg.xid, OFPBFC_BAD_ID).await;
    }

    if sw.bundles.len() >= limits.max_open_bundles {
        info!("bundle open exceeds connection limit");
        return send_bundle_failed(sw, msg.xid, OFPBFC_OUT_OF_BUNDLES).await;
    }

    sw.bundles.insert(
        msg.bundle_id,
        BundleRecord {
            flags: msg.flags,
            closed: false,
            messages: Vec::new(),
        },
    );
    send_frame(
        sw,
        Encoder::bundle_control(
            msg.xid,
            msg.bundle_id,
            OFPBCT_OPEN_REPLY,
            msg.flags,
            &msg.properties,
        )?,
    )
    .await
}

async fn handle_bundle_close<S: OpenFlowStream>(
    sw: &mut Connection<S>,
    msg: &crate::protocol::control::BundleMessage,
) -> Result<()> {
    if let Some(bundle) = sw.bundles.get_mut(&msg.bundle_id) {
        bundle.closed = true;
        send_frame(
            sw,
            Encoder::bundle_control(
                msg.xid,
                msg.bundle_id,
                OFPBCT_CLOSE_REPLY,
                msg.flags,
                &msg.properties,
            )?,
        )
        .await
    } else {
        info!("bundle close for unknown bundle_id={}", msg.bundle_id);
        send_bundle_failed(sw, msg.xid, OFPBFC_BAD_ID).await
    }
}

async fn handle_bundle_commit<S: OpenFlowStream>(
    sw: &mut Connection<S>,
    msg: &crate::protocol::control::BundleMessage,
) -> Result<()> {
    if let Some(bundle) = sw.bundles.remove(&msg.bundle_id) {
        info!(
            "committed bundle_id={} flags={} messages={}",
            msg.bundle_id,
            bundle.flags,
            bundle.messages.len()
        );
        for nested in bundle.messages {
            send_frame(sw, nested).await?;
        }
        send_frame(
            sw,
            Encoder::bundle_control(
                msg.xid,
                msg.bundle_id,
                OFPBCT_COMMIT_REPLY,
                msg.flags,
                &msg.properties,
            )?,
        )
        .await
    } else {
        info!("bundle commit for unknown bundle_id={}", msg.bundle_id);
        send_bundle_failed(sw, msg.xid, OFPBFC_BAD_ID).await
    }
}

async fn handle_bundle_discard<S: OpenFlowStream>(
    sw: &mut Connection<S>,
    msg: &crate::protocol::control::BundleMessage,
) -> Result<()> {
    if sw.bundles.remove(&msg.bundle_id).is_some() {
        send_frame(
            sw,
            Encoder::bundle_control(
                msg.xid,
                msg.bundle_id,
                OFPBCT_DISCARD_REPLY,
                msg.flags,
                &msg.properties,
            )?,
        )
        .await
    } else {
        info!("bundle discard for unknown bundle_id={}", msg.bundle_id);
        send_bundle_failed(sw, msg.xid, OFPBFC_BAD_ID).await
    }
}

async fn handle_bundle_control<S: OpenFlowStream>(
    sw: &mut Connection<S>,
    msg: crate::protocol::control::BundleMessage,
    limits: &ConnectionLimits,
) -> Result<()> {
    match msg.ctrl_type {
        OFPBCT_OPEN_REQUEST => handle_bundle_open(sw, &msg, limits).await,
        OFPBCT_CLOSE_REQUEST => handle_bundle_close(sw, &msg).await,
        OFPBCT_COMMIT_REQUEST => handle_bundle_commit(sw, &msg).await,
        OFPBCT_DISCARD_REQUEST => handle_bundle_discard(sw, &msg).await,
        _ => {
            info!(
                "received bundle reply xid={} bundle_id={} type={}",
                msg.xid, msg.bundle_id, msg.ctrl_type
            );
            Ok(())
        }
    }
}

async fn handle_bundle_add_message<S: OpenFlowStream>(
    sw: &mut Connection<S>,
    msg: crate::protocol::control::BundleAddMessage,
    limits: &ConnectionLimits,
) -> Result<()> {
    let Some(bundle) = sw.bundles.get(&msg.bundle_id) else {
        info!("bundle add for unknown bundle_id={}", msg.bundle_id);
        send_bundle_failed(sw, msg.xid, OFPBFC_BAD_ID).await?;
        return Ok(());
    };

    if bundle.closed {
        info!("bundle add for closed bundle_id={}", msg.bundle_id);
        send_bundle_failed(sw, msg.xid, OFPBFC_BUNDLE_CLOSED).await?;
        return Ok(());
    }

    if bundle.messages.len() >= limits.max_messages_per_bundle
        || retained_bundle_bytes(sw).saturating_add(msg.message.len())
            > limits.max_total_bundle_bytes
    {
        info!(
            "bundle add exceeds resource limit bundle_id={} message_len={}",
            msg.bundle_id,
            msg.message.len()
        );
        send_bundle_failed(sw, msg.xid, OFPBFC_MSG_TOO_MANY).await?;
        return Ok(());
    }

    if let Some(bundle) = sw.bundles.get_mut(&msg.bundle_id) {
        bundle.messages.push(msg.message);
    }
    Ok(())
}

fn retained_bundle_bytes<S>(sw: &Connection<S>) -> usize {
    sw.bundles
        .values()
        .map(|bundle| bundle.messages.iter().map(Vec::len).sum::<usize>())
        .sum()
}

async fn send_bundle_failed<S: OpenFlowStream>(
    sw: &mut Connection<S>,
    xid: u32,
    code: u16,
) -> Result<()> {
    send_frame(sw, Encoder::error(xid, OFPET_BUNDLE_FAILED, code, &[])?).await?;
    Ok(())
}

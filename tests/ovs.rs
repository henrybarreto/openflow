//! Integration tests that run this crate's `OpenFlow` client against a real
//! Open vSwitch instance, built and started from
//! `tests/container/Containerfile` via `testcontainers`.
//!
//! # Why the local management socket, not a network controller target
//!
//! Every OVS bridge exposes a local `OpenFlow` control channel at
//! `<run-dir>/<bridge>.mgmt`, independent of whatever remote controller (if
//! any) is configured via `ovs-vsctl set-controller`. It is the same channel
//! `ovs-ofctl <bridge> ...` uses when no explicit target is given, and it
//! receives asynchronous messages (`PACKET_IN`, etc.) exactly like a real
//! controller connection. Using it means the test process talks straight to
//! the switch without needing the container to dial back out to the host,
//! so `tests/container/entrypoint.sh` bind-mounts its OVS run directory out
//! to a host-side temp directory, and these tests connect to the socket
//! file that appears there via `openflow::client::Connection::connect_unix`.
//!
//! # Requirements to run
//!
//! These tests need a working container engine (Podman, or anything else
//! `testcontainers` can talk to) and enough privilege to create veth pairs
//! and bring up a userspace `Open vSwitch` bridge inside the container
//! (`--privileged`, or at least `NET_ADMIN`/`NET_RAW`). They
//! are gated behind `OPENFLOW_RUN_OVS_TESTS=1` since they are slow (image
//! build + container boot) and require that privilege, which most sandboxed
//! CI runners and dev machines don't grant by default.
//!
//! ```bash
//! ./scripts/test-ovs.sh
//! ```

#![cfg(not(clippy))]

use std::path::{Path, PathBuf};
use std::time::Duration;

use openflow::client::{Connection, Error as ClientError};
use openflow::protocol::action::Action;
use openflow::protocol::constants::{
    ETH_TYPE_IPV4, NX_CS_RPL, NX_CS_TRK, OFPACFC_UNSUPPORTED, OFPACPT_CONT_STATUS_MASTER,
    OFPACPT_FLOW_REMOVED_MASTER, OFPACPT_PACKET_IN_MASTER, OFPACPT_PORT_STATUS_MASTER,
    OFPBCT_CLOSE_REPLY, OFPBCT_CLOSE_REQUEST, OFPBCT_COMMIT_REPLY, OFPBCT_COMMIT_REQUEST,
    OFPBCT_DISCARD_REPLY, OFPBCT_DISCARD_REQUEST, OFPBCT_OPEN_REPLY, OFPBCT_OPEN_REQUEST,
    OFPBF_ORDERED, OFPBRC_BAD_MULTIPART, OFPBRC_IS_SLAVE, OFPCML_NO_BUFFER, OFPCR_ROLE_EQUAL,
    OFPCR_ROLE_MASTER, OFPCR_ROLE_NOCHANGE, OFPCR_ROLE_SLAVE, OFPCSR_CONTROLLER_ADDED, OFPCSR_ROLE,
    OFPCSR_SHORT_ID, OFPET_ASYNC_CONFIG_FAILED, OFPET_BAD_REQUEST, OFPET_FLOW_MOD_FAILED,
    OFPET_FLOW_MONITOR_FAILED, OFPFC_DELETE_STRICT, OFPFC_MODIFY_STRICT, OFPFF_SEND_FLOW_REM,
    OFPFMC_ADD, OFPFMFC_BAD_TABLE_ID, OFPFMF_ADD, OFPFMF_REMOVED, OFPGC_INSERT_BUCKET,
    OFPGC_MODIFY, OFPGC_REMOVE_BUCKET, OFPGT_ALL, OFPG_ALL, OFPG_ANY, OFPG_BUCKET_ALL,
    OFPG_BUCKET_LAST, OFPMC_ADD, OFPMC_DELETE, OFPMC_MODIFY, OFPMF_KBPS, OFPMP_AGGREGATE_STATS,
    OFPMP_BUNDLE_FEATURES, OFPMP_CONTROLLER_STATUS, OFPMP_DESC, OFPMP_EXPERIMENTER,
    OFPMP_FLOW_DESC, OFPMP_FLOW_MONITOR, OFPMP_FLOW_STATS, OFPMP_GROUP_DESC, OFPMP_GROUP_FEATURES,
    OFPMP_GROUP_STATS, OFPMP_METER_DESC, OFPMP_METER_FEATURES, OFPMP_METER_STATS, OFPMP_PORT_DESC,
    OFPMP_PORT_STATS, OFPMP_QUEUE_DESC, OFPMP_QUEUE_STATS, OFPMP_TABLE_DESC, OFPMP_TABLE_FEATURES,
    OFPMP_TABLE_STATS, OFPPC_PORT_DOWN, OFPP_ANY, OFPP_CONTROLLER, OFPQ_ALL, OFPRR_HARD_TIMEOUT,
    OFPTT_ALL, OFP_NO_BUFFER,
};

use openflow::protocol::codec::Encoder;
use openflow::protocol::control::{
    Bucket, BundleAddMessage, BundleFeaturesRequest, BundleMessage, FlowMonitorRequest,
    FlowStatsRequest, GroupMod, GroupMultipartRequest, MeterBand, MeterMod, MeterMultipartRequest,
    MultipartReplyBody, MultipartRequestBody, Property, QueueMultipartRequest,
};
use openflow::protocol::instruction::Instruction;
use openflow::protocol::message::Message;
use openflow::protocol::nicira;
use openflow::protocol::ofmatch::Match;
use openflow::protocol::oxm;
use openflow::protocol::oxs::Tlv as OxsTlv;
use openflow::protocol::rule::Rule;

use testcontainers::core::{CmdWaitFor, ExecCommand, Mount, WaitFor};
use testcontainers::runners::{AsyncBuilder, AsyncRunner};
use testcontainers::{ContainerAsync, GenericBuildableImage, GenericImage, ImageExt};

fn run_ovs_tests_enabled() -> bool {
    std::env::var_os("OPENFLOW_RUN_OVS_TESTS").is_some()
}

const BRIDGE_NAME: &str = "ofbr0";
const VETH_OUTER: &str = "ofveth0";
const VETH_INNER: &str = "ofveth1";

struct OvsBridge {
    // Kept alive for the container's lifetime; dropping it stops/removes the
    // container (and, via entrypoint.sh's trap, tears down the bridge/veth).
    _container: ContainerAsync<GenericImage>,
    run_dir: PathBuf,
}

impl OvsBridge {
    fn mgmt_socket_path(&self) -> PathBuf {
        self.run_dir.join(format!("{BRIDGE_NAME}.mgmt"))
    }

    async fn connect(&self) -> Connection<tokio::net::UnixStream> {
        connect_with_retry(&self.mgmt_socket_path()).await
    }

    async fn exec_checked(&self, command: ExecCommand) -> Vec<u8> {
        let mut result = self
            ._container
            .exec(command.with_cmd_ready_condition(CmdWaitFor::exit()))
            .await
            .expect("failed to execute command in OVS container");
        assert_eq!(
            result
                .exit_code()
                .await
                .expect("failed to inspect OVS command"),
            Some(0)
        );
        result
            .stdout_to_vec()
            .await
            .expect("failed to read OVS command output")
    }
}

async fn connect_with_retry(path: &Path) -> Connection<tokio::net::UnixStream> {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(15);
    loop {
        match Connection::connect_unix(path).await {
            Ok(conn) => return conn,
            Err(err) => {
                if tokio::time::Instant::now() >= deadline {
                    panic!("failed to connect to OVS mgmt socket at {path:?}: {err}");
                }
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        }
    }
}

async fn start_bridge() -> OvsBridge {
    let run_dir = std::env::temp_dir().join(format!("openflow-ovs-it-{}", uuid_like()));
    std::fs::create_dir_all(&run_dir).expect("failed to create OVS run-dir mount source");

    let image = GenericBuildableImage::new("openflow-ovs-integration-test", "latest")
        .with_dockerfile(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/container/Containerfile"
        ))
        .with_file(
            concat!(env!("CARGO_MANIFEST_DIR"), "/tests/container/entrypoint.sh"),
            "entrypoint.sh",
        )
        .build_image()
        .await
        .expect("failed to build the OVS test image");

    let container = image
        .with_wait_for(WaitFor::message_on_stdout("entrypoint: ready"))
        .with_env_var("BRIDGE_NAME", BRIDGE_NAME)
        .with_env_var("VETH_OUTER", VETH_OUTER)
        .with_env_var("VETH_INNER", VETH_INNER)
        .with_mount(Mount::bind_mount(
            run_dir.to_string_lossy().into_owned(),
            "/var/run/openvswitch",
        ))
        // Needed to load the netdev datapath, create veth pairs, and bring
        // links up inside the container's own network namespace.
        .with_privileged(true)
        .start()
        .await
        .expect("failed to start the OVS container");

    OvsBridge {
        _container: container,
        run_dir,
    }
}

fn uuid_like() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    format!("{nanos:x}-{:x}", std::process::id())
}

async fn port_desc(
    conn: &mut Connection<tokio::net::UnixStream>,
) -> Vec<openflow::protocol::control::PortDescEntry> {
    match conn
        .multipart_request(
            OFPMP_PORT_DESC,
            &MultipartRequestBody::Port(openflow::protocol::control::PortMultipartRequest {
                port_no: OFPP_ANY,
            }),
        )
        .await
        .expect("OFPMP_PORT_DESC request failed")
    {
        MultipartReplyBody::PortDesc(entries) => entries,
        other => panic!("unexpected OFPMP_PORT_DESC reply: {other:?}"),
    }
}

async fn flow_desc(
    conn: &mut Connection<tokio::net::UnixStream>,
) -> Vec<openflow::protocol::control::FlowDesc> {
    let body = MultipartRequestBody::FlowStats(openflow::protocol::control::FlowStatsRequest {
        table_id: OFPTT_ALL,
        out_port: openflow::protocol::constants::OFPP_ANY,
        out_group: openflow::protocol::constants::OFPG_ANY,
        cookie: 0,
        cookie_mask: 0,
        of_match: Vec::new(),
    });
    match conn
        .multipart_request(OFPMP_FLOW_DESC, &body)
        .await
        .expect("OFPMP_FLOW_DESC request failed")
    {
        MultipartReplyBody::FlowDesc(entries) => entries,
        other => panic!("unexpected OFPMP_FLOW_DESC reply: {other:?}"),
    }
}

async fn group_desc(
    conn: &mut Connection<tokio::net::UnixStream>,
) -> Vec<openflow::protocol::control::GroupDescEntry> {
    match conn
        .multipart_request(
            OFPMP_GROUP_DESC,
            &MultipartRequestBody::Group(GroupMultipartRequest { group_id: OFPG_ALL }),
        )
        .await
        .expect("OFPMP_GROUP_DESC request failed")
    {
        MultipartReplyBody::GroupDesc(entries) => entries,
        other => panic!("unexpected OFPMP_GROUP_DESC reply: {other:?}"),
    }
}

async fn group_stats(
    conn: &mut Connection<tokio::net::UnixStream>,
) -> Vec<openflow::protocol::control::GroupStatsEntry> {
    match conn
        .multipart_request(
            OFPMP_GROUP_STATS,
            &MultipartRequestBody::Group(GroupMultipartRequest { group_id: OFPG_ALL }),
        )
        .await
        .expect("OFPMP_GROUP_STATS request failed")
    {
        MultipartReplyBody::GroupStats(entries) => entries,
        other => panic!("unexpected OFPMP_GROUP_STATS reply: {other:?}"),
    }
}

/// `OFPM_ALL`: the "all meters" wildcard. Not defined as a constant by this
/// crate (meter multipart requests just carry a raw `meter_id`), so it is
/// spelled out here per the OF1.5.1 spec value.
const OFPM_ALL: u32 = 0xffff_ffff;

async fn meter_desc(
    conn: &mut Connection<tokio::net::UnixStream>,
) -> Vec<openflow::protocol::control::MeterDescEntry> {
    match conn
        .multipart_request(
            OFPMP_METER_DESC,
            &MultipartRequestBody::Meter(MeterMultipartRequest { meter_id: OFPM_ALL }),
        )
        .await
        .expect("OFPMP_METER_DESC request failed")
    {
        MultipartReplyBody::MeterDesc(entries) => entries,
        other => panic!("unexpected OFPMP_METER_DESC reply: {other:?}"),
    }
}

async fn meter_stats(
    conn: &mut Connection<tokio::net::UnixStream>,
) -> Vec<openflow::protocol::control::MeterStatsEntry> {
    match conn
        .multipart_request(
            OFPMP_METER_STATS,
            &MultipartRequestBody::Meter(MeterMultipartRequest { meter_id: OFPM_ALL }),
        )
        .await
        .expect("OFPMP_METER_STATS request failed")
    {
        MultipartReplyBody::MeterStats(entries) => entries,
        other => panic!("unexpected OFPMP_METER_STATS reply: {other:?}"),
    }
}

#[tokio::test]
async fn handshake_completes_against_real_ovs() {
    if !run_ovs_tests_enabled() {
        return;
    }
    let bridge = start_bridge().await;
    let conn = bridge.connect().await;

    let features = conn.features().expect("handshake did not yield features");
    assert!(features.n_tables > 0, "switch reported zero flow tables");
    assert_ne!(
        features.datapath_id, 0,
        "switch reported a zero datapath id"
    );
}

#[tokio::test]
async fn ovs_bridge_tools_trace_restart_and_reconnect() {
    if !run_ovs_tests_enabled() {
        return;
    }
    let bridge = start_bridge().await;
    let exists = bridge
        .exec_checked(ExecCommand::new(["ovs-vsctl", "br-exists", BRIDGE_NAME]))
        .await;
    assert!(exists.is_empty());

    let trace = bridge
        .exec_checked(ExecCommand::new([
            "ovs-appctl",
            "ofproto/trace",
            BRIDGE_NAME,
            "in_port=1,dl_src=00:11:22:33:44:55,dl_dst=ff:ff:ff:ff:ff:ff,dl_type=0x0800",
        ]))
        .await;
    let trace = String::from_utf8_lossy(&trace);
    assert!(
        trace.contains("Datapath actions"),
        "unexpected trace output: {trace}"
    );

    let restart = "ovs-appctl -t ovs-vswitchd exit; sleep 1; ovs-vswitchd --pidfile --detach --log-file -vsyslog:off -vconsole:info; sleep 1; chmod 0777 /var/run/openvswitch/ofbr0.mgmt";
    bridge
        .exec_checked(ExecCommand::new(["sh", "-c", restart]))
        .await;
    let mut connection = bridge.connect().await;
    connection
        .get_config()
        .await
        .expect("OpenFlow management socket did not reconnect after restart");
}

#[tokio::test]
async fn desc_multipart_reports_open_vswitch() {
    if !run_ovs_tests_enabled() {
        return;
    }
    let bridge = start_bridge().await;
    let mut conn = bridge.connect().await;

    let reply = conn
        .multipart_request(OFPMP_DESC, &MultipartRequestBody::Empty)
        .await
        .expect("OFPMP_DESC request failed");

    match reply {
        MultipartReplyBody::Desc(desc) => {
            assert!(
                desc.mfr_desc.to_lowercase().contains("nicira")
                    || desc.sw_desc.to_lowercase().contains("open vswitch"),
                "unexpected OFPMP_DESC contents: {desc:?}"
            );
        }
        other => panic!("unexpected OFPMP_DESC reply: {other:?}"),
    }
}

#[tokio::test]
async fn table_stats_matches_features_table_count() {
    if !run_ovs_tests_enabled() {
        return;
    }
    let bridge = start_bridge().await;
    let mut conn = bridge.connect().await;
    let n_tables = conn.features().unwrap().n_tables;

    match conn
        .multipart_request(OFPMP_TABLE_STATS, &MultipartRequestBody::Empty)
        .await
        .expect("OFPMP_TABLE_STATS request failed")
    {
        MultipartReplyBody::TableStats(entries) => {
            assert_eq!(entries.len(), usize::from(n_tables));
        }
        other => panic!("unexpected OFPMP_TABLE_STATS reply: {other:?}"),
    }
}

#[tokio::test]
async fn port_desc_reports_the_test_veth_port() {
    if !run_ovs_tests_enabled() {
        return;
    }
    let bridge = start_bridge().await;
    let mut conn = bridge.connect().await;

    let ports = port_desc(&mut conn).await;
    assert!(
        ports.iter().any(|p| p.name == VETH_INNER),
        "expected a port named {VETH_INNER}, got: {ports:?}"
    );
}

#[tokio::test]
async fn flow_table_starts_empty() {
    if !run_ovs_tests_enabled() {
        return;
    }
    let bridge = start_bridge().await;
    let mut conn = bridge.connect().await;

    assert!(flow_desc(&mut conn).await.is_empty());
}

#[tokio::test]
async fn add_flow_then_delete_round_trips_through_flow_desc() {
    if !run_ovs_tests_enabled() {
        return;
    }
    let bridge = start_bridge().await;
    let mut conn = bridge.connect().await;

    let rule = Rule::add(
        0,
        0,
        1000,
        Match::any(),
        vec![Instruction::ApplyActions(vec![Action::Output {
            port: OFPP_CONTROLLER,
            max_len: OFPCML_NO_BUFFER,
        }])],
    );
    conn.add_flow(rule).await.expect("add_flow failed");

    let entries = flow_desc(&mut conn).await;
    assert_eq!(
        entries.len(),
        1,
        "expected exactly one installed flow: {entries:?}"
    );
    assert_eq!(entries[0].priority, 1000);
    assert_eq!(entries[0].table_id, 0);

    conn.delete_flows(None).await.expect("delete_flows failed");
    assert!(flow_desc(&mut conn).await.is_empty());
}

#[tokio::test]
async fn table_miss_flow_produces_a_real_packet_in() {
    if !run_ovs_tests_enabled() {
        return;
    }
    let bridge = start_bridge().await;
    let mut conn = bridge.connect().await;

    // The bridge's local management socket is a "service" connection, which
    // OVS defaults to a fully-masked (nothing enabled) async config, unlike
    // a real controller connection — without this, OVS never forwards the
    // PACKET_IN this test waits for.
    conn.send_raw(
        &openflow::protocol::codec::Encoder::set_async(
            1,
            &[openflow::protocol::control::Property::ReasonMask {
                kind: openflow::protocol::constants::OFPACPT_PACKET_IN_MASTER,
                mask: 0x7,
            }],
        )
        .expect("encode set_async"),
    )
    .await
    .expect("failed to send OFPT_SET_ASYNC");
    conn.send_barrier()
        .await
        .expect("barrier after set_async failed");

    // fail_mode=secure (set by entrypoint.sh) means an empty table drops
    // everything unless something forwards misses to the controller, so
    // install that miss rule ourselves before generating traffic.
    let rule = Rule::add(
        0,
        0,
        0,
        Match::any(),
        vec![Instruction::ApplyActions(vec![Action::Output {
            port: OFPP_CONTROLLER,
            max_len: OFPCML_NO_BUFFER,
        }])],
    );
    conn.add_flow(rule).await.expect("add_flow failed");

    // Generate a real Ethernet frame from inside the container: an ARP
    // request out ofveth0 crosses the veth wire into ofveth1, which is the
    // bridge port, and (since the table only has our miss rule) gets sent
    // back to us as a PACKET_IN.
    bridge
        .exec_arping()
        .await
        .expect("failed to run arping inside the OVS container");

    let packet_in = tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            match conn.recv_message().await.expect("failed reading a message") {
                Message::PacketIn(pkt) => return pkt,
                Message::EchoRequest { xid, payload } => {
                    conn.send_raw(
                        &openflow::protocol::codec::Encoder::echo_reply(xid, &payload)
                            .expect("encode echo reply"),
                    )
                    .await
                    .expect("failed to answer echo request");
                }
                other => panic!("unexpected message while waiting for PACKET_IN: {other:?}"),
            }
        }
    })
    .await
    .expect("timed out waiting for a real PACKET_IN from OVS");

    assert!(
        !packet_in.data.is_empty(),
        "PACKET_IN carried no packet data"
    );

    let veth_port = port_desc(&mut conn)
        .await
        .into_iter()
        .find(|p| p.name == VETH_INNER)
        .expect("veth port missing from OFPMP_PORT_DESC")
        .port_no;
    assert_eq!(packet_in.in_port(), Some(veth_port));
}

#[tokio::test]
async fn reconnecting_to_the_local_socket_works_repeatedly() {
    if !run_ovs_tests_enabled() {
        return;
    }
    let bridge = start_bridge().await;

    for _ in 0..3 {
        let conn = bridge.connect().await;
        assert!(conn.features().is_some());
        drop(conn);
    }
}

#[tokio::test]
async fn aggregate_stats_reports_zero_when_table_empty() {
    if !run_ovs_tests_enabled() {
        return;
    }
    let bridge = start_bridge().await;
    let mut conn = bridge.connect().await;

    let body = MultipartRequestBody::FlowStats(openflow::protocol::control::FlowStatsRequest {
        table_id: OFPTT_ALL,
        out_port: OFPP_ANY,
        out_group: openflow::protocol::constants::OFPG_ANY,
        cookie: 0,
        cookie_mask: 0,
        of_match: Vec::new(),
    });
    match conn
        .multipart_request(OFPMP_AGGREGATE_STATS, &body)
        .await
        .expect("OFPMP_AGGREGATE_STATS request failed")
    {
        MultipartReplyBody::Aggregate(_) => {}
        other => panic!("unexpected OFPMP_AGGREGATE_STATS reply: {other:?}"),
    }
}

#[tokio::test]
async fn port_stats_reports_the_test_veth_port() {
    if !run_ovs_tests_enabled() {
        return;
    }
    let bridge = start_bridge().await;
    let mut conn = bridge.connect().await;

    match conn
        .multipart_request(
            OFPMP_PORT_STATS,
            &MultipartRequestBody::Port(openflow::protocol::control::PortMultipartRequest {
                port_no: OFPP_ANY,
            }),
        )
        .await
        .expect("OFPMP_PORT_STATS request failed")
    {
        MultipartReplyBody::PortStats(entries) => {
            let port_no = port_desc(&mut conn)
                .await
                .into_iter()
                .find(|p| p.name == VETH_INNER)
                .expect("veth port missing from OFPMP_PORT_DESC")
                .port_no;
            assert!(
                entries.iter().any(|e| e.port_no == port_no),
                "expected port stats for {VETH_INNER}, got: {entries:?}"
            );
        }
        other => panic!("unexpected OFPMP_PORT_STATS reply: {other:?}"),
    }
}

#[tokio::test]
async fn group_features_multipart_succeeds() {
    if !run_ovs_tests_enabled() {
        return;
    }
    let bridge = start_bridge().await;
    let mut conn = bridge.connect().await;

    match conn
        .multipart_request(OFPMP_GROUP_FEATURES, &MultipartRequestBody::Empty)
        .await
        .expect("OFPMP_GROUP_FEATURES request failed")
    {
        MultipartReplyBody::GroupFeatures(_) => {}
        other => panic!("unexpected OFPMP_GROUP_FEATURES reply: {other:?}"),
    }
}

#[tokio::test]
async fn meter_features_multipart_succeeds() {
    if !run_ovs_tests_enabled() {
        return;
    }
    let bridge = start_bridge().await;
    let mut conn = bridge.connect().await;

    match conn
        .multipart_request(OFPMP_METER_FEATURES, &MultipartRequestBody::Empty)
        .await
        .expect("OFPMP_METER_FEATURES request failed")
    {
        MultipartReplyBody::MeterFeatures(_) => {}
        other => panic!("unexpected OFPMP_METER_FEATURES reply: {other:?}"),
    }
}

#[tokio::test]
async fn table_features_get_reports_all_tables() {
    if !run_ovs_tests_enabled() {
        return;
    }
    let bridge = start_bridge().await;
    let mut conn = bridge.connect().await;
    let n_tables = conn.features().unwrap().n_tables;

    // An empty request body is OVS's documented way to *get* the current
    // table-features array (as opposed to setting it).
    match conn
        .multipart_request(
            OFPMP_TABLE_FEATURES,
            &MultipartRequestBody::TableFeatures(Vec::new()),
        )
        .await
        .expect("OFPMP_TABLE_FEATURES request failed")
    {
        MultipartReplyBody::TableFeatures(entries) => {
            assert_eq!(entries.len(), usize::from(n_tables));
        }
        other => panic!("unexpected OFPMP_TABLE_FEATURES reply: {other:?}"),
    }
}

#[tokio::test]
async fn table_desc_matches_table_count() {
    if !run_ovs_tests_enabled() {
        return;
    }
    let bridge = start_bridge().await;
    let mut conn = bridge.connect().await;
    let n_tables = conn.features().unwrap().n_tables;

    match conn
        .multipart_request(OFPMP_TABLE_DESC, &MultipartRequestBody::Empty)
        .await
        .expect("OFPMP_TABLE_DESC request failed")
    {
        MultipartReplyBody::TableDesc(entries) => {
            assert_eq!(entries.len(), usize::from(n_tables));
        }
        other => panic!("unexpected OFPMP_TABLE_DESC reply: {other:?}"),
    }
}

#[tokio::test]
async fn bundle_features_multipart_is_rejected_as_unsupported_by_ovs() {
    if !run_ovs_tests_enabled() {
        return;
    }
    let bridge = start_bridge().await;
    let mut conn = bridge.connect().await;

    // OVS 3.x does not implement OFPMP_BUNDLE_FEATURES and answers
    // OFPBRC_BAD_MULTIPART. Asserting the rejection still exercises our
    // request encoder and the error-decode path; if a future OVS gains
    // support, this test tells us by failing.
    let err = conn
        .multipart_request(
            OFPMP_BUNDLE_FEATURES,
            &MultipartRequestBody::BundleFeatures(BundleFeaturesRequest {
                feature_request_flags: 0,
                properties: Vec::new(),
            }),
        )
        .await
        .expect_err("expected OVS to reject OFPMP_BUNDLE_FEATURES");
    match err {
        ClientError::Remote {
            error_type, code, ..
        } => {
            assert_eq!(error_type, OFPET_BAD_REQUEST);
            assert_eq!(code, OFPBRC_BAD_MULTIPART);
        }
        other => panic!("expected a remote OFPT_ERROR, got: {other}"),
    }
}

#[tokio::test]
async fn get_config_round_trips_after_set_config() {
    if !run_ovs_tests_enabled() {
        return;
    }
    let bridge = start_bridge().await;
    let mut conn = bridge.connect().await;

    let miss_send_len = 128;
    conn.send_raw(&openflow::protocol::codec::Encoder::set_config(
        1,
        0,
        miss_send_len,
    ))
    .await
    .expect("failed to send OFPT_SET_CONFIG");
    conn.send_barrier()
        .await
        .expect("barrier after set_config failed");

    conn.send_raw(&openflow::protocol::codec::Encoder::get_config_request(2))
        .await
        .expect("failed to send OFPT_GET_CONFIG_REQUEST");
    match conn.recv_message().await.expect("failed reading a message") {
        Message::GetConfigReply(config) => {
            assert_eq!(config.miss_send_len, miss_send_len);
        }
        other => panic!("unexpected reply to OFPT_GET_CONFIG_REQUEST: {other:?}"),
    }
}

#[tokio::test]
async fn get_async_request_returns_a_reply() {
    if !run_ovs_tests_enabled() {
        return;
    }
    let bridge = start_bridge().await;
    let mut conn = bridge.connect().await;

    conn.send_raw(
        &openflow::protocol::codec::Encoder::get_async_request(1)
            .expect("encode get_async_request"),
    )
    .await
    .expect("failed to send OFPT_GET_ASYNC_REQUEST");
    match conn.recv_message().await.expect("failed reading a message") {
        Message::GetAsyncReply { .. } => {}
        other => panic!("unexpected reply to OFPT_GET_ASYNC_REQUEST: {other:?}"),
    }
}

#[tokio::test]
async fn packet_out_is_accepted() {
    if !run_ovs_tests_enabled() {
        return;
    }
    let bridge = start_bridge().await;
    let mut conn = bridge.connect().await;

    conn.send_raw(
        &openflow::protocol::codec::Encoder::packet_out(1, OFP_NO_BUFFER, None, Vec::new(), &[])
            .expect("encode packet out"),
    )
    .await
    .expect("failed to send OFPT_PACKET_OUT");
    conn.send_barrier()
        .await
        .expect("barrier after packet_out failed");
}

#[tokio::test]
async fn table_mod_is_accepted() {
    if !run_ovs_tests_enabled() {
        return;
    }
    let bridge = start_bridge().await;
    let mut conn = bridge.connect().await;

    // A no-op config (0) for table 0: this only exercises that OVS accepts
    // the message, not any particular table-config semantics.
    conn.send_raw(
        &openflow::protocol::codec::Encoder::table_mod(1, 0, 0, &[]).expect("encode table_mod"),
    )
    .await
    .expect("failed to send OFPT_TABLE_MOD");
    conn.send_barrier()
        .await
        .expect("barrier after table_mod failed");
}

#[tokio::test]
async fn port_mod_toggles_admin_state_and_emits_port_status() {
    if !run_ovs_tests_enabled() {
        return;
    }
    let bridge = start_bridge().await;
    let mut conn = bridge.connect().await;
    conn.enable_all_async_events()
        .await
        .expect("enable async events");

    let veth_port = port_desc(&mut conn)
        .await
        .into_iter()
        .find(|p| p.name == VETH_INNER)
        .expect("veth port missing from OFPMP_PORT_DESC");

    conn.send_raw(
        &openflow::protocol::codec::Encoder::port_mod(
            1,
            veth_port.port_no,
            veth_port.hw_addr,
            OFPPC_PORT_DOWN,
            OFPPC_PORT_DOWN,
            &[],
        )
        .expect("encode port_mod"),
    )
    .await
    .expect("failed to send OFPT_PORT_MOD");

    let status = tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            match conn.recv_message().await.expect("failed reading a message") {
                Message::PortStatus(status) => return status,
                Message::EchoRequest { xid, payload } => {
                    conn.send_raw(
                        &openflow::protocol::codec::Encoder::echo_reply(xid, &payload)
                            .expect("encode echo reply"),
                    )
                    .await
                    .expect("failed to answer echo request");
                }
                other => panic!("unexpected message while waiting for PORT_STATUS: {other:?}"),
            }
        }
    })
    .await
    .expect("timed out waiting for a PORT_STATUS after port_mod");

    assert_eq!(status.desc.port_no, veth_port.port_no);
    assert_ne!(
        status.desc.config & OFPPC_PORT_DOWN,
        0,
        "expected the port to be reported admin-down: {status:?}"
    );
}

#[tokio::test]
async fn flow_mod_error_reports_bad_table_id() {
    if !run_ovs_tests_enabled() {
        return;
    }
    let bridge = start_bridge().await;
    let mut conn = bridge.connect().await;

    // OVS really does have 254 tables, so a merely-large id is valid.
    // OFPTT_ALL is a delete-only wildcard and is never a legal target for
    // OFPFC_ADD, so that is the portable way to provoke BAD_TABLE_ID.
    let bad = Rule::add(0, OFPTT_ALL, 1, Match::any(), Vec::new());
    let err = conn
        .add_flow(bad)
        .await
        .expect_err("expected a rejection for an invalid table id");
    match err {
        ClientError::Remote {
            error_type, code, ..
        } => {
            assert_eq!(error_type, OFPET_FLOW_MOD_FAILED);
            assert_eq!(code, OFPFMFC_BAD_TABLE_ID);
        }
        other => panic!("expected a remote OFPT_ERROR, got: {other}"),
    }
}

#[tokio::test]
async fn group_mod_add_then_delete_round_trips_through_group_desc_and_stats() {
    if !run_ovs_tests_enabled() {
        return;
    }
    let bridge = start_bridge().await;
    let mut conn = bridge.connect().await;

    assert!(group_desc(&mut conn).await.is_empty());

    let group_id = 1;
    let add = GroupMod::add(
        1,
        OFPGT_ALL,
        group_id,
        vec![Bucket {
            bucket_id: 0,
            actions: vec![Action::Output {
                port: OFPP_CONTROLLER,
                max_len: OFPCML_NO_BUFFER,
            }],
            properties: Vec::new(),
        }],
    );
    conn.send_raw(&add.encode().expect("encode group-mod add"))
        .await
        .expect("failed to send OFPT_GROUP_MOD add");
    conn.send_barrier()
        .await
        .expect("barrier after group-mod add failed");

    let desc = group_desc(&mut conn).await;
    assert_eq!(desc.len(), 1, "expected exactly one group: {desc:?}");
    assert_eq!(desc[0].group_id, group_id);

    let stats = group_stats(&mut conn).await;
    assert!(
        stats.iter().any(|s| s.group_id == group_id),
        "expected stats for group {group_id}: {stats:?}"
    );

    let delete = GroupMod::delete(2, group_id);
    conn.send_raw(&delete.encode().expect("encode group-mod delete"))
        .await
        .expect("failed to send OFPT_GROUP_MOD delete");
    conn.send_barrier()
        .await
        .expect("barrier after group-mod delete failed");

    assert!(group_desc(&mut conn).await.is_empty());
}

#[tokio::test]
async fn meter_mod_add_then_delete_round_trips_through_meter_desc_and_stats() {
    if !run_ovs_tests_enabled() {
        return;
    }
    let bridge = start_bridge().await;
    let mut conn = bridge.connect().await;

    assert!(meter_desc(&mut conn).await.is_empty());

    let meter_id = 1;
    let add = MeterMod {
        xid: 1,
        command: OFPMC_ADD,
        // A meter must declare its rate unit; OVS answers OFPMMFC_BAD_FLAGS
        // for flags == 0.
        flags: OFPMF_KBPS,
        meter_id,
        bands: vec![MeterBand::Drop {
            rate: 1000,
            burst_size: 0,
        }],
    };
    conn.send_raw(&add.encode().expect("encode meter-mod add"))
        .await
        .expect("failed to send OFPT_METER_MOD add");
    conn.send_barrier()
        .await
        .expect("barrier after meter-mod add failed");

    let desc = meter_desc(&mut conn).await;
    assert_eq!(desc.len(), 1, "expected exactly one meter: {desc:?}");
    assert_eq!(desc[0].meter_id, meter_id);

    let stats = meter_stats(&mut conn).await;
    assert!(
        stats.iter().any(|s| s.meter_id == meter_id),
        "expected stats for meter {meter_id}: {stats:?}"
    );

    let delete = MeterMod {
        xid: 2,
        command: OFPMC_DELETE,
        flags: OFPMF_KBPS,
        meter_id,
        bands: Vec::new(),
    };
    conn.send_raw(&delete.encode().expect("encode meter-mod delete"))
        .await
        .expect("failed to send OFPT_METER_MOD delete");
    conn.send_barrier()
        .await
        .expect("barrier after meter-mod delete failed");

    assert!(meter_desc(&mut conn).await.is_empty());
}

#[tokio::test]
async fn flow_removed_event_fires_on_hard_timeout_with_send_flow_rem_flag() {
    if !run_ovs_tests_enabled() {
        return;
    }
    let bridge = start_bridge().await;
    let mut conn = bridge.connect().await;

    // OVS drops FLOW_REMOVED until the connection asks for it.
    conn.enable_all_async_events()
        .await
        .expect("enable async events");

    // The spec only says a controller-initiated delete *should* generate
    // this event (7.3.4.2), and OVS does not; a timeout expiry *must*.
    let mut rule = Rule::add(0, 0, 1234, Match::any(), Vec::new());
    rule.flags = OFPFF_SEND_FLOW_REM;
    rule.hard_timeout = 1;
    conn.add_flow(rule).await.expect("add_flow failed");

    let removed = tokio::time::timeout(Duration::from_secs(15), async {
        loop {
            match conn.recv_message().await.expect("failed reading a message") {
                Message::FlowRemoved(removed) => return removed,
                Message::EchoRequest { xid, payload } => {
                    conn.send_raw(
                        &openflow::protocol::codec::Encoder::echo_reply(xid, &payload)
                            .expect("encode echo reply"),
                    )
                    .await
                    .expect("failed to answer echo request");
                }
                other => panic!("unexpected message while waiting for FLOW_REMOVED: {other:?}"),
            }
        }
    })
    .await
    .expect("timed out waiting for a FLOW_REMOVED after hard timeout");

    assert_eq!(removed.priority, 1234);
    assert_eq!(removed.reason, OFPRR_HARD_TIMEOUT);
    assert_eq!(removed.hard_timeout, 1);
    // 1.5 carries the counters as an OXS list rather than inline fields.
    assert!(
        removed
            .stats
            .iter()
            .any(|s| matches!(s, OxsTlv::PacketCount(_))),
        "expected a packet count in the OXS stats: {:?}",
        removed.stats
    );
}

#[tokio::test]
async fn bundle_open_add_commit_installs_a_flow() {
    if !run_ovs_tests_enabled() {
        return;
    }
    let bridge = start_bridge().await;
    let mut conn = bridge.connect().await;

    assert!(flow_desc(&mut conn).await.is_empty());

    let bundle_id = 1;
    let open = BundleMessage {
        xid: 1,
        bundle_id,
        ctrl_type: openflow::protocol::constants::OFPBCT_OPEN_REQUEST,
        flags: openflow::protocol::constants::OFPBF_ATOMIC
            | openflow::protocol::constants::OFPBF_ORDERED,
        properties: Vec::new(),
    };
    conn.send_raw(&open.encode().expect("encode bundle open"))
        .await
        .expect("failed to send OFPT_BUNDLE_CONTROL open");

    match conn
        .recv_message()
        .await
        .expect("failed reading bundle open reply")
    {
        Message::BundleControl(reply) => {
            assert_eq!(
                reply.ctrl_type,
                openflow::protocol::constants::OFPBCT_OPEN_REPLY
            );
        }
        other => panic!("unexpected reply to bundle open: {other:?}"),
    }

    // The nested message's xid must equal the bundle-add's own xid
    // (spec 7.3.9.6); OVS enforces it with OFPBFC_MSG_BAD_XID.
    let flow = Rule::add(
        2,
        0,
        1500,
        Match::any(),
        vec![Instruction::ApplyActions(vec![Action::Output {
            port: OFPP_CONTROLLER,
            max_len: OFPCML_NO_BUFFER,
        }])],
    );
    let add_message = BundleAddMessage {
        xid: 2,
        bundle_id,
        flags: openflow::protocol::constants::OFPBF_ATOMIC
            | openflow::protocol::constants::OFPBF_ORDERED,
        message: flow.encode().expect("encode flow"),
        properties: Vec::new(),
    };
    conn.send_raw(&add_message.encode().expect("encode bundle add-message"))
        .await
        .expect("failed to send OFPT_BUNDLE_ADD_MESSAGE");

    let commit = BundleMessage {
        xid: 3,
        bundle_id,
        ctrl_type: openflow::protocol::constants::OFPBCT_COMMIT_REQUEST,
        flags: openflow::protocol::constants::OFPBF_ATOMIC
            | openflow::protocol::constants::OFPBF_ORDERED,
        properties: Vec::new(),
    };
    conn.send_raw(&commit.encode().expect("encode bundle commit"))
        .await
        .expect("failed to send OFPT_BUNDLE_CONTROL commit");

    match conn
        .recv_message()
        .await
        .expect("failed reading bundle commit reply")
    {
        Message::BundleControl(reply) => {
            assert_eq!(
                reply.ctrl_type,
                openflow::protocol::constants::OFPBCT_COMMIT_REPLY
            );
        }
        other => panic!("unexpected reply to bundle commit: {other:?}"),
    }

    let entries = flow_desc(&mut conn).await;
    assert_eq!(
        entries.len(),
        1,
        "expected the bundled flow to be installed: {entries:?}"
    );
    assert_eq!(entries[0].priority, 1500);

    conn.delete_flows(None)
        .await
        .expect("cleanup delete_flows failed");
}

impl OvsBridge {
    async fn exec_arping(&self) -> Result<(), testcontainers::TestcontainersError> {
        use testcontainers::core::ExecCommand;

        self._container
            .exec(ExecCommand::new([
                "arping",
                "-c",
                "1",
                "-I",
                VETH_OUTER,
                "10.211.0.2",
            ]))
            .await?;
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Coverage of the remaining OpenFlow operations this crate can perform against
// a switch. Each test below exercises one operation that the suite above does
// not, so that every message type and multipart subtype the crate can send is
// tried against real OVS at least once.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn echo_request_round_trips_with_its_payload() {
    if !run_ovs_tests_enabled() {
        return;
    }
    let bridge = start_bridge().await;
    let mut conn = bridge.connect().await;

    conn.send_raw(&Encoder::echo_request(4242, b"ping-payload").expect("encode echo request"))
        .await
        .expect("send echo request");

    let payload = tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            match conn.recv_message().await.expect("read") {
                Message::EchoReply { xid, payload } => return (xid, payload),
                Message::EchoRequest { xid, payload } => {
                    conn.send_raw(&Encoder::echo_reply(xid, &payload).expect("encode echo reply"))
                        .await
                        .expect("answer echo");
                }
                other => panic!("unexpected while waiting for echo reply: {other:?}"),
            }
        }
    })
    .await
    .expect("timed out waiting for an echo reply");

    assert_eq!(payload.0, 4242, "echo reply must echo the xid");
    assert_eq!(payload.1, b"ping-payload", "echo reply must echo the body");
}

#[tokio::test]
async fn barrier_request_gets_a_reply_with_the_same_xid() {
    if !run_ovs_tests_enabled() {
        return;
    }
    let bridge = start_bridge().await;
    let mut conn = bridge.connect().await;

    // send_barrier() matches the xid internally and errors if it never
    // arrives, so a clean return is the assertion.
    conn.send_barrier().await.expect("barrier round trip");
    conn.send_barrier()
        .await
        .expect("second barrier round trip");
}

#[tokio::test]
async fn role_request_reports_and_changes_the_controller_role() {
    if !run_ovs_tests_enabled() {
        return;
    }
    let bridge = start_bridge().await;
    let mut conn = bridge.connect().await;

    // OFPCR_ROLE_NOCHANGE queries the current role without changing it.
    conn.send_raw(&Encoder::role_request(1, OFPCR_ROLE_NOCHANGE, 0, 0).expect("encode"))
        .await
        .expect("send role request");
    let current = tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            match conn.recv_message().await.expect("read") {
                Message::RoleReply(reply) => return reply,
                Message::EchoRequest { xid, payload } => {
                    conn.send_raw(&Encoder::echo_reply(xid, &payload).expect("encode echo reply"))
                        .await
                        .expect("answer echo");
                }
                other => panic!("unexpected while waiting for role reply: {other:?}"),
            }
        }
    })
    .await
    .expect("timed out waiting for a role reply");
    assert_eq!(
        current.role, OFPCR_ROLE_EQUAL,
        "a fresh connection starts in the equal role"
    );

    // Becoming master requires a generation id that does not go backwards.
    conn.send_raw(&Encoder::role_request(2, OFPCR_ROLE_MASTER, 0, 1).expect("encode"))
        .await
        .expect("send role request");
    let promoted = tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            match conn.recv_message().await.expect("read") {
                Message::RoleReply(reply) => return reply,
                Message::EchoRequest { xid, payload } => {
                    conn.send_raw(&Encoder::echo_reply(xid, &payload).expect("encode echo reply"))
                        .await
                        .expect("answer echo");
                }
                other => panic!("unexpected while waiting for role reply: {other:?}"),
            }
        }
    })
    .await
    .expect("timed out waiting for the master role reply");
    assert_eq!(promoted.role, OFPCR_ROLE_MASTER);
}

#[tokio::test]
async fn set_async_is_readable_back_through_get_async() {
    if !run_ovs_tests_enabled() {
        return;
    }
    let bridge = start_bridge().await;
    let mut conn = bridge.connect().await;

    conn.enable_all_async_events()
        .await
        .expect("set async config");
    let props = conn.get_async().await.expect("get async config");

    // enable_all_async_events sets the six masks this crate models; the
    // switch must report them back.
    let mask_for = |kind: u16| {
        props.iter().find_map(|p| match p {
            Property::ReasonMask { kind: k, mask } if *k == kind => Some(*mask),
            _ => None,
        })
    };
    assert_eq!(mask_for(OFPACPT_FLOW_REMOVED_MASTER), Some(0x3f));
    assert_eq!(mask_for(OFPACPT_PORT_STATUS_MASTER), Some(0x7));
    assert_eq!(mask_for(OFPACPT_PACKET_IN_MASTER), Some(0x3f));

    // An undefined reason bit must be refused rather than silently
    // truncated.
    let bogus = vec![Property::ReasonMask {
        kind: OFPACPT_PACKET_IN_MASTER,
        mask: 0xffff_ffff,
    }];
    assert!(
        conn.set_async(&bogus).await.is_err(),
        "OVS must reject an out-of-range reason mask"
    );
}

#[tokio::test]
async fn flow_stats_multipart_is_rejected_as_unsupported_by_ovs() {
    if !run_ovs_tests_enabled() {
        return;
    }
    let bridge = start_bridge().await;
    let mut conn = bridge.connect().await;

    conn.add_flow(Rule::add(0, 0, 321, Match::any(), Vec::new()))
        .await
        .expect("add_flow");

    // OFPMP_FLOW_STATS is the 1.5 counters-only sibling of
    // OFPMP_FLOW_DESC. OVS 3.x implements FLOW_DESC but not FLOW_STATS,
    // and answers OFPBRC_BAD_MULTIPART. Asserting the rejection still
    // exercises the request encoder (its body is a full
    // ofp_flow_stats_request) and the error path; if a future OVS gains
    // support, this test tells us by failing.
    let err = conn
        .multipart_request(
            OFPMP_FLOW_STATS,
            &MultipartRequestBody::FlowStats(FlowStatsRequest {
                table_id: OFPTT_ALL,
                out_port: OFPP_ANY,
                out_group: OFPG_ANY,
                cookie: 0,
                cookie_mask: 0,
                of_match: Vec::new(),
            }),
        )
        .await
        .expect_err("expected OVS to reject OFPMP_FLOW_STATS");
    match err {
        ClientError::Remote {
            error_type, code, ..
        } => {
            assert_eq!(error_type, OFPET_BAD_REQUEST);
            assert_eq!(code, OFPBRC_BAD_MULTIPART);
        }
        other => panic!("expected a remote OFPT_ERROR, got: {other}"),
    }

    // The same counters are reachable through OFPMP_FLOW_DESC, which OVS
    // does implement -- so the OXS stats path is still covered live.
    let entries = flow_desc(&mut conn).await;
    let entry = entries
        .iter()
        .find(|e| e.priority == 321)
        .expect("the installed flow should appear in flow desc");
    assert!(
        entry
            .stats
            .iter()
            .any(|s| matches!(s, OxsTlv::PacketCount(_))),
        "expected OXS counters: {:?}",
        entry.stats
    );
}

#[tokio::test]
async fn queue_desc_and_queue_stats_multiparts_succeed() {
    if !run_ovs_tests_enabled() {
        return;
    }
    let bridge = start_bridge().await;
    let mut conn = bridge.connect().await;

    let reply = conn
        .multipart_request(
            OFPMP_QUEUE_DESC,
            &MultipartRequestBody::Queue(QueueMultipartRequest {
                port_no: OFPP_ANY,
                queue_id: OFPQ_ALL,
            }),
        )
        .await
        .expect("OFPMP_QUEUE_DESC request failed");
    assert!(
        matches!(reply, MultipartReplyBody::QueueDesc(_)),
        "unexpected OFPMP_QUEUE_DESC reply: {reply:?}"
    );

    let reply = conn
        .multipart_request(
            OFPMP_QUEUE_STATS,
            &MultipartRequestBody::Queue(QueueMultipartRequest {
                port_no: OFPP_ANY,
                queue_id: OFPQ_ALL,
            }),
        )
        .await
        .expect("OFPMP_QUEUE_STATS request failed");
    assert!(
        matches!(reply, MultipartReplyBody::QueueStats(_)),
        "unexpected OFPMP_QUEUE_STATS reply: {reply:?}"
    );
}

#[tokio::test]
async fn experimenter_message_and_multipart_are_rejected_cleanly() {
    if !run_ovs_tests_enabled() {
        return;
    }
    let bridge = start_bridge().await;
    let mut conn = bridge.connect().await;

    // An unknown experimenter id must draw OFPBRC_BAD_EXPERIMENTER rather
    // than dropping the connection.
    conn.send_raw(&Encoder::experimenter(1, 0x00ff_ffff, 1, &[1, 2, 3, 4]).expect("encode"))
        .await
        .expect("send experimenter");
    let err = tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            match conn.recv_message().await.expect("read") {
                Message::Error(err) => return err,
                Message::EchoRequest { xid, payload } => {
                    conn.send_raw(&Encoder::echo_reply(xid, &payload).expect("encode echo reply"))
                        .await
                        .expect("answer echo");
                }
                other => panic!("unexpected while waiting for an error: {other:?}"),
            }
        }
    })
    .await
    .expect("timed out waiting for an experimenter rejection");
    assert_eq!(err.error_type, OFPET_BAD_REQUEST);

    // The connection must still work afterwards.
    conn.send_barrier()
        .await
        .expect("connection unusable after an experimenter rejection");
}

#[tokio::test]
async fn flow_mod_modify_and_strict_delete_commands_work() {
    if !run_ovs_tests_enabled() {
        return;
    }
    let bridge = start_bridge().await;
    let mut conn = bridge.connect().await;

    let match_v4 = || Match::new(vec![oxm::eth_type(ETH_TYPE_IPV4)]);

    // ADD, then MODIFY the instruction set of the same flow.
    let mut add = Rule::add(0, 0, 700, match_v4(), Vec::new());
    add.cookie = 0x1111;
    conn.add_flow(add).await.expect("add");

    let mut modify = Rule::add(
        0,
        0,
        700,
        match_v4(),
        vec![Instruction::ApplyActions(vec![Action::Output {
            port: OFPP_CONTROLLER,
            max_len: OFPCML_NO_BUFFER,
        }])],
    );
    modify.command = OFPFC_MODIFY_STRICT;
    modify.cookie = 0x2222;
    conn.send_flow_mod(modify).await.expect("modify");
    conn.send_barrier().await.expect("barrier after modify");

    let entries = flow_desc(&mut conn).await;
    let entry = entries
        .iter()
        .find(|e| e.priority == 700)
        .expect("modified flow should still exist");
    assert!(
        !entry.instructions.is_empty(),
        "OFPFC_MODIFY_STRICT should have installed the new instructions"
    );

    // DELETE_STRICT removes exactly that flow and nothing else.
    let mut other = Rule::add(0, 0, 701, Match::any(), Vec::new());
    other.cookie = 0x3333;
    conn.add_flow(other).await.expect("add second");

    let mut del = Rule::delete(0, 0, match_v4());
    del.command = OFPFC_DELETE_STRICT;
    del.priority = 700;
    del.cookie = 0;
    del.cookie_mask = 0;
    conn.send_flow_mod(del).await.expect("delete strict");
    conn.send_barrier().await.expect("barrier after delete");

    let remaining = flow_desc(&mut conn).await;
    assert!(
        remaining.iter().all(|e| e.priority != 700),
        "OFPFC_DELETE_STRICT should have removed priority 700"
    );
    assert!(
        remaining.iter().any(|e| e.priority == 701),
        "OFPFC_DELETE_STRICT must not have touched priority 701: {remaining:?}"
    );
}

#[tokio::test]
async fn group_mod_modify_and_bucket_commands_work() {
    if !run_ovs_tests_enabled() {
        return;
    }
    let bridge = start_bridge().await;
    let mut conn = bridge.connect().await;

    let bucket = |bucket_id: u32, port: u32| Bucket {
        bucket_id,
        actions: vec![Action::Output {
            port,
            max_len: OFPCML_NO_BUFFER,
        }],
        properties: Vec::new(),
    };

    conn.send_raw(
        &GroupMod::add(1, OFPGT_ALL, 5, vec![bucket(0, OFPP_CONTROLLER)])
            .encode()
            .expect("encode add"),
    )
    .await
    .expect("send group add");
    conn.send_barrier().await.expect("barrier after group add");

    // MODIFY replaces the whole bucket list.
    let modify = GroupMod {
        xid: 2,
        command: OFPGC_MODIFY,
        group_type: OFPGT_ALL,
        group_id: 5,
        command_bucket_id: OFPG_BUCKET_ALL,
        buckets: vec![bucket(0, OFPP_CONTROLLER), bucket(1, OFPP_CONTROLLER)],
        properties: Vec::new(),
    };
    conn.send_raw(&modify.encode().expect("encode modify"))
        .await
        .expect("send group modify");
    conn.send_barrier()
        .await
        .expect("barrier after group modify");

    let desc = group_desc(&mut conn).await;
    let group = desc
        .iter()
        .find(|g| g.group_id == 5)
        .expect("group 5 should exist");
    assert_eq!(
        group.buckets.len(),
        2,
        "OFPGC_MODIFY should have installed two buckets: {group:?}"
    );

    conn.send_raw(&GroupMod::delete(3, 5).encode().expect("encode delete"))
        .await
        .expect("send group delete");
    conn.send_barrier()
        .await
        .expect("barrier after group delete");
    assert!(group_desc(&mut conn).await.is_empty());
}

#[tokio::test]
async fn meter_mod_modify_changes_an_existing_meter() {
    if !run_ovs_tests_enabled() {
        return;
    }
    let bridge = start_bridge().await;
    let mut conn = bridge.connect().await;

    let band = |rate: u32| MeterBand::Drop {
        rate,
        burst_size: 0,
    };

    for (command, rate) in [(OFPMC_ADD, 1000u32), (OFPMC_MODIFY, 2000)] {
        let meter = MeterMod {
            xid: 1,
            command,
            flags: OFPMF_KBPS,
            meter_id: 9,
            bands: vec![band(rate)],
        };
        conn.send_raw(&meter.encode().expect("encode meter-mod"))
            .await
            .expect("send meter-mod");
        conn.send_barrier()
            .await
            .unwrap_or_else(|e| panic!("barrier after meter command {command}: {e}"));
    }

    let desc = meter_desc(&mut conn).await;
    let meter = desc
        .iter()
        .find(|m| m.meter_id == 9)
        .expect("meter 9 should exist");
    assert!(
        matches!(
            meter.bands.first(),
            Some(MeterBand::Drop { rate: 2000, .. })
        ),
        "OFPMC_MODIFY should have changed the band rate: {meter:?}"
    );

    let delete = MeterMod {
        xid: 2,
        command: OFPMC_DELETE,
        flags: OFPMF_KBPS,
        meter_id: 9,
        bands: Vec::new(),
    };
    conn.send_raw(&delete.encode().expect("encode delete"))
        .await
        .expect("send meter delete");
    conn.send_barrier()
        .await
        .expect("barrier after meter delete");
}

#[tokio::test]
async fn bundle_discard_abandons_staged_messages() {
    if !run_ovs_tests_enabled() {
        return;
    }
    let bridge = start_bridge().await;
    let mut conn = bridge.connect().await;

    assert!(flow_desc(&mut conn).await.is_empty());

    let bundle_id = 77;
    let ctrl = |xid: u32, ctrl_type: u16| BundleMessage {
        xid,
        bundle_id,
        ctrl_type,
        flags: OFPBF_ORDERED,
        properties: Vec::new(),
    };

    conn.send_raw(&ctrl(1, OFPBCT_OPEN_REQUEST).encode().expect("encode open"))
        .await
        .expect("send open");
    match conn.recv_message().await.expect("open reply") {
        Message::BundleControl(reply) => assert_eq!(reply.ctrl_type, OFPBCT_OPEN_REPLY),
        other => panic!("unexpected reply to bundle open: {other:?}"),
    }

    let flow = Rule::add(2, 0, 999, Match::any(), Vec::new());
    let add = BundleAddMessage {
        xid: 2,
        bundle_id,
        flags: OFPBF_ORDERED,
        message: flow.encode().expect("encode flow"),
        properties: Vec::new(),
    };
    conn.send_raw(&add.encode().expect("encode add"))
        .await
        .expect("send bundle add");

    // DISCARD must throw the staged flow away rather than applying it.
    conn.send_raw(
        &ctrl(3, OFPBCT_DISCARD_REQUEST)
            .encode()
            .expect("encode discard"),
    )
    .await
    .expect("send discard");
    match conn.recv_message().await.expect("discard reply") {
        Message::BundleControl(reply) => assert_eq!(reply.ctrl_type, OFPBCT_DISCARD_REPLY),
        other => panic!("unexpected reply to bundle discard: {other:?}"),
    }

    conn.send_barrier().await.expect("barrier after discard");
    assert!(
        flow_desc(&mut conn).await.is_empty(),
        "a discarded bundle must not install its staged flow"
    );
}

/// The Nicira connection-tracking extension is the one part of this
/// crate whose wire constants were reconstructed from OVS sources rather
/// than a specification, and its own module doc says so. This is the
/// test that turns that guess into a verified fact: OVS either accepts
/// the bytes or answers with an `OFPT_ERROR` naming what it disliked.
#[tokio::test]
async fn nicira_conntrack_actions_and_match_fields_are_accepted_by_ovs() {
    if !run_ovs_tests_enabled() {
        return;
    }
    let bridge = start_bridge().await;
    let mut conn = bridge.connect().await;

    // ct(commit, zone=1, nat(src=203.0.113.5)) applied to IPv4 traffic.
    let nat = nicira::nat_src("203.0.113.5".parse().expect("addr"));
    let ct_action = nicira::ct(true, 1, None, std::slice::from_ref(&nat)).expect("build ct action");
    let commit_rule = Rule::add(
        0,
        0,
        900,
        Match::new(vec![oxm::eth_type(ETH_TYPE_IPV4)]),
        vec![Instruction::ApplyActions(vec![ct_action])],
    );
    conn.add_flow(commit_rule)
        .await
        .expect("OVS rejected the NXAST_CT action");

    // A ct_state match, which rides under the Nicira OXM class.
    let tracked = NX_CS_TRK | NX_CS_RPL;
    let ct_rule = Rule::add(
        0,
        0,
        901,
        Match::new(vec![
            oxm::eth_type(ETH_TYPE_IPV4),
            oxm::ct_state_masked(tracked, tracked),
            oxm::ct_zone(1),
        ]),
        vec![Instruction::ApplyActions(vec![Action::Output {
            port: OFPP_CONTROLLER,
            max_len: OFPCML_NO_BUFFER,
        }])],
    );
    conn.add_flow(ct_rule)
        .await
        .expect("OVS rejected the ct_state/ct_zone match fields");

    // A ct() that recirculates instead of continuing the action list.
    let recirc = nicira::ct(false, 2, Some(1), &[]).expect("build ct recirc action");
    let recirc_rule = Rule::add(
        0,
        0,
        902,
        Match::new(vec![oxm::eth_type(ETH_TYPE_IPV4)]),
        vec![Instruction::ApplyActions(vec![recirc])],
    );
    conn.add_flow(recirc_rule)
        .await
        .expect("OVS rejected the recirculating NXAST_CT action");

    // All three must be readable back, which proves OVS stored them.
    let entries = flow_desc(&mut conn).await;
    for priority in [900u16, 901, 902] {
        assert!(
            entries.iter().any(|e| e.priority == priority),
            "flow with priority {priority} missing after install: {entries:?}"
        );
    }
}

#[tokio::test]
async fn remaining_multipart_subtypes_are_exercised() {
    if !run_ovs_tests_enabled() {
        return;
    }
    let bridge = start_bridge().await;
    let mut conn = bridge.connect().await;

    // OFPMP_CONTROLLER_STATUS: OVS answers with the status of every
    // controller connection it knows about.
    match conn
        .multipart_request(OFPMP_CONTROLLER_STATUS, &MultipartRequestBody::Empty)
        .await
    {
        Ok(MultipartReplyBody::ControllerStatus(_)) => {}
        Ok(other) => panic!("unexpected OFPMP_CONTROLLER_STATUS reply: {other:?}"),
        // Older OVS builds may not implement it; a clean rejection is
        // still a pass, an unparseable reply is not.
        Err(ClientError::Remote { error_type, .. }) => {
            assert_eq!(error_type, OFPET_BAD_REQUEST);
        }
        Err(other) => panic!("OFPMP_CONTROLLER_STATUS failed unexpectedly: {other}"),
    }

    // OFPMP_FLOW_MONITOR: a monitor request needs a body, and OVS
    // either installs the monitor or rejects the subtype outright.
    match conn
        .multipart_request(
            OFPMP_FLOW_MONITOR,
            &MultipartRequestBody::FlowMonitor(FlowMonitorRequest {
                monitor_id: 1,
                out_port: OFPP_ANY,
                out_group: OFPG_ANY,
                flags: OFPFMF_ADD | OFPFMF_REMOVED,
                table_id: OFPTT_ALL,
                command: OFPFMC_ADD,
                of_match: Vec::new(),
            }),
        )
        .await
    {
        Ok(MultipartReplyBody::FlowMonitor(_)) => {}
        Ok(other) => panic!("unexpected OFPMP_FLOW_MONITOR reply: {other:?}"),
        Err(ClientError::Remote { error_type, .. }) => {
            assert!(
                error_type == OFPET_BAD_REQUEST || error_type == OFPET_FLOW_MONITOR_FAILED,
                "unexpected error type {error_type} for OFPMP_FLOW_MONITOR"
            );
        }
        Err(other) => panic!("OFPMP_FLOW_MONITOR failed unexpectedly: {other}"),
    }

    // OFPMP_EXPERIMENTER with an unknown vendor id must be refused
    // without dropping the connection.
    let mut body = Vec::new();
    body.extend_from_slice(&0x00ff_ffffu32.to_be_bytes()); // experimenter
    body.extend_from_slice(&1u32.to_be_bytes()); // exp_type
    match conn
        .multipart_request(
            OFPMP_EXPERIMENTER,
            &MultipartRequestBody::Experimenter(body),
        )
        .await
    {
        Ok(other) => panic!("unexpected OFPMP_EXPERIMENTER reply: {other:?}"),
        Err(ClientError::Remote { .. }) => {}
        Err(other) => panic!("OFPMP_EXPERIMENTER failed unexpectedly: {other}"),
    }

    conn.send_barrier()
        .await
        .expect("connection unusable after the multipart sweep");
}

#[tokio::test]
async fn group_insert_and_remove_bucket_commands_work() {
    if !run_ovs_tests_enabled() {
        return;
    }
    let bridge = start_bridge().await;
    let mut conn = bridge.connect().await;

    let bucket = |bucket_id: u32| Bucket {
        bucket_id,
        actions: vec![Action::Output {
            port: OFPP_CONTROLLER,
            max_len: OFPCML_NO_BUFFER,
        }],
        properties: Vec::new(),
    };

    conn.send_raw(
        &GroupMod::add(1, OFPGT_ALL, 8, vec![bucket(0)])
            .encode()
            .expect("encode add"),
    )
    .await
    .expect("send group add");
    conn.send_barrier().await.expect("barrier after add");

    // INSERT_BUCKET and REMOVE_BUCKET are the two commands that actually
    // use command_bucket_id.
    let insert = GroupMod {
        xid: 2,
        command: OFPGC_INSERT_BUCKET,
        group_type: OFPGT_ALL,
        group_id: 8,
        command_bucket_id: OFPG_BUCKET_LAST,
        buckets: vec![bucket(1)],
        properties: Vec::new(),
    };
    conn.send_raw(&insert.encode().expect("encode insert"))
        .await
        .expect("send insert-bucket");
    conn.send_barrier()
        .await
        .expect("barrier after insert-bucket");
    let group = group_desc(&mut conn)
        .await
        .into_iter()
        .find(|g| g.group_id == 8)
        .expect("group 8");
    assert_eq!(
        group.buckets.len(),
        2,
        "OFPGC_INSERT_BUCKET should have added a bucket: {group:?}"
    );

    let remove = GroupMod {
        xid: 3,
        command: OFPGC_REMOVE_BUCKET,
        group_type: OFPGT_ALL,
        group_id: 8,
        command_bucket_id: OFPG_BUCKET_LAST,
        buckets: Vec::new(),
        properties: Vec::new(),
    };
    conn.send_raw(&remove.encode().expect("encode remove"))
        .await
        .expect("send remove-bucket");
    conn.send_barrier()
        .await
        .expect("barrier after remove-bucket");
    let group = group_desc(&mut conn)
        .await
        .into_iter()
        .find(|g| g.group_id == 8)
        .expect("group 8");
    assert_eq!(
        group.buckets.len(),
        1,
        "OFPGC_REMOVE_BUCKET should have removed a bucket: {group:?}"
    );

    conn.send_raw(&GroupMod::delete(4, 8).encode().expect("encode delete"))
        .await
        .expect("send delete");
    conn.send_barrier().await.expect("barrier after delete");
}

#[tokio::test]
async fn bundle_close_before_commit_is_accepted() {
    if !run_ovs_tests_enabled() {
        return;
    }
    let bridge = start_bridge().await;
    let mut conn = bridge.connect().await;

    let bundle_id = 88;
    let ctrl = |xid: u32, ctrl_type: u16| BundleMessage {
        xid,
        bundle_id,
        ctrl_type,
        flags: OFPBF_ORDERED,
        properties: Vec::new(),
    };
    async fn expect_reply(conn: &mut Connection<tokio::net::UnixStream>, want: u16) {
        match conn.recv_message().await.expect("bundle reply") {
            Message::BundleControl(reply) => assert_eq!(reply.ctrl_type, want),
            other => panic!("unexpected bundle reply: {other:?}"),
        }
    }

    conn.send_raw(&ctrl(1, OFPBCT_OPEN_REQUEST).encode().expect("open"))
        .await
        .expect("send open");
    expect_reply(&mut conn, OFPBCT_OPEN_REPLY).await;

    let flow = Rule::add(2, 0, 555, Match::any(), Vec::new());
    conn.send_raw(
        &BundleAddMessage {
            xid: 2,
            bundle_id,
            flags: OFPBF_ORDERED,
            message: flow.encode().expect("encode flow"),
            properties: Vec::new(),
        }
        .encode()
        .expect("encode add"),
    )
    .await
    .expect("send add");

    // CLOSE seals the bundle; COMMIT then applies it.
    conn.send_raw(&ctrl(3, OFPBCT_CLOSE_REQUEST).encode().expect("close"))
        .await
        .expect("send close");
    expect_reply(&mut conn, OFPBCT_CLOSE_REPLY).await;

    conn.send_raw(&ctrl(4, OFPBCT_COMMIT_REQUEST).encode().expect("commit"))
        .await
        .expect("send commit");
    expect_reply(&mut conn, OFPBCT_COMMIT_REPLY).await;

    conn.send_barrier().await.expect("barrier after commit");
    assert!(
        flow_desc(&mut conn).await.iter().any(|e| e.priority == 555),
        "a closed-then-committed bundle must install its flow"
    );
}

#[tokio::test]
async fn slave_role_restricts_controller_to_read_only() {
    if !run_ovs_tests_enabled() {
        return;
    }
    let bridge = start_bridge().await;
    let mut conn = bridge.connect().await;

    conn.send_raw(&Encoder::role_request(1, OFPCR_ROLE_SLAVE, 0, 1).expect("encode"))
        .await
        .expect("send role request");
    let reply = tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            match conn.recv_message().await.expect("read") {
                Message::RoleReply(reply) => return reply,
                Message::EchoRequest { xid, payload } => {
                    conn.send_raw(&Encoder::echo_reply(xid, &payload).expect("encode echo reply"))
                        .await
                        .expect("answer echo");
                }
                other => panic!("unexpected while waiting for role reply: {other:?}"),
            }
        }
    })
    .await
    .expect("timed out waiting for the slave role reply");
    assert_eq!(reply.role, OFPCR_ROLE_SLAVE);

    // A slave may not modify the flow table: the spec requires
    // OFPET_BAD_REQUEST / OFPBRC_IS_SLAVE.
    let err = conn
        .add_flow(Rule::add(0, 0, 1, Match::any(), Vec::new()))
        .await
        .expect_err("a slave controller must not be able to add flows");
    match err {
        ClientError::Remote {
            error_type, code, ..
        } => {
            assert_eq!(error_type, OFPET_BAD_REQUEST);
            assert_eq!(code, OFPBRC_IS_SLAVE);
        }
        other => panic!("expected OFPBRC_IS_SLAVE, got: {other}"),
    }

    // Reads are still allowed in the slave role.
    assert!(port_desc(&mut conn).await.iter().any(|p| p.port_no != 0));
}

/// `OFPT_CONTROLLER_STATUS` is the one async push this crate models that
/// no single-controller test can trigger: the spec fires it when the set
/// of connected controllers changes. Enable it on one connection, then
/// connect (and drop) a second, and look for the push. Real hardware and
/// OVS builds vary in whether they implement the push side of this at
/// all, so a timeout is tolerated -- an unparseable push is not.
#[tokio::test]
async fn controller_status_push_fires_when_a_second_controller_connects() {
    if !run_ovs_tests_enabled() {
        return;
    }
    let bridge = start_bridge().await;
    let mut watcher = bridge.connect().await;
    let enabled = watcher
        .set_async(&[Property::ReasonMask {
            kind: OFPACPT_CONT_STATUS_MASTER,
            mask: 0x7f,
        }])
        .await;
    match enabled {
        Ok(()) => {}
        // This OVS build doesn't support the CONT_STATUS async event
        // property at all; nothing further to check.
        Err(ClientError::Remote {
            error_type: OFPET_ASYNC_CONFIG_FAILED,
            code: OFPACFC_UNSUPPORTED,
            ..
        }) => return,
        Err(other) => panic!("enable controller-status events: {other}"),
    }

    let second = bridge.connect().await;

    let push = tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            match watcher.recv_message().await.expect("read") {
                Message::ControllerStatus(status) => return status,
                Message::EchoRequest { xid, payload } => {
                    watcher
                        .send_raw(&Encoder::echo_reply(xid, &payload).expect("encode echo reply"))
                        .await
                        .expect("answer echo");
                }
                other => {
                    panic!("unexpected message while waiting for controller status: {other:?}")
                }
            }
        }
    })
    .await;

    drop(second);

    match push {
        Ok(status) => {
            assert!(matches!(
                status.reason,
                OFPCSR_CONTROLLER_ADDED | OFPCSR_ROLE | OFPCSR_SHORT_ID
            ));
        }
        Err(_) => {
            // This OVS build never pushes OFPT_CONTROLLER_STATUS; nothing
            // further to check.
        }
    }
}

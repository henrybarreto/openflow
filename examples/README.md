# Examples

Each file is a standalone `cargo run --example <name>` program. Run them from
the crate root. They all use `tracing` for output, so set `RUST_LOG` if you
want more (or less) detail, e.g. `RUST_LOG=debug cargo run --example 01_handshake`.

### Start here

| Example | What it shows |
| --- | --- |
| `01_handshake` | `Connection::connect_tcp` + the `OpenFlow` hello/features handshake. |
| `02_add_flow` | Building a `Match`/`Instruction`/`Action` and installing it with `add_flow`. |
| `03_table_miss` | Installing the standard table-miss-to-controller rule. |
| `25_error_handling` | **Read this early.** Catching `Error::Remote` and decoding a switch's `OFPT_ERROR` into a typed `ErrorType`. |

### Reading switch state

| Example | What it shows |
| --- | --- |
| `05_flow_stats` | `OFPMP_FLOW_DESC`: list installed flow entries. |
| `06_port_stats` | `OFPMP_PORT_STATS`: per-port counters. |
| `07_switch_description` | `OFPMP_DESC`: who the switch says it is. |
| `17_port_inventory` | `OFPMP_PORT_DESC`: every port's number, MAC, config and link state. |
| `18_table_inventory` | `OFPMP_TABLE_STATS`/`_DESC`/`_FEATURES`: counters, config, and what each table supports. |
| `21_queue_inspect` | `OFPMP_QUEUE_DESC`/`_STATS`: egress queues and their counters. |
| `22_aggregate_stats` | `OFPMP_AGGREGATE_STATS`, plus `multipart_request_with_timeout`. |
| `23_flow_monitor` | `OFPMP_FLOW_MONITOR`: subscribe to flow-table changes instead of polling. |
| `24_controller_status` | `OFPMP_CONTROLLER_STATUS`: who else is connected. |

### Writing flows

| Example | What it shows |
| --- | --- |
| `04_delete_flows` | Deleting all flows, or just flows tagged with a given cookie. |
| `08_batch_with_barrier` | Sending several flow-mods and syncing with one trailing barrier. |
| `13_packet_out` | Crafting a raw Ethernet frame and injecting it with `PacketOut`. |
| `14_bundle` | Installing two flow-mods atomically via a bundle (open/add/commit). |
| `31_flow_mod_commands` | `OFPFC_MODIFY`/`MODIFY_STRICT`/`DELETE_STRICT`, and what "strict" changes. |
| `34_bundle_discard` | Abandoning a staged bundle — the counterpart to `14`'s commit. |

### Groups, meters, ports and tables

| Example | What it shows |
| --- | --- |
| `12_group_mod` | Installing a `SELECT` group (ECMP-style load balancing). |
| `15_meter_mod` | A rate-limiting meter and a flow metered through it. |
| `19_group_inspect` | `OFPMP_GROUP_DESC`/`_STATS`/`_FEATURES`. |
| `20_meter_inspect` | `OFPMP_METER_DESC`/`_STATS`/`_FEATURES`. |
| `32_group_mod_commands` | `OFPGC_MODIFY` and the bucket-level insert/remove commands. |
| `33_port_and_table_mod` | `OFPT_PORT_MOD` (admin up/down + the `PORT_STATUS` it emits) and `OFPT_TABLE_MOD`. |

### Session control

| Example | What it shows |
| --- | --- |
| `11_unix_bridge_client` | Connecting to a local OVS bridge over its Unix management socket. |
| `16_async_events` | `enable_all_async_events` + a `recv_message` loop over packet-in, flow-removed and port-status. |
| `26_role_request` | Claiming master/slave with `send_raw`, `generation_id`, and answering echoes while you wait. |
| `27_switch_config` | `OFPT_SET_CONFIG`/`GET_CONFIG`, and a narrow hand-built `set_async` mask. |

### Offline reference — no switch needed

| Example | What it shows |
| --- | --- |
| `09_build_rule_offline` | Building a richer match/action/instruction set with no network I/O. |
| `28_match_cookbook` | Every match shape with its prerequisites, each validated by the parser. |
| `29_action_cookbook` | Every action type, each round-tripped through the encoder. |
| `30_pipeline_instructions` | A multi-table pipeline: apply-actions vs write-actions, metadata, goto, clear. |

### Controller server and vendor extensions

| Example | What it shows |
| --- | --- |
| `10_run_controller` | Running this crate's bundled learning-switch controller (`src/controller`) that accepts switch connections. |
| `36_conntrack` | Open vSwitch conntrack: `ct()`/`nat()` actions and `ct_state`/`ct_zone` matches. |
| `37_experimenter` | Vendor messages and multipart bodies, and what a clean rejection looks like. |

`09`, `28`, `29` and `30` run on their own — no switch, no network, no root.
Everything else needs a real `OpenFlow` 1.5 peer. The examples are controller
clients or controller-side protocol demonstrations; they do not turn this
crate into a standalone switch. Two ways to get a real peer with Open vSwitch
are:

- **Client examples** (everything except `09`, `10`, `28` and `29`) connect
  *out* to a switch, so point an OVS bridge at them as a passive listener:

  ```sh
  ovs-vsctl set-controller br0 ptcp:6653:0.0.0.0
  OFPORT_ADDR=127.0.0.1:6653 cargo run --example 01_handshake
  ```

  `12_group_mod`, `19_group_inspect` and `32_group_mod_commands` assume
  ports `1`–`3` exist on the bridge; `13_packet_out`, `15_meter_mod` and
  `30_pipeline_instructions` assume port `1` does. Add a few dummy internal
  ports if you're testing against an otherwise empty bridge:

  ```sh
  ovs-vsctl add-port br0 p1 -- set interface p1 type=internal
  ovs-vsctl add-port br0 p2 -- set interface p2 type=internal
  ovs-vsctl add-port br0 p3 -- set interface p3 type=internal
  ```

- **`10_run_controller`** instead listens for switches to dial in, matching
  how OVS normally behaves:

  ```sh
  OFLISTEN=0.0.0.0:6653 cargo run --example 10_run_controller &
  ovs-vsctl set-controller br0 tcp:127.0.0.1:6653
  ```

## Testing against real OVS in a container

`ovs-vsctl`/`ovsdb-server` need root (or membership in the `openvswitch`
group) to talk to `/run/openvswitch`. If you don't have that locally, run the
OVS-side setup from a privileged Docker container that shares the host's OVS
socket and network namespace instead of changing host permissions:

```sh
docker run --rm -it \
  -v /run/openvswitch:/run/openvswitch \
  --network host \
  --privileged \
  archlinux:latest bash

# inside the container
pacman -Sy --noconfirm openvswitch
ovs-vsctl --may-exist add-br ofexample-br
ovs-vsctl set bridge ofexample-br protocols=OpenFlow15
ovs-vsctl set-controller ofexample-br ptcp:16653:127.0.0.1
ovs-vsctl add-port ofexample-br p1 -- set interface p1 type=internal
ovs-vsctl add-port ofexample-br p2 -- set interface p2 type=internal
ovs-vsctl add-port ofexample-br p3 -- set interface p3 type=internal
```

With `--network host`, that `ptcp` listener is reachable from the host
directly, so the client examples can run normally outside the container:

```sh
OFPORT_ADDR=127.0.0.1:16653 cargo run --example 01_handshake
OFPORT_ADDR=127.0.0.1:16653 cargo run --example 07_switch_description
OFPORT_ADDR=127.0.0.1:16653 cargo run --example 12_group_mod
```

Every example in this list (`01`–`08`, `12`–`14`) has been run against a
real Open vSwitch 3.7 bridge set up exactly this way; see git history for
the bugs that surfaced doing so (a double-wrapped match in `05`, a missing
`OFPG_BUCKET_ALL` sentinel in `12`, a missing `in_port` in `13`, and a
mismatched nested-message `xid` in `14` — all switch-rejected the request
with a specific `OFPET_*`/`OFPBFC_*` error that pointed straight at the
fix).

Tear the bridge down from inside the same (or a new) privileged container
when you're done:

```sh
ovs-vsctl --if-exists del-br ofexample-br
```

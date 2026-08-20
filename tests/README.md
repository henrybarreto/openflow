# Integration Test Guide

This folder contains controller integration tests driven by fake or real
OpenFlow switch peers. Use this guide when adding new tests.

## Goal

Write tests that talk to the controller over TCP and verify requests,
responses, and asynchronous events exchanged with a switch.

Do not guess message boundaries.
Do not assume a single `read()` returns one OpenFlow frame.
Always read frames by length.

## Basic Flow

Follow this order for every test:

1. Start the controller on a local test port.
2. Wait until the server is ready to accept connections.
3. Connect a fake switch with `TcpStream`.
4. Send one OpenFlow frame.
5. Read exactly one OpenFlow frame in response.
6. Parse the frame header.
7. Assert the message type and any important fields.
8. Repeat for the rest of the scenario.
9. Close the socket cleanly at the end.

## Frame Reading Rule

Use a helper that:

1. Reads exactly 8 bytes for the OpenFlow header.
2. Parses the length from bytes 2 and 3.
3. Reads the remaining bytes for that frame.
4. Returns the full frame buffer.

Never use raw `read()` to decide where a frame ends.
TCP can merge multiple frames or split one frame.

## What To Assert

For each response, check the smallest set of facts that proves the behavior:

1. `msg_type`
2. `xid` when the message uses one
3. payload bytes when the message carries data
4. frame length when the encoder depends on it

Do not assert on log output unless the test is specifically about logging.

## Existing Canonical Flow

The current canonical example is `tests/controller.rs`.

That test shows the standard handshake:

1. send `HELLO`
2. receive `HELLO`
3. receive `FEATURES_REQUEST`
4. send `FEATURES_REPLY`
5. receive `FLOW_MOD`
6. send `ECHO_REQUEST`
7. receive `ECHO_REPLY`

Use that shape for new tests.

## Recommended Test Cases

Add one focused test per behavior:

1. `hello_and_features`
   - verify the handshake
2. `echo_reply`
   - verify echo request and reply
3. `table_miss_flow_mod`
   - verify the controller installs the table-miss rule after features
4. `packet_in_broadcast_flood`
   - verify a broadcast packet becomes a flood `PacketOut`
5. `packet_in_unknown_destination`
   - verify an unknown destination also floods
6. `packet_in_known_destination_unicast`
   - verify the controller emits a `FlowMod` and a unicast `PacketOut`
7. `packet_in_same_port_ignore`
   - verify no response is sent when source and destination map to the same port
8. `packet_in_missing_in_port_ignore`
   - verify malformed packet-in metadata is ignored
9. `disconnect_is_clean`
   - verify closing the socket does not count as a controller error

## Path Of Completeness

To reach full coverage, create tests in this order:

1. Core controller handshake
   - hello exchange
   - features request and reply
   - initial table-miss flow install
2. Message response behavior
   - echo request and reply
   - barrier reply ignored safely
   - error message logged or ignored safely
   - unknown message type ignored safely
3. Learning-switch behavior
   - broadcast packet -> flood packet-out
   - unknown destination -> flood packet-out
   - known destination on different port -> flow-mod + packet-out
   - known destination on same port -> ignore
   - missing `in_port` -> ignore
   - non-ethernet or too-short payload -> ignore
4. Wire-format edge cases
   - empty payload messages
   - exact-length payload messages
   - invalid lengths rejected
   - short buffers rejected
   - unsupported versions rejected
5. Disconnect and lifecycle behavior
   - clean socket close is not an error
   - repeated connect/disconnect cycles still work
   - second switch can connect after the first disconnects

Treat the suite as complete only when each branch in the controller and each
parser/encoder used by the controller has at least one test that proves it.

If a branch cannot be reached through the TCP fake-switch path, add a direct
unit test next to the parser or encoder instead of forcing the integration test
to do the wrong job.

## Test Template

Use this structure:

```rust
// 1. start controller
// 2. connect fake switch
// 3. send frame
// 4. read frame
// 5. parse header
// 6. assert response
```

For learning-switch tests, the flow is usually:

```rust
// handshake
// send packet-in
// read packet-out or flow-mod
// assert behavior
```

## Checklist

Before finishing a new test, confirm:

1. The test uses framed reads.
2. The test waits for the server before connecting.
3. The test uses a unique port or otherwise avoids collisions.
4. The test closes the socket cleanly.
5. The test covers only one behavior.
6. The assertions prove the intended controller branch.

## Real Open vSwitch Integration Tests

`tests/ovs.rs` runs this crate's client against a real Open
vSwitch instance instead of a fake TCP switch. `tests/container/Containerfile`
and `tests/container/entrypoint.sh` build and boot that instance (a
userspace/`netdev` OVS bridge plus a veth pair for generating real traffic)
via `testcontainers`, which needs a working container engine and enough
privilege to create veth pairs and bring up OVS inside the container.

These tests are slow (image build + container boot) and privileged, so they
are gated behind an env var and skip themselves (returning immediately) when
it isn't set:

```bash
./scripts/test-ovs.sh
```

For the complete local gate, including optional TLS coverage, run
`cargo test --all-features` before the privileged OVS script.

The script checks for Cargo, a reachable Docker-compatible engine, and support
for privileged containers before setting `OPENFLOW_RUN_OVS_TESTS=1` and
running `cargo test --test ovs -- --test-threads=1`. Docker is the default;
Podman also works when its Docker-compatible CLI and socket are configured.
The containers and temporary run-directory mount are removed automatically by
`testcontainers` when the test process exits.

No Linux device access or platform-specific packet adapter is required. These
tests exercise the controller against OpenFlow peers and keep switch datapath
execution outside the crate's mandatory suite.

See the module doc comment at the top of `tests/ovs.rs` for why
these tests connect to the bridge's local management socket rather than
configuring `ovs-vsctl set-controller` with a network target.

## Files To Copy

Start from:

1. `tests/controller.rs`
2. `src/controller/server.rs`
3. `src/protocol/io.rs`

Those files show the controller handshake, the framed read/write rules, and the
current end-to-end test style.

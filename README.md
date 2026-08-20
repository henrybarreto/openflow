# openflow

`openflow` is an asynchronous Rust library for building controllers that
communicate with `OpenFlow` 1.5.1 switches. It provides typed protocol models,
wire-format encoding and decoding, connection and session management, and
controller-side helpers for common switch operations.

The crate runs on the controller side of the connection. It can send flow,
group, meter, port, bundle, packet-out, and statistics requests and receive
switch replies and asynchronous events. It does not execute the switch
datapath or provide host packet I/O.

## Compliance and compatibility

The implementation targets the [OpenFlow Switch Specification 1.5.1](https://github.com/henrybarreto/openflow/blob/main/docs/rfcs/openflow-switch-v1.5.1.txt).
The standard message families, actions, instructions, match fields, and
properties are represented by typed APIs, with raw support for experimenter
messages where vendor-specific data is required.

The test suite covers wire encoding and decoding, controller interactions with
fake peers, and selected interoperability scenarios with Open vSwitch. These
tests are not an ONF certification and this project does not claim formal,
requirement-by-requirement conformance. Interoperability still depends on the
`OpenFlow` version and extensions implemented by the connected switch.

## Install

```toml
[dependencies]
openflow = "1.0"
```

TLS is opt-in:

```toml
[dependencies]
openflow = { version = "1.0", features = ["tls"] }
```

## Quick start

```rust,no_run
use openflow::client::Connection;
use openflow::protocol::action::Action;
use openflow::protocol::constants::ETH_TYPE_IPV4;
use openflow::protocol::instruction::Instruction;
use openflow::protocol::ofmatch::Match;
use openflow::protocol::oxm;
use openflow::protocol::rule::Rule;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut connection = Connection::connect_tcp("127.0.0.1:6653").await?;

    let of_match = Match::new(vec![oxm::eth_type(ETH_TYPE_IPV4)]);
    let instructions = vec![Instruction::apply_actions(vec![Action::output(2)])];
    let flow = Rule::add(0, 0, 100, of_match, instructions);

    connection.add_flow(flow).await?;
    Ok(())
}
```

`connect_tcp` completes the `OpenFlow` handshake before returning. `add_flow`
sends the rule and waits for a barrier reply. This example assumes that the
switch has an output port numbered `2`.

## Scope

Included:

- `OpenFlow` 1.5.1 controller protocol messages and frame handling.
- Handshake, configuration, roles, barriers, asynchronous events, and typed
  remote errors.
- Flow, group, meter, port, table, bundle, packet-out, and multipart requests.
- TCP, Unix-domain sockets, caller-provided async streams, and optional
  verified TLS over TCP.
- Single-switch sessions and multi-switch lifecycle management with reconnect
  and backoff support.
- A small learning-switch controller for demonstrations and simple experiments.

Not included:

- Switch datapath execution, forwarding, NIC access, packet capture, or host
  networking configuration.
- OVSDB, vendor-specific behavior abstractions, or device drivers.
- A general controller framework, topology service, orchestration layer, or
  deployment-specific policy.
- A built-in metrics exporter.
- ONF certification or a formal conformance matrix.

## Examples

The examples are standalone programs. Start with the handshake client:

```sh
OFPORT_ADDR=127.0.0.1:6653 cargo run --example 01_handshake
```

Build a flow without connecting to a switch:

```sh
cargo run --example 09_build_rule_offline
```

Run the bundled learning-switch controller, then configure an Open vSwitch
bridge from another terminal:

```sh
# terminal 1
OFLISTEN=0.0.0.0:6653 cargo run --example 10_run_controller

# terminal 2
ovs-vsctl set-controller br0 tcp:127.0.0.1:6653
```

See [`examples/README.md`](examples/README.md) for the complete example list,
client/controller connection directions, and Open vSwitch setup.

## Testing

```sh
cargo test --all-features
```

The real Open vSwitch integration suite requires a Docker- or
Podman-compatible engine and privileged containers:

```sh
./scripts/test-ovs.sh
```

See [`tests/README.md`](tests/README.md) for the test environment and framing
rules.

Protocol parser fuzzing is local-only. Install `cargo-fuzz`, then run the
time-bounded target from the repository root:

```sh
cargo install cargo-fuzz
cargo fuzz run protocol -- -max_total_time=60
```

The target exercises OpenFlow frame, action, instruction, packet, and flow
parsers. Reproduce a crash with `cargo fuzz run protocol fuzz/artifacts/protocol/<artifact>`.

## Security analysis

The repository includes 58 custom `CodeQL` queries covering input handling,
protocol validation, resource limits, and transport behavior. See
[`codeql/README.md`](codeql/README.md) for the query-pack layout and commands
for running the fixture tests. With the CodeQL CLI installed locally,
`sh scripts/run-codeql.sh` runs those tests and produces a production-source
SARIF report at `.codeql/openflow.sarif`.

## Operational notes

`OpenFlow` frames default to the protocol's maximum 65,535-byte wire length;
applications can lower the limit per connection. Applications should also
define request timeouts, reconnect policy, event handling, backpressure, and
metrics for their deployment.

The optional TLS transport requires an application-provided trust policy and
does not fall back to plaintext. In multi-switch mode, only operations
explicitly submitted as safe are eligible for retry after a transport failure;
uncertain mutating operations are not replayed automatically.

## License

MIT — see [`LICENSE`](LICENSE).

## Notice

`OpenFlow` is a trademark of the Open Networking Foundation. This project is
independent and is not endorsed, sponsored, or certified by the Open Networking
Foundation. The name identifies the protocol implemented by this library.

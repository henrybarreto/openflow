# Release checklist

Run all commands from a clean checkout with the current stable Rust toolchain.
`cargo fmt`, `cargo test`, and `cargo clippy` must be clean before packaging.

```sh
cargo fmt --all --check
git diff --check
cargo test --all-features --no-fail-fast
cargo clippy --all-targets --all-features -- -D warnings
cargo llvm-cov --lib --tests --all-features
cargo package
cargo publish --dry-run
cargo audit
```

`cargo publish` and `cargo audit` require registry or advisory database access.
A publish is not considered verified when run with `--offline` because Cargo
must contact the registry.

The real-OVS gate is separate because it requires a reachable Docker- or
Podman-compatible engine and privileged containers:

```sh
./scripts/test-ovs.sh
```

The production release scope is the controller protocol, connection, session,
request, reconnect, deadline, keepalive, and event-management behavior. No
Linux device access, packet adapter, or standalone datapath execution is
required by this project's release gate.

Formal ONF certification, a requirement-by-requirement conformance matrix,
vendor-specific experimenter semantics, a larger controller framework, and a
built-in metrics exporter are deferred and are not release blockers for the
current scope.

Record command output and the toolchain version with the release artifact.
Do not suppress skipped, unavailable, or environment-blocked checks in the
release report; record the reason and rerun them in a capable environment.

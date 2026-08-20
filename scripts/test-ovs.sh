#!/bin/sh
# Run the real-Open-vSwitch integration suite on a local Docker-compatible
# engine. testcontainers-rs builds the image and starts it privileged because
# the suite creates veth pairs inside the container network namespace.
set -eu

if ! command -v cargo >/dev/null 2>&1; then
    echo "error: cargo is required" >&2
    exit 1
fi

if ! command -v docker >/dev/null 2>&1; then
    echo "error: docker CLI is required (a Podman Docker-compatible CLI also works)" >&2
    exit 1
fi

if ! docker info >/dev/null 2>&1; then
    echo "error: cannot reach a Docker-compatible engine; check Docker or DOCKER_HOST" >&2
    exit 1
fi

if ! docker run --rm --privileged alpine:3.20 true >/dev/null 2>&1; then
    echo "error: this suite needs an engine permitted to start privileged containers" >&2
    exit 1
fi

export OPENFLOW_RUN_OVS_TESTS=1
exec cargo test --test ovs -- --test-threads=1 "$@"

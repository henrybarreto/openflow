#!/bin/sh
# Boots ovsdb-server + ovs-vswitchd (no systemd in this image), creates a
# userspace (netdev) bridge, wires up a veth pair so the test process can
# push real Ethernet frames into it, and optionally points the bridge at an
# external controller. Runs as the container's PID 1; traps SIGTERM to tear
# the bridge/veth down so a forced container removal doesn't leak links into a shared
# (host) network namespace.
set -eu

BRIDGE_NAME="${BRIDGE_NAME:-ofbr0}"
VETH_OUTER="${VETH_OUTER:-ofveth0}"
VETH_INNER="${VETH_INNER:-ofveth1}"
VETH_OUTER_ADDR="${VETH_OUTER_ADDR:-10.211.0.1/24}"
VETH_INNER_ADDR="${VETH_INNER_ADDR:-10.211.0.2/24}"
# e.g. "tcp:127.0.0.1:16700" - left empty means "don't call set-controller",
# useful for tests that only want to talk to the bridge's built-in local
# management socket (/var/run/openvswitch/<bridge>.mgmt).
CONTROLLER_TARGET="${CONTROLLER_TARGET:-}"

DB_SOCK=/var/run/openvswitch/db.sock
DB_FILE=/etc/openvswitch/conf.db

cleanup() {
    ovs-vsctl --if-exists del-br "$BRIDGE_NAME" || true
    ip link del "$VETH_OUTER" 2>/dev/null || true
    ovs-appctl -t ovs-vswitchd exit --cleanup 2>/dev/null || true
    ovs-appctl -t ovsdb-server exit 2>/dev/null || true
}
trap cleanup TERM INT

mkdir -p /var/run/openvswitch /etc/openvswitch

if [ ! -f "$DB_FILE" ]; then
    ovsdb-tool create "$DB_FILE" /usr/share/openvswitch/vswitch.ovsschema
fi

ovsdb-server \
    --remote=punix:"$DB_SOCK" \
    --remote=db:Open_vSwitch,Open_vSwitch,manager_options \
    --pidfile --detach --log-file

ovs-vsctl --no-wait init
ovs-vswitchd --pidfile --detach --log-file -vsyslog:off -vconsole:info

ovs-vsctl --may-exist add-br "$BRIDGE_NAME" \
    -- set bridge "$BRIDGE_NAME" datapath_type=netdev protocols=OpenFlow15 fail_mode=secure

if [ -n "$CONTROLLER_TARGET" ]; then
    ovs-vsctl set-controller "$BRIDGE_NAME" "$CONTROLLER_TARGET"
fi

# veth pair: VETH_OUTER stays in the root namespace with an IP so the test
# can generate real frames (ping/arping) against VETH_INNER, which lives on
# the bridge as a normal switch port and is what actually triggers
# table-miss PACKET_IN messages.
ip link add "$VETH_OUTER" type veth peer name "$VETH_INNER"
ip addr add "$VETH_OUTER_ADDR" dev "$VETH_OUTER" || true
ip link set "$VETH_OUTER" up
ip link set "$VETH_INNER" up
ovs-vsctl --may-exist add-port "$BRIDGE_NAME" "$VETH_INNER"

# /var/run/openvswitch is bind-mounted out to a host directory so the test
# process (running as a normal host user, not root) can connect straight to
# the bridge's local management socket. ovs-vswitchd creates that socket
# root-owned with a restrictive mode, so open it up.
chmod 0777 /var/run/openvswitch
chmod 0777 /var/run/openvswitch/"$BRIDGE_NAME".mgmt

echo "entrypoint: ready (bridge=$BRIDGE_NAME controller=${CONTROLLER_TARGET:-<none>})"

# PID 1: wait for a signal instead of exiting so `trap` above can clean up.
tail -f /dev/null &
wait $!

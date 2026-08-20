macro_rules! info {
    ($($arg:tt)*) => {};
}

fn bind() {}
fn accept() {}
fn spawn() {}
fn echo_reply() {}
fn insert() {}

pub fn run() {
    bind(); // $ Alert[openflow/public-plaintext-bind]
} // $ Alert[openflow/plaintext-controller]

pub fn run_with_limits() {
    accept();
    spawn(); /* $ Alert[openflow/unbounded-connection-spawn] */ /* $ Alert[openflow/task-without-cancellation] */
} // $ Alert[openflow/connection-limit-bypass]

pub fn run_tls_with_limits() {
    accept();
    spawn(); /* $ Alert[openflow/unbounded-connection-spawn] */ /* $ Alert[openflow/task-without-cancellation] */
} // $ Alert[openflow/connection-limit-bypass]

pub fn handle_echo_request() {
    echo_reply(); // $ Alert[openflow/echo-amplification]
}

pub fn handle_bundle_add_message() {
    let mut messages = Vec::new();
    messages.push(1); // $ Alert[openflow/unbounded-bundle-storage]
} // $ Alert[openflow/bundle-state-machine]

pub fn handle_bundle_open() {
    insert();
} // $ Alert[openflow/bundle-state-machine]

pub fn handle_packet_in_with_limits() {
    insert();
}

pub fn handle_switch(input: Result<u8, ()>) -> u8 {
    input.unwrap() // $ Alert[openflow/network-panic]
} // $ Alert[openflow/handshake-timeout-bypass]

pub fn handle_message() {
    match 1 {
        _ => info!("peer event"), /* $ Alert[openflow/ignored-message-variant] */ /* $ Alert[openflow/log-amplification] */
    }
} /* $ Alert[openflow/missing-protocol-error] */ /* $ Alert[openflow/missing-handshake-gate] */

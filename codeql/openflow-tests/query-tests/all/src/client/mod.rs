fn wait_for_message() {}
fn read_message_responding_to_echo() {}
fn new() {}
fn connect() {
    connect(); // $ Alert[openflow/missing-connect-timeout]
}
fn typed_reply_body() {}

pub fn retain_pending_message() {
    let mut messages = Vec::new();
    messages.push(1); // $ Alert[openflow/unbounded-pending-messages]
}

pub fn collect_multipart_reply() {
    let mut collected = Vec::new();
    loop {
        collected.extend_from_slice(&[]); // $ Alert[openflow/unbounded-multipart-reassembly]
        break;
    }
} // $ Alert[openflow/multipart-termination]

pub fn get_config() {}
pub fn request_role() {}
pub fn multipart_request() {}

pub fn connect_tcp() {
    new(); // $ Alert[openflow/frame-limit-bypass]
}

pub fn connect_unix() {
    new(); // $ Alert[openflow/frame-limit-bypass]
}

pub fn connect_stream() {
    new(); // $ Alert[openflow/frame-limit-bypass]
} // $ Alert[openflow/tls-server-name-bypass]

pub fn connect_without_timeout() {
    connect();
}

pub fn use_waiters() {
    wait_for_message(); /* $ Alert[openflow/request-reply-mismatch] */ /* $ Alert[openflow/xid-not-correlated] */
    read_message_responding_to_echo(); // $ Alert[openflow/xid-not-correlated]
}

pub fn decode_multipart() {
    typed_reply_body(); // $ Alert[openflow/multipart-body-kind]
}

pub fn parse_payload() {
    let bytes = Vec::<u8>::new();
    let _ = bytes.to_vec();
}

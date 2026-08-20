fn empty() {}
fn dangerous() {}
fn with_protocol_versions() {}
fn connect() {}
fn TcpStream() {}

pub fn client_config() {
    empty();
    dangerous(); // $ Alert[openflow/tls-verification-bypass]
    with_protocol_versions(); // $ Alert[openflow/weak-tls-policy]
} // $ Alert[openflow/tls-empty-trust-store]

pub fn connect_transport() {
    connect(); // $ Alert[openflow/tls-missing-timeout]
} // $ Alert[openflow/tls-server-name-bypass]

pub fn connect_stream() {} // $ Alert[openflow/tls-server-name-bypass]

pub fn connect_tcp() {
    TcpStream();
} // $ Alert[openflow/tls-plaintext-fallback]

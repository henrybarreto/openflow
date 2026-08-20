pub fn parse() {}

pub fn parse_nested() {
    parse(); // $ Alert[openflow/nested-message-validation]
}

fn encode_experimenter() {}
fn parse_experimenter() {}

pub fn get() {}

pub fn decode() {
    get();
    encode_experimenter(); // $ Alert[openflow/experimenter-payload-validation]
    parse_experimenter(); // $ Alert[openflow/experimenter-payload-validation]
} /* $ Alert[openflow/non-exact-frame-parse] */ /* $ Alert[openflow/packet-length-consistency] */ /* $ Alert[openflow/trailing-bytes-accepted] */

pub fn handle_message() {
    match 1 {
        _ => {} // $ Alert[openflow/ignored-message-variant]
    }
} /* $ Alert[openflow/missing-protocol-error] */ /* $ Alert[openflow/missing-handshake-gate] */

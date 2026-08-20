#![no_main]

use libfuzzer_sys::fuzz_target;
use openflow::protocol::{codec::Decoder, header::Header, hello::Hello, packet_out::PacketOut};

fuzz_target!(|data: &[u8]| {
    // Exercise overlapping parser entry points because messages can embed
    // actions, instructions, OXM fields, and nested control structures.
    let _ = Header::parse(data);
    let _ = Hello::parse(data);
    let _ = Decoder::error(data);
    let _ = Decoder::actions(data);
    let _ = Decoder::instructions(data);
    let _ = Decoder::flow_mod(data);
    let _ = Decoder::packet_out(data);
    let _ = PacketOut::parse(data);
});

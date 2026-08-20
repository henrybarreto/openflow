pub fn handle_switch(input: Result<u8, ()>) -> u8 {
    input.unwrap() // $ Alert[openflow/network-panic]
}

pub fn handle_safe(input: Result<u8, ()>) -> u8 {
    input.unwrap_or(0)
}

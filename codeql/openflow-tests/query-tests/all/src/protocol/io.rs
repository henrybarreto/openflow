pub fn read() {}

pub fn read_frame() {
    let length = 8usize;
    let _frame = vec![0u8; length]; // $ Alert[openflow/unbounded-frame-allocation]
    let _ = length - 1; // $ Alert[openflow/unchecked-length-arithmetic]
    read();
} // $ Alert[openflow/missing-read-timeout]

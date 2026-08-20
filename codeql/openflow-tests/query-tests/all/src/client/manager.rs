fn send() {}
fn try_send() {}
fn push_back() {}
fn spawn() {}

pub fn execute_safe() {} /* $ Alert[openflow/retry-without-idempotency] */ /* $ Alert[openflow/retry-mutating-operation] */

pub fn dispatch_message() {
    send();
}

pub fn send_operation() {
    try_send(); // $ Alert[openflow/unhandled-channel-send]
}

pub fn run() {
    spawn(); // $ Alert[openflow/task-without-cancellation]
}

pub fn write_command() {
    push_back();
}

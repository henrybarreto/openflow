/**
 * @name Handshake timeout bypass
 * @description A connection handshake must have a finite deadline.
 * @kind problem
 * @problem.severity warning
 * @security-severity 7.5
 * @precision high
 * @id openflow/handshake-timeout-bypass
 * @tags security external/cwe/cwe-400
 */
import rust
import OpenFlow

from ProjectFunction function
where function.getName().getText() in ["handshake", "connect_and_handshake", "handle_switch"] and
  not functionHasCall(function, "timeout") and
  not functionHasCall(function, "timeout_at") and
  not functionHasCall(function, "handshake_with_timeout") and
  not functionHasCall(function, "read_frame_with_timeout")
select function, "Bound the handshake so an untrusted peer cannot hold the task indefinitely."

/**
 * @name Unhandled channel send
 * @description Ignoring a try_send result can hide shutdown and backpressure signals.
 * @kind problem
 * @problem.severity warning
 * @security-severity 5.0
 * @precision medium
 * @id openflow/unhandled-channel-send
 * @tags security reliability
 */
import rust
import OpenFlow

from ProjectCall call, ProjectFunction function
where call.getTargetName() = "try_send" and
  call.getEnclosingCallable() = function and
  function.getName().getText() in ["dispatch_message", "publish_status", "stop", "send_operation"] and
  inClient(call)
select call, "Handle channel closure or backpressure instead of discarding the send result."

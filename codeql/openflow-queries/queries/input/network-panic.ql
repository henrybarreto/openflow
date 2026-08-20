/**
 * @name Network panic
 * @description Panic-like operations in network handling can terminate a service on malformed input.
 * @kind problem
 * @problem.severity warning
 * @security-severity 7.5
 * @precision high
 * @id openflow/network-panic
 * @tags security reliability external/cwe/cwe-248
 */
import rust
import OpenFlow

from ProjectCall call, ProjectFunction function
where call.getTargetName() in ["unwrap", "expect", "unwrap_unchecked"] and
  call.getEnclosingCallable() = function and
  function.getName().getText().matches("handle%") and
  (inController(call) or inProtocol(call) or inClient(call))
select call, "Return a protocol error instead of panicking on network-derived data."

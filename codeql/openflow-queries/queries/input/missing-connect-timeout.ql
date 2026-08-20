/**
 * @name Missing connect timeout
 * @description A connection setup path calls connect without a timeout wrapper.
 * @kind problem
 * @problem.severity warning
 * @security-severity 5.0
 * @precision medium
 * @id openflow/missing-connect-timeout
 * @tags security external/cwe/cwe-400
 */
import rust
import OpenFlow

from ProjectCall call, ProjectFunction function
where call.getTargetName() = "connect" and
  call.getEnclosingCallable() = function and
  not functionHasCall(function, "timeout") and
  not functionHasCall(function, "timeout_at") and
  function.getName().getText() = "connect" and
  inClient(call)
select call, "Bound connection establishment with a deadline."

/**
 * @name Unbounded pending messages
 * @description Unrelated messages are queued while a request waits for its reply.
 * @kind problem
 * @problem.severity warning
 * @security-severity 7.5
 * @precision medium
 * @id openflow/unbounded-pending-messages
 * @tags security external/cwe/cwe-770
 */
import rust
import OpenFlow

from ProjectCall call, ProjectFunction function
where call.getTargetName() in ["push", "push_back"] and
  call.getEnclosingCallable() = function and
  function.getName().getText() = "retain_pending_message" and
  not functionHasCall(function, "len") and
  inClient(call)
select call, "Bound pending-message retention before queuing asynchronous traffic."

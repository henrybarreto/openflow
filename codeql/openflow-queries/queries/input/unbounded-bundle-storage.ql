/**
 * @name Unbounded bundle storage
 * @description Bundle messages are retained without a visible count or byte limit.
 * @kind problem
 * @problem.severity warning
 * @security-severity 7.5
 * @precision medium
 * @id openflow/unbounded-bundle-storage
 * @tags security external/cwe/cwe-770
 */
import rust
import OpenFlow

from ProjectCall call, ProjectFunction function
where call.getTargetName() = "push" and
  call.getEnclosingCallable() = function and
  function.getName().getText() = "handle_bundle_add_message" and
  not functionHasCall(function, "len") and
  inController(call)
select call, "Apply a bundle message-count and byte limit before retaining data."

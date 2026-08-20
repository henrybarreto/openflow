/**
 * @name Public plaintext bind
 * @description A plaintext listener may expose the control plane beyond a protected interface.
 * @kind problem
 * @problem.severity warning
 * @security-severity 6.5
 * @precision medium
 * @id openflow/public-plaintext-bind
 * @tags security external/cwe/cwe-668
 */
import rust
import OpenFlow

from ProjectCall call, ProjectFunction function
where call.getTargetName() = "bind" and
  call.getEnclosingCallable() = function and
  function.getName().getText() = "run" and
  inController(call)
select call, "Bind plaintext control traffic only to an explicitly protected interface."

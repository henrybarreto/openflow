/**
 * @name Frame limit bypass
 * @description A connection constructor should preserve the configured maximum frame size.
 * @kind problem
 * @problem.severity warning
 * @security-severity 7.5
 * @precision medium
 * @id openflow/frame-limit-bypass
 * @tags security external/cwe/cwe-770
 */
import rust
import OpenFlow

from ProjectCall call, ProjectFunction function
where call.getTargetName() = "new" and
  call.getEnclosingCallable() = function and
  function.getName().getText() in ["connect_tcp", "connect_unix", "connect_stream"] and
  not functionHasCall(function, "handshake_with_timeout") and
  inClient(call)
select call, "Use the configured frame-size limit when constructing a network connection."

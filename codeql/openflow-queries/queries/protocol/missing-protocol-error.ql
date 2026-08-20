/**
 * @name Missing protocol error
 * @description Invalid or unsupported protocol messages should produce an explicit OpenFlow error.
 * @kind problem
 * @problem.severity warning
 * @security-severity 5.0
 * @precision medium
 * @id openflow/missing-protocol-error
 * @tags security external/cwe/cwe-388
 */
import rust
import OpenFlow

from ProjectFunction function
where function.getName().getText() = "handle_message" and
  not functionHasCall(function, "ensure_message_allowed") and
  not functionHasCall(function, "error")
select function, "Return a protocol error for invalid or unsupported messages."

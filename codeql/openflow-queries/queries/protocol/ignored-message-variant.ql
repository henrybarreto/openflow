/**
 * @name Ignored message variant
 * @description A wildcard match arm can silently accept a protocol message without an explicit error.
 * @kind problem
 * @problem.severity warning
 * @security-severity 5.0
 * @precision medium
 * @id openflow/ignored-message-variant
 * @tags security external/cwe/cwe-20
 */
import rust
import OpenFlow

from MatchArm arm, ProjectFunction function
where arm.getPat() instanceof WildcardPat and
  arm.getEnclosingCallable() = function and
  function.getName().getText() = "handle_message"
select arm, "Handle unsupported message variants explicitly and return a protocol error when required."

/**
 * @name Multipart part limit bypass
 * @description Multipart reply sequences must be bounded by part count.
 * @kind problem
 * @problem.severity warning
 * @security-severity 7.5
 * @precision medium
 * @id openflow/multipart-part-limit-bypass
 * @tags security external/cwe/cwe-770
 */
import rust
import OpenFlow

from LoopExpr loopExpression, ProjectFunction function
where loopExpression.getEnclosingCallable() = function and
  function.getName().getText() = "collect_multipart_reply" and
  functionHasCall(function, "checked_add") and
  not functionHasField(function, "max_parts") and
  not functionHasCall(function, "max_parts")
select loopExpression, "Check the cumulative multipart part limit before accepting another reply."

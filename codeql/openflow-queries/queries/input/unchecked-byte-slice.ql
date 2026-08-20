/**
 * @name Unchecked byte slice
 * @description Direct indexing of a byte buffer can panic on malformed network input.
 * @kind problem
 * @problem.severity warning
 * @security-severity 7.5
 * @precision high
 * @id openflow/unchecked-byte-slice
 * @tags security reliability external/cwe/cwe-119
 */
import rust
import OpenFlow

from IndexExpr expression, ProjectFunction function
where expression.fromSource() and
  inProtocol(expression) and
  expression.getEnclosingCallable() = function and
  function.getName().getText().matches("parse%")
  and not functionHasCall(function, "first_chunk")
  and not functionHasCall(function, "try_into")
select expression, "Use a checked slice or validated offset for network-derived bytes."

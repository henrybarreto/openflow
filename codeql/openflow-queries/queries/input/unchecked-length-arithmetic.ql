/**
 * @name Unchecked length arithmetic
 * @description Length subtraction or addition can underflow or overflow before a bounds check.
 * @kind problem
 * @problem.severity warning
 * @security-severity 7.5
 * @precision medium
 * @id openflow/unchecked-length-arithmetic
 * @tags security external/cwe/cwe-190
 */
import rust
import OpenFlow

from BinaryExpr expression, ProjectFunction function
where expression.fromSource() and expression.getOperatorName() in ["+", "-"] and
  expression.getEnclosingCallable() = function and
  function.getName().getText() = "read_frame" and
  not functionHasCall(function, "reset") and
  expression.getFile().getAbsolutePath().matches("%/src/protocol/io.rs")
select expression, "Use checked or saturating length arithmetic before indexing or allocating."

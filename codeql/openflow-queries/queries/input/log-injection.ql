/**
 * @name Log injection
 * @description Log records include values that may originate from an untrusted peer.
 * @kind problem
 * @problem.severity warning
 * @security-severity 5.0
 * @precision medium
 * @id openflow/log-injection
 * @tags security external/cwe/cwe-117
 */
import rust
import OpenFlow

from MacroCall macro, ProjectFunction function
where macro.fromSource() and
  macro.getPath().toAbbreviatedString() = "format" and
  macro.getEnclosingCallable() = function and
  function.getName().getText() = "handle_message" and
  functionHasMacro(function, "info") and
  inController(macro)
select macro, "Sanitize or structure peer-controlled values before logging them."

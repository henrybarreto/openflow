/**
 * @name Log amplification
 * @description High-rate protocol events are logged at an unbounded per-message rate.
 * @kind problem
 * @problem.severity recommendation
 * @security-severity 4.0
 * @precision medium
 * @id openflow/log-amplification
 * @tags security external/cwe/cwe-779
 */
import rust
import OpenFlow

from MacroCall macro, ProjectFunction function
where macro.fromSource() and
  macro.getPath().toAbbreviatedString() in ["info", "warn", "error", "debug", "trace"] and
  macro.getEnclosingCallable() = function and
  function.getName().getText() = "handle_message" and
  inController(macro)
select macro, "Rate-limit or aggregate logs for peer-controlled protocol events."

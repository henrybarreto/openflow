/**
 * @name Unbounded frame allocation
 * @description A vector allocation uses a wire-controlled frame size without an explicit limit.
 * @kind problem
 * @problem.severity warning
 * @security-severity 7.5
 * @precision medium
 * @id openflow/unbounded-frame-allocation
 * @tags security external/cwe/cwe-770
 */
import rust
import OpenFlow

from MacroCall m, ProjectFunction function
where m.fromSource() and m.getPath().toAbbreviatedString() = "vec" and
  m.getEnclosingCallable() = function and
  function.getName().getText() = "read_frame" and
  not functionHasCall(function, "reset") and
  m.getFile().getAbsolutePath().matches("%/src/protocol/io.rs")
select m, "Validate the advertised frame size before allocating a buffer."

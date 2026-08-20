/**
 * @name Reserved bit accepted
 * @description Reserved wire bits should be checked or deliberately documented as forward-compatible.
 * @kind problem
 * @problem.severity recommendation
 * @security-severity 4.0
 * @precision medium
 * @id openflow/reserved-bit-accepted
 * @tags security external/cwe/cwe-20
 */
import rust
import OpenFlow

from ProjectFunction function
where function.getName().getText() = "parse_stats" and
  function.getFile().getAbsolutePath().matches("%/protocol/oxs.rs") and
  not functionHasCall(function, "read_u16")
select function, "Review reserved-field handling and reject non-zero values when required by the message."

/**
 * @name Non-exact frame parse
 * @description A parser accepts a prefix of a frame instead of requiring an exact wire length.
 * @kind problem
 * @problem.severity warning
 * @security-severity 5.0
 * @precision medium
 * @id openflow/non-exact-frame-parse
 * @tags security external/cwe/cwe-20
 */
import rust
import OpenFlow

from ProjectFunction function
where function.getName().getText() = "decode" and
  inProtocol(function) and
  functionHasCall(function, "get") and
  not functionHasCall(function, "len")
select function, "Require the parser input and advertised frame length to agree exactly."

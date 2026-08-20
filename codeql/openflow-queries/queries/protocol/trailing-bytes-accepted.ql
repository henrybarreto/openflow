/**
 * @name Trailing bytes accepted
 * @description A decoder takes only a prefix of its input without proving that the remainder is valid padding.
 * @kind problem
 * @problem.severity warning
 * @security-severity 6.5
 * @precision medium
 * @id openflow/trailing-bytes-accepted
 * @tags security external/cwe/cwe-20
 */
import rust
import OpenFlow

from ProjectFunction function
where function.getName().getText().matches("decode%") and
  functionHasCall(function, "get") and
  not functionHasCall(function, "len") and
  inProtocol(function)
select function, "Reject unconsumed bytes or validate them as protocol padding."

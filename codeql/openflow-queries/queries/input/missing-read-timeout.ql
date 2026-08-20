/**
 * @name Missing read timeout
 * @description A network read path has no timeout operation in its enclosing function.
 * @kind problem
 * @problem.severity warning
 * @security-severity 7.5
 * @precision medium
 * @id openflow/missing-read-timeout
 * @tags security external/cwe/cwe-400
 */
import rust
import OpenFlow

from ProjectFunction function
where function.getName().getText().matches("read%") and
  functionHasCall(function, "read") and
  not functionHasCall(function, "reset") and
  not functionHasCall(function, "timeout") and
  not functionHasCall(function, "timeout_at") and
  inProtocol(function)
select function, "Apply a deadline to reads that wait for an untrusted peer."

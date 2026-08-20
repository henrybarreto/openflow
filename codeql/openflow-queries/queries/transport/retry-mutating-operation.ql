/**
 * @name Retry mutating operation
 * @description Retrying a mutating OpenFlow operation after transport loss can duplicate effects.
 * @kind problem
 * @problem.severity warning
 * @security-severity 7.5
 * @precision medium
 * @id openflow/retry-mutating-operation
 * @tags security external/cwe/cwe-672
 */
import rust
import OpenFlow

from ProjectFunction function
where function.getName().getText() = "execute_safe" and
  function.getFile().getAbsolutePath().matches("%/client/manager.rs") and
  not functionHasCall(function, "execute_safe") and
  not functionHasCall(function, "send_operation")
select function, "Restrict automatic retries to operations with an explicit idempotency guarantee."

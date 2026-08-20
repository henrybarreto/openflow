/**
 * @name Retry without idempotency
 * @description A retry boundary must make operation idempotency explicit before replaying it.
 * @kind problem
 * @problem.severity warning
 * @security-severity 7.5
 * @precision medium
 * @id openflow/retry-without-idempotency
 * @tags security external/cwe/cwe-672
 */
import rust
import OpenFlow

from ProjectFunction function
where function.getName().getText() = "execute_safe" and
  function.getFile().getAbsolutePath().matches("%/client/manager.rs") and
  not functionHasCall(function, "execute_safe") and
  not functionHasCall(function, "send_operation")
select function, "Verify that the retried operation is read-only or idempotent."

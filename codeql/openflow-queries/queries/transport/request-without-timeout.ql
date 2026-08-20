/**
 * @name Request without timeout
 * @description A request that waits for a peer reply must have an operation deadline.
 * @kind problem
 * @problem.severity warning
 * @security-severity 7.5
 * @precision medium
 * @id openflow/request-without-timeout
 * @tags security external/cwe/cwe-400
 */
import rust
import OpenFlow

from ProjectFunction function
where function.getName().getText() in ["get_config", "request_role", "multipart_request"] and
  inClient(function) and
  functionHasCall(function, "wait_for_message") and
  not functionHasCall(function, "timeout") and
  not functionHasCall(function, "timeout_at")
select function, "Apply an operation timeout while waiting for the switch reply."

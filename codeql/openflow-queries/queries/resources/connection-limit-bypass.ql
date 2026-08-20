/**
 * @name Connection limit bypass
 * @description An accept loop must enforce a maximum number of active connections.
 * @kind problem
 * @problem.severity warning
 * @security-severity 7.5
 * @precision medium
 * @id openflow/connection-limit-bypass
 * @tags security external/cwe/cwe-770
 */
import rust
import OpenFlow

from ProjectFunction function
where function.getName().getText() in ["run", "run_with_limits", "run_tls", "run_tls_with_limits"] and
  functionHasCall(function, "accept") and
  not functionHasCall(function, "max_connections") and
  not functionHasCall(function, "try_acquire_owned") and
  not functionHasCall(function, "acquire_owned")
select function, "Enforce an active-connection limit before spawning another handler."

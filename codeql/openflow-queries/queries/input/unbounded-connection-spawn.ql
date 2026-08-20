/**
 * @name Unbounded connection spawning
 * @description An accept loop spawns connection tasks without an admission limit.
 * @kind problem
 * @problem.severity warning
 * @security-severity 7.5
 * @precision medium
 * @id openflow/unbounded-connection-spawn
 * @tags security external/cwe/cwe-770
 */
import rust
import OpenFlow

from ProjectCall call, ProjectFunction function
where call.getTargetName() = "spawn" and
  call.getEnclosingCallable() = function and
  function.getName().getText() in ["run_with_limits", "run_tls_with_limits"] and
  not functionHasCall(function, "try_acquire_owned") and
  not functionHasCall(function, "acquire_owned") and
  inController(call)
select call, "Limit or otherwise account for concurrent connection tasks."

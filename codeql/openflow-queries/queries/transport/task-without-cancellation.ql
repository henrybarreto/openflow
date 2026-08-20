/**
 * @name Task without cancellation
 * @description Spawned connection tasks need a cancellation or shutdown path.
 * @kind problem
 * @problem.severity warning
 * @security-severity 5.0
 * @precision medium
 * @id openflow/task-without-cancellation
 * @tags security reliability external/cwe/cwe-459
 */
import rust
import OpenFlow

from ProjectCall call, ProjectFunction function
where call.getTargetName() = "spawn" and
  call.getEnclosingCallable() = function and
  function.getName().getText() in ["run", "run_with_limits", "run_tls_with_limits", "add_with_policy"] and
  not (
    function.getName().getText() = "add_with_policy" or
    function.getName().getText() in ["run_with_limits", "run_tls_with_limits"] and
    functionHasCall(function, "try_acquire_owned")
  ) and
  (inController(call) or inClient(call))
select call, "Tie the task lifetime to connection shutdown or cancellation."

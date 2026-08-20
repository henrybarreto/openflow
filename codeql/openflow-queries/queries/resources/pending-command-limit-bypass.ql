/**
 * @name Pending command limit bypass
 * @description Outstanding command identifiers must be bounded while waiting for a barrier.
 * @kind problem
 * @problem.severity warning
 * @security-severity 7.5
 * @precision medium
 * @id openflow/pending-command-limit-bypass
 * @tags security external/cwe/cwe-770
 */
import rust
import OpenFlow

from ProjectFunction function
where function.getName().getText() in ["write_command", "retain_pending_command_xid"] and
  functionHasCall(function, "push_back") and
  functionHasCall(function, "len") and
  not functionHasField(function, "MAX_PENDING_COMMAND_XIDS") and
  not functionHasField(function, "pending_command_xids") and
  not functionHasCall(function, "MAX_PENDING_COMMAND_XIDS")
select function, "Bound pending command identifiers before adding another entry."

/**
 * @name Missing handshake gate
 * @description Message dispatch must reject stateful messages before handshake completion.
 * @kind problem
 * @problem.severity warning
 * @security-severity 7.5
 * @precision high
 * @id openflow/missing-handshake-gate
 * @tags security external/cwe/cwe-306
 */
import rust
import OpenFlow

from ProjectFunction function
where function.getName().getText() = "handle_message" and
  not functionHasCall(function, "ensure_message_allowed")
select function, "Gate stateful message handling on a completed handshake."

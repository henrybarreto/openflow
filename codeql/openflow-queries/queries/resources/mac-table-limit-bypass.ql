/**
 * @name MAC table limit bypass
 * @description Learning-switch state must not grow without a configured entry limit.
 * @kind problem
 * @problem.severity warning
 * @security-severity 7.5
 * @precision medium
 * @id openflow/mac-table-limit-bypass
 * @tags security external/cwe/cwe-770
 */
import rust
import OpenFlow

from ProjectFunction function
where function.getName().getText() = "handle_packet_in_with_limits" and
  functionHasCall(function, "insert") and
  functionHasCall(function, "len") and
  not functionHasField(function, "max_mac_entries") and
  not functionHasCall(function, "max_mac_entries")
select function, "Enforce the MAC table entry limit before inserting peer-controlled addresses."

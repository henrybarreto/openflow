/**
 * @name Bundle message limit bypass
 * @description A bundle must reject excessive nested-message counts.
 * @kind problem
 * @problem.severity warning
 * @security-severity 7.5
 * @precision medium
 * @id openflow/bundle-message-limit-bypass
 * @tags security external/cwe/cwe-770
 */
import rust
import OpenFlow

from ProjectFunction function
where function.getName().getText() = "handle_bundle_add_message" and
  functionHasCall(function, "push") and
  functionHasCall(function, "len") and
  not functionHasField(function, "max_messages_per_bundle") and
  not functionHasField(function, "max_total_bundle_bytes") and
  not functionHasCall(function, "max_messages_per_bundle")
select function, "Enforce a per-bundle nested-message limit before retaining the message."

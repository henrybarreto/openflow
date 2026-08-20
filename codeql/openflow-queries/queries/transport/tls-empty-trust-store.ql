/**
 * @name TLS empty trust store
 * @description A client trust store must contain an intentional trust anchor before connecting.
 * @kind problem
 * @problem.severity error
 * @security-severity 8.1
 * @precision medium
 * @id openflow/tls-empty-trust-store
 * @tags security external/cwe/cwe-295
 */
import rust
import OpenFlow

from ProjectFunction function
where function.getName().getText() = "client_config" and
  functionHasCall(function, "empty") and
  not functionHasCall(function, "add")
select function, "Reject an empty trust store or require an explicit trust policy."

/**
 * @name TLS server-name bypass
 * @description TLS connections must verify the configured server name and use it for SNI.
 * @kind problem
 * @problem.severity error
 * @security-severity 8.1
 * @precision medium
 * @id openflow/tls-server-name-bypass
 * @tags security external/cwe/cwe-297
 */
import rust
import OpenFlow

from ProjectFunction function
where function.getName().getText() in ["connect_transport", "connect_stream"] and
  not functionHasCall(function, "connect_transport") and
  not functionHasCall(function, "try_from") and
  not functionHasCall(function, "ServerName")
select function, "Construct ServerName from the configured endpoint and pass it to TLS."

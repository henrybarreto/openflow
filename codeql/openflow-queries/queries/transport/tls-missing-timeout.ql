/**
 * @name TLS missing timeout
 * @description TLS handshakes can otherwise wait indefinitely on an untrusted endpoint.
 * @kind problem
 * @problem.severity warning
 * @security-severity 7.5
 * @precision high
 * @id openflow/tls-missing-timeout
 * @tags security external/cwe/cwe-400
 */
import rust
import OpenFlow

from ProjectCall call, ProjectFunction function
where call.getTargetName() in ["connect", "accept"] and
  call.getEnclosingCallable() = function and
  function.getFile().getAbsolutePath().matches("%/tls.rs") and
  not isInlineTestFunction(function) and
  not functionHasCall(function, "timeout") and
  not functionHasCall(function, "timeout_at") and
  inTls(call)
select call, "Wrap the TLS handshake in a bounded timeout."

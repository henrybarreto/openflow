/**
 * @name TLS plaintext fallback
 * @description A TLS connector must not silently continue over its original plaintext stream.
 * @kind problem
 * @problem.severity error
 * @security-severity 8.1
 * @precision high
 * @id openflow/tls-plaintext-fallback
 * @tags security external/cwe/cwe-319
 */
import rust
import OpenFlow

from ProjectFunction function
where function.getName().getText().matches("connect%") and
  function.getFile().getAbsolutePath().matches("%/tls.rs") and
  functionHasCall(function, "TcpStream") and
  not functionHasCall(function, "connect_transport") and
  not functionHasCall(function, "connect_stream") and
  inTls(function)
select function, "Fail the connection when TLS setup fails; do not fall back to plaintext."

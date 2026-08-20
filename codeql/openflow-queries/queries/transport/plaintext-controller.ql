/**
 * @name Plaintext controller
 * @description The controller exposes a non-TLS listener for OpenFlow traffic.
 * @kind problem
 * @problem.severity warning
 * @security-severity 6.5
 * @precision high
 * @id openflow/plaintext-controller
 * @tags security external/cwe/cwe-319
 */
import rust
import OpenFlow

from ProjectFunction function
where function.getName().getText() = "run" and
  function.getFile().getAbsolutePath().matches("%/controller/server.rs") and
  functionHasCall(function, "bind") and
  inController(function)
select function, "Require an explicit deployment decision before accepting plaintext control traffic."

/**
 * @name Header version bypass
 * @description Header parsing accepts a non-Hello version unless the message layer enforces it.
 * @kind problem
 * @problem.severity warning
 * @security-severity 6.5
 * @precision medium
 * @id openflow/header-version-bypass
 * @tags security external/cwe/cwe-20
 */
import rust
import OpenFlow

from ProjectFunction function
where function.getName().getText() = "parse" and
  function.getFile().getAbsolutePath().matches("%/protocol/header.rs") and
  not functionHasCall(function, "from_be_bytes") and
  not functionHasCall(function, "UnsupportedVersion")
select function, "Keep version negotiation limited to Hello and validate versions for other messages."

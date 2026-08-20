/**
 * @name Multipart termination
 * @description Multipart reassembly must terminate only when the MORE flag is clear.
 * @kind problem
 * @problem.severity warning
 * @security-severity 7.5
 * @precision medium
 * @id openflow/multipart-termination
 * @tags security external/cwe/cwe-835
 */
import rust
import OpenFlow

from ProjectFunction function
where function.getName().getText() = "collect_multipart_reply" and
  not functionHasField(function, "multipart_limits") and
  not functionHasCall(function, "OFPMPF_REPLY_MORE")
select function, "Use the multipart MORE flag as the only termination condition."

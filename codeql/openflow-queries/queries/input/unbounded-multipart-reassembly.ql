/**
 * @name Unbounded multipart reassembly
 * @description Multipart data is accumulated without a visible collection limit.
 * @kind problem
 * @problem.severity warning
 * @security-severity 7.5
 * @precision medium
 * @id openflow/unbounded-multipart-reassembly
 * @tags security external/cwe/cwe-770
 */
import rust
import OpenFlow

from ProjectCall call, ProjectFunction function
where call.getTargetName() in ["extend", "extend_from_slice"] and
  call.getEnclosingCallable() = function and
  function.getName().getText() = "collect_multipart_reply" and
  not functionHasCall(function, "len") and
  inClient(call)
select call, "Enforce multipart byte and part limits before retaining another reply."

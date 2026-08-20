/**
 * @name Unbounded payload copy
 * @description A payload is copied into a new allocation without an obvious protocol limit.
 * @kind problem
 * @problem.severity warning
 * @security-severity 6.5
 * @precision medium
 * @id openflow/unbounded-payload-copy
 * @tags security external/cwe/cwe-770
 */
import rust
import OpenFlow

from ProjectCall call, ProjectFunction function
where call.getTargetName() in ["to_vec", "clone", "extend_from_slice"] and
  call.getEnclosingCallable() = function and
  function.getName().getText().matches("parse%") and
  not functionHasCall(function, "body_from_frame") and
  not functionHasCall(function, "parse_length_prefixed_entries") and
  not functionHasCall(function, "len") and
  inProtocol(call)
select call, "Bound or account for the payload before copying it."

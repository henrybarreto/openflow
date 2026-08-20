/**
 * @name Experimenter payload validation
 * @description Experimenter messages still require a valid fixed header and bounded payload.
 * @kind problem
 * @problem.severity warning
 * @security-severity 6.5
 * @precision medium
 * @id openflow/experimenter-payload-validation
 * @tags security external/cwe/cwe-20
 */
import rust
import OpenFlow

from ProjectCall call, ProjectFunction function
where call.getTargetName() in ["encode_experimenter", "parse_experimenter"] and
  call.getEnclosingCallable() = function and
  not (
    function.getName().getText() in ["parse_action", "parse_instruction"] and
    call.getTargetName() = "parse_experimenter"
  ) and
  not (
    function.getName().getText() = "experimenter" and
    call.getTargetName() = "encode_experimenter"
  )
select call, "Validate experimenter header length and apply a payload policy."

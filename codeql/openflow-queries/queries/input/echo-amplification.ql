/**
 * @name Echo amplification
 * @description Echo replies copy attacker-controlled payloads without an explicit size policy.
 * @kind problem
 * @problem.severity warning
 * @security-severity 5.0
 * @precision medium
 * @id openflow/echo-amplification
 * @tags security external/cwe/cwe-400
 */
import rust
import OpenFlow

from ProjectCall call, ProjectFunction function
where call.getTargetName() = "echo_reply" and
  call.getEnclosingCallable() = function and
  function.getName().getText() = "handle_echo_request" and
  not functionHasCall(function, "send_frame") and
  inController(call)
select call, "Apply a payload limit or rate policy to echo responses."

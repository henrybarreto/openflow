/**
 * @name Multipart body kind
 * @description Multipart replies must decode the body according to the requested statistics kind.
 * @kind problem
 * @problem.severity warning
 * @security-severity 6.5
 * @precision medium
 * @id openflow/multipart-body-kind
 * @tags security external/cwe/cwe-20
 */
import rust
import OpenFlow

from ProjectCall call, ProjectFunction function
where call.getTargetName() in ["typed_reply_body", "parse_multipart_reply"] and
  call.getEnclosingCallable() = function and
  not (
    function.getName().getText() = "multipart_request_with_timeout" and
    call.getTargetName() = "typed_reply_body"
  ) and
  inClient(call)
select call, "Dispatch multipart body decoding by the validated request kind."

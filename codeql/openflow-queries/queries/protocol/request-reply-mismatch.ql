/**
 * @name Request reply mismatch
 * @description A request wait path should constrain the reply message kind, not only receive any frame.
 * @kind problem
 * @problem.severity warning
 * @security-severity 6.5
 * @precision medium
 * @id openflow/request-reply-mismatch
 * @tags security external/cwe/cwe-20
 */
import rust
import OpenFlow

from ProjectCall call, ProjectFunction function
where call.getTargetName() = "wait_for_message"
  and call.getEnclosingCallable() = function
  and not (
    function.getName().getText() = "wait_for_features_reply" or
    function.getName().getText() = "get_config" or
    function.getName().getText() = "get_config_with_timeout" or
    function.getName().getText() = "request_role" or
    function.getName().getText() = "request_role_with_timeout" or
    function.getName().getText() = "get_async" or
    function.getName().getText() = "collect_multipart_reply"
  )
select call, "Match the expected reply variant and reject unrelated messages."

/**
 * @name XID not correlated
 * @description Requests and replies must compare transaction identifiers before accepting replies.
 * @kind problem
 * @problem.severity warning
 * @security-severity 7.5
 * @precision medium
 * @id openflow/xid-not-correlated
 * @tags security external/cwe/cwe-345
 */
import rust
import OpenFlow

from ProjectCall call, ProjectFunction function
where call.getTargetName() in ["wait_for_message", "read_message_responding_to_echo"] and
  call.getEnclosingCallable() = function and
  not (
    function.getName().getText() = "wait_for_message" or
    function.getName().getText() = "exchange_hello" or
    function.getName().getText() = "request_features_and_config" or
    function.getName().getText() = "wait_for_features_reply" or
    function.getName().getText() = "wait_for_barrier" or
    function.getName().getText() = "get_config" or
    function.getName().getText() = "get_config_with_timeout" or
    function.getName().getText() = "request_role" or
    function.getName().getText() = "request_role_with_timeout" or
    function.getName().getText() = "get_async" or
    function.getName().getText() = "collect_multipart_reply"
  )
select call, "Correlate the reply transaction identifier with the outstanding request."

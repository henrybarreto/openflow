/**
 * @name Nested message validation
 * @description Nested protocol messages must be decoded with the same structural checks as frames.
 * @kind problem
 * @problem.severity warning
 * @security-severity 6.5
 * @precision medium
 * @id openflow/nested-message-validation
 * @tags security external/cwe/cwe-20
 */
import rust
import OpenFlow

from ProjectCall call, ProjectFunction function
where call.getTargetName() = "parse" and
  call.getEnclosingCallable() = function and
  function.getName().getText().matches("parse_%") and
  function.getName().getText() != "parse_of_type" and
  not functionHasCall(function, "body_from_frame") and
  not functionHasCall(function, "is_multiple_of") and
  not function.getName().getText() in [
    "parse_get_request", "parse_error", "parse_oxs_list",
    "parse_multipart_request", "parse_multipart_reply", "parse_role_request",
    "parse_role_reply", "parse_async_config_get_reply", "parse_async_config_set",
    "parse_table_mod", "parse_port_mod", "parse_group_mod", "parse_meter_mod",
    "parse_bundle_message", "parse_bundle_add_message"
  ] and
  inProtocol(call)
select call, "Validate nested message type, length, version, and trailing bytes before accepting it."

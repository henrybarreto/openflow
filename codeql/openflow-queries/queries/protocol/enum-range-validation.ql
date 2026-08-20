/**
 * @name Enum range validation
 * @description Numeric protocol enums must be rejected when their values are not defined.
 * @kind problem
 * @problem.severity warning
 * @security-severity 5.0
 * @precision medium
 * @id openflow/enum-range-validation
 * @tags security external/cwe/cwe-20
 */
import rust
import OpenFlow

from ProjectFunction function
where function.getName().getText() in [
    "parse_action",
    "parse_bundle_message",
    "parse_multipart_reply",
    "parse_multipart_request",
    "parse_role_request",
    "parse_role_reply"
  ] and
  functionHasCall(function, "read_u16") and
  inProtocol(function)
select function, "Validate numeric message, action, and property enums before dispatch."

/**
 * @name TLV padding not validated
 * @description TLV parsers must validate alignment padding and require zero padding bytes.
 * @kind problem
 * @problem.severity warning
 * @security-severity 5.0
 * @precision medium
 * @id openflow/tlv-padding-not-validated
 * @tags security external/cwe/cwe-20
 */
import rust
import OpenFlow

from ProjectFunction function
where function.getName().getText() = "parse_stats" and
  not functionHasCall(function, "is_multiple_of") and
  not functionHasCall(function, "any") and
  inProtocol(function)
select function, "Validate alignment padding bytes instead of discarding them."

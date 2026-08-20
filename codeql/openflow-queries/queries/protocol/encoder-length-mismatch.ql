/**
 * @name Encoder length mismatch
 * @description Encoders that append variable data must derive the header length from final output.
 * @kind problem
 * @problem.severity warning
 * @security-severity 6.5
 * @precision medium
 * @id openflow/encoder-length-mismatch
 * @tags security external/cwe/cwe-20
 */
import rust
import OpenFlow

from ProjectFunction function
where function.getName().getText().matches("encode%") and
  functionHasCall(function, "extend_from_slice") and
  function.getName().getText() != "encode" and
  not function.getName().getText().matches("%property%") and
  not functionHasCall(function, "write_len") and
  not functionHasCall(function, "checked_u16_len") and
  not functionHasCall(function, "encode_message") and
  not functionHasCallThroughTarget(function, "encode_into", "write_len") and
  not function.getName().getText() in [
    "encode_generic", "encode_u8_arg", "encode_u16_arg", "encode_u32_arg",
    "encode_list", "encode_tlv_list", "encode_header"
  ] and
  inProtocol(function)
select function, "Compute and validate the wire length after all variable fields are encoded."

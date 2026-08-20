/**
 * @name Multipart byte limit bypass
 * @description Multipart reply bytes must be bounded before accumulation.
 * @kind problem
 * @problem.severity warning
 * @security-severity 7.5
 * @precision medium
 * @id openflow/multipart-byte-limit-bypass
 * @tags security external/cwe/cwe-770
 */
import rust
import OpenFlow

from ProjectFunction function
where function.getName().getText() = "collect_multipart_reply" and
  functionHasCall(function, "extend_from_slice") and
  functionHasCall(function, "len") and
  not functionHasField(function, "max_bytes") and
  not functionHasCall(function, "max_bytes")
select function, "Check the cumulative multipart byte limit before extending the buffer."

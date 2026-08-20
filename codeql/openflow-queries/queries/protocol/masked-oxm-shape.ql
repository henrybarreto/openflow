/**
 * @name Masked OXM shape
 * @description Masked OXM values must have equal value and mask widths and a maskable field id.
 * @kind problem
 * @problem.severity warning
 * @security-severity 6.5
 * @precision medium
 * @id openflow/masked-oxm-shape
 * @tags security external/cwe/cwe-20
 */
import rust
import OpenFlow

from ProjectCall call
where call.getTargetName() = "masked_field" and
  inProtocol(call)
select call, "Validate masked OXM width and field maskability before encoding or accepting it."

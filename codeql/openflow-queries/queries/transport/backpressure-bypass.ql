/**
 * @name Backpressure bypass
 * @description Unbounded or oversized channels can turn peer traffic into memory pressure.
 * @kind problem
 * @problem.severity warning
 * @security-severity 7.5
 * @precision medium
 * @id openflow/backpressure-bypass
 * @tags security external/cwe/cwe-770
 */
import rust
import OpenFlow

from ProjectCall call
where call.getTargetName() = "unbounded_channel"
select call, "Use a bounded channel and define behavior when the queue is full."

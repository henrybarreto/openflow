/**
 * @name Weak TLS policy
 * @description TLS configuration should use approved protocol versions and cipher policy.
 * @kind problem
 * @problem.severity warning
 * @security-severity 7.4
 * @precision medium
 * @id openflow/weak-tls-policy
 * @tags security external/cwe/cwe-326
 */
import rust
import OpenFlow

from ProjectCall call
where call.getTargetName() = "with_protocol_versions" and inTls(call)
select call, "Review the TLS protocol-version policy against the deployment baseline."

/**
 * @name TLS verification bypass
 * @description Custom certificate verifiers or dangerous TLS configuration can disable authentication.
 * @kind problem
 * @problem.severity error
 * @security-severity 8.1
 * @precision high
 * @id openflow/tls-verification-bypass
 * @tags security external/cwe/cwe-295
 */
import rust
import OpenFlow

from ProjectCall call
where call.getTargetName() in ["dangerous", "set_certificate_verifier", "with_custom_certificate_verifier"]
select call, "Do not bypass certificate and hostname verification for the OpenFlow peer."

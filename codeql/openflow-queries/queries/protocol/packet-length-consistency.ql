/**
 * @name Packet length consistency
 * @description Packet payload and enclosing frame lengths must be mutually consistent.
 * @kind problem
 * @problem.severity warning
 * @security-severity 7.5
 * @precision medium
 * @id openflow/packet-length-consistency
 * @tags security external/cwe/cwe-20
 */
import rust
import OpenFlow

from ProjectFunction function
where function.getName().getText() in ["parse", "decode"] and
  function.getFile().getAbsolutePath().matches("%/protocol/%") and
  functionHasCall(function, "get") and
  not functionHasCall(function, "body_from_frame") and
  not functionHasCall(function, "parse_experimenter_property") and
  not functionHasCall(function, "len") and
  inProtocol(function)
select function, "Check packet and frame lengths before slicing payload data."

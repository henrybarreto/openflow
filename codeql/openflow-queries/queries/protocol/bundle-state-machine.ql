/**
 * @name Bundle state machine
 * @description Bundle operations must enforce open, closed, commit, and discard state transitions.
 * @kind problem
 * @problem.severity warning
 * @security-severity 7.5
 * @precision medium
 * @id openflow/bundle-state-machine
 * @tags security external/cwe/cwe-841
 */
import rust
import OpenFlow

from ProjectFunction function
where ((
    function.getName().getText() = "handle_bundle_open" and
    not functionHasCall(function, "contains_key") and
    not functionHasCall(function, "len")
  ) or (
    function.getName().getText() = "handle_bundle_close" and
    not functionHasCall(function, "get_mut")
  ) or (
    function.getName().getText() in ["handle_bundle_commit", "handle_bundle_discard"] and
    not functionHasCall(function, "remove")
  ) or (
    function.getName().getText() = "handle_bundle_add_message" and
    not functionHasCall(function, "get")
  )) and
  inController(function)
select function, "Check bundle existence and state before applying this bundle operation."

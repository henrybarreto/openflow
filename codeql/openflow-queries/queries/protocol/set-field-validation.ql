/**
 * @name Set-field validation
 * @description SET_FIELD actions must contain exactly one valid OXM field and correct padding.
 * @kind problem
 * @problem.severity warning
 * @security-severity 6.5
 * @precision medium
 * @id openflow/set-field-validation
 * @tags security external/cwe/cwe-20
 */
import rust
import OpenFlow

from ProjectFunction function
where function.getName().getText() = "parse_set_field" and
  not functionHasCall(function, "validate_set_field") and
  function.getFile().getAbsolutePath().matches("%/protocol/action.rs")
select function, "Validate the SET_FIELD OXM shape, field width, and zero padding."

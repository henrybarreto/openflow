/**
 * @name Copy-field validation
 * @description COPY_FIELD must validate source and destination identifiers and bit ranges.
 * @kind problem
 * @problem.severity warning
 * @security-severity 6.5
 * @precision medium
 * @id openflow/copy-field-validation
 * @tags security external/cwe/cwe-20
 */
import rust
import OpenFlow

from ProjectFunction function
where function.getName().getText() = "parse_copy_field" and
  not functionHasCall(function, "validate_copy_field") and
  function.getFile().getAbsolutePath().matches("%/protocol/action.rs")
select function, "Validate COPY_FIELD identifiers, offsets, widths, and reserved bytes."

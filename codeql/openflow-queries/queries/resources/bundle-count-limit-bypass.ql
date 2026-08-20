/**
 * @name Bundle count limit bypass
 * @description The number of simultaneously open bundles must be bounded.
 * @kind problem
 * @problem.severity warning
 * @security-severity 7.5
 * @precision medium
 * @id openflow/bundle-count-limit-bypass
 * @tags security external/cwe/cwe-770
 */
import rust
import OpenFlow

from ProjectFunction function
where function.getName().getText() = "handle_bundle_open" and
  functionHasCall(function, "insert") and
  functionHasCall(function, "len") and
  not functionHasField(function, "max_open_bundles") and
  not functionHasCall(function, "max_open_bundles")
select function, "Enforce the maximum open-bundle count before insertion."

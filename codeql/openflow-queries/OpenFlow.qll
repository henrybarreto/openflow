/** Shared predicates for the repository's CodeQL queries. */

import rust

/** A call made by primary source code rather than a library. */
class ProjectCall extends Call {
  ProjectCall() { this.fromSource() and not isTestFile(this) }
}

/** A function declared by primary source code. */
class ProjectFunction extends Function {
  ProjectFunction() { this.fromSource() and not isTestFile(this) }
}

/** Holds when a source call resolves to the requested short target name. */
predicate calls(ProjectCall call, string name) {
  call.getTargetName() = name
}

/** Holds when a source function has the requested name. */
predicate functions(ProjectFunction function, string name) {
  function.getName().getText() = name
}

/** Holds when an element belongs to the project's Rust source tree. */
predicate isProjectRust(AstNode node) {
  node.fromSource() and
  not isTestFile(node) and
  node.getFile().getAbsolutePath().matches("%/src/%.rs")
}

/** Holds when an element is in a separate Rust test source file. */
predicate isTestFile(AstNode node) {
  node.getFile().getAbsolutePath().matches("%/tests.rs") or
  node.getFile().getAbsolutePath().matches("%/tests_coverage.rs")
}

/** Holds for the repository's inline TLS test functions. */
predicate isInlineTestFunction(Function function) {
  function.getName().getText().matches("tls_%")
}

predicate inProtocol(AstNode node) {
  isProjectRust(node) and node.getFile().getAbsolutePath().matches("%/src/protocol/%.rs")
}

predicate inController(AstNode node) {
  isProjectRust(node) and node.getFile().getAbsolutePath().matches("%/src/controller/%.rs")
}

predicate inClient(AstNode node) {
  isProjectRust(node) and node.getFile().getAbsolutePath().matches("%/src/client/%.rs")
}

predicate inTls(AstNode node) {
  isProjectRust(node) and node.getFile().getAbsolutePath().matches("%/src/tls.rs")
}

/** Holds when a source function contains a call to the requested target. */
predicate functionHasCall(ProjectFunction function, string name) {
  exists(ProjectCall call |
    call.getEnclosingCallable() = function and
    call.getTargetName() = name
  )
}

/** Holds when a source function calls a target that contains the requested call. */
predicate functionHasCallThroughTarget(ProjectFunction function, string target, string name) {
  exists(ProjectCall call, ProjectFunction targetFunction |
    call.getEnclosingCallable() = function and
    call.getTargetName() = target and
    call.getStaticTarget() = targetFunction and
    functionHasCall(targetFunction, name)
  )
}

/** Holds when a source function reads a field with the requested name. */
predicate functionHasField(ProjectFunction function, string name) {
  exists(FieldExpr field |
    field.getEnclosingCallable() = function and
    field.getIdentifier().getText() = name
  )
}

/** Holds when a source function contains the requested macro invocation. */
predicate functionHasMacro(ProjectFunction function, string name) {
  exists(MacroCall macro |
    macro.fromSource() and
    macro.getEnclosingCallable() = function and
    macro.getPath().toAbbreviatedString() = name
  )
}

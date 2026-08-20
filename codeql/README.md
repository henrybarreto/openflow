# CodeQL Analysis

This directory contains the repository's custom CodeQL security analysis.

## Layout

- `openflow-queries/` contains the shared Rust model, 58 queries, and the
  `openflow-security.qls` suite.
- `openflow-tests/` contains the query-test pack and its fixtures.
- `openflow-tests/query-tests/all/` runs the complete suite.
- `openflow-tests/query-tests/smoke/` runs a smaller set for quick checks.

The fixture source intentionally contains vulnerable patterns. The expected
results in the `.expected` files are part of the tests, not findings from the
production source.

## Prerequisites

Install the CodeQL CLI with Rust support and ensure `cargo` is available. Run
the commands below from the repository root.

## Query Tests

Install the pack dependencies:

```sh
codeql pack install -- codeql/openflow-queries
codeql pack install --additional-packs=codeql/openflow-queries -- codeql/openflow-tests
```

Run the complete fixture suite:

```sh
codeql test run --search-path codeql codeql/openflow-tests/query-tests/all
```

Run the smoke suite:

```sh
codeql test run --search-path codeql codeql/openflow-tests/query-tests/smoke
```

## Source Analysis

For a production-source scan, build a CodeQL database from a source-only
checkout or temporary source tree. Exclude `codeql/` and `.codeql/` so fixture
vulnerabilities and generated artifacts are not analyzed as production code.

Store the database and SARIF output under `.codeql/`; those generated files are
ignored by the repository. The checked analysis output is
`.codeql/openflow-remediated.sarif`.

## Generated Files

Do not commit generated CodeQL artifacts such as `codeql-pack.lock.yml`, test
`.actual` files, `codeql-database.yml`, `.testproj/` directories, or fixture
`target/` and `Cargo.lock` files. Authored queries, suites, fixtures, and
`.expected` results should remain under version control.

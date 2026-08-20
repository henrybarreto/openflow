#!/bin/sh
# Run the custom query regression suite and scan the production crate locally.
set -eu

if ! command -v codeql >/dev/null 2>&1; then
    printf '%s\n' 'CodeQL CLI is required; install it with Rust support first.' >&2
    exit 1
fi

repo_root=$(git rev-parse --show-toplevel)
cd "$repo_root"

database_path=${CODEQL_DATABASE:-.codeql/openflow-database}
sarif_path=${CODEQL_SARIF:-.codeql/openflow.sarif}

mkdir -p .codeql
codeql pack install -- codeql/openflow-queries
codeql pack install --additional-packs=codeql/openflow-queries -- codeql/openflow-tests
codeql test run --additional-packs=codeql/openflow-queries --search-path=codeql \
    codeql/openflow-tests/query-tests/all
codeql database create "$database_path" --overwrite --language=rust --command='cargo build --all-features'
codeql database analyze "$database_path" codeql/openflow-queries/suites/openflow-security.qls \
    --format=sarif-latest --output="$sarif_path"

printf 'CodeQL SARIF written to %s\n' "$sarif_path"

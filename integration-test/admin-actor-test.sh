#!/usr/bin/env bash
# End-to-end guard on the admin actor surface through the vs-admin CLI
# (zipline#33, A4). The sibling Rust tests in vs/src/admin_service.rs
# (e2e_actor_guard) pin the same two assertions over a raw HTTPS client;
# this script drives them through vs-admin so the CLI end of the wire is
# exercised too:
#
#   1. `vs-admin actors` lists the OIDC-only connected actor by its ZPR
#      address, with a null cn.
#   2. `vs-admin actors --addr <that address>` returns the descriptor
#      carrying the actor's user.* attributes.
#
# The server side is the ignored launcher test serve_admin_for_cli_harness
# (same fixture as the Rust guard: FakeDb assembly, on-disk vsapikey-format
# keys file, real rustls admin server, real OIDC-only connect). No ValKey,
# no root, no netns, no docker — deliberately, matching the rest of this
# suite (the real `vs` binary hard-requires ValKey in main.rs, so this
# harness assembles the service in-process instead).
set -euo pipefail

REPO_ROOT=$(realpath "$(dirname "$0")/..")
VS_ADMIN_BIN="$REPO_ROOT/target/debug/vs-admin"

cd "$REPO_ROOT"

# vs-admin is not built by `cargo test`; make sure the binary is current.
cargo build -p vs-admin --quiet

# Compile the harness's test binary now, so the 120 s wait for harness.json
# below times the server start only. On a cold CI cache the compile alone can
# exceed it (seen on macOS after a Cargo.lock change).
cargo test -p vs --bin vs --no-run --quiet

HARNESS_DIR=$(mktemp -d)
HARNESS_PID=""

cleanup() {
    # Ask the launcher to exit, then wait for it so cargo's lock is released.
    touch "$HARNESS_DIR/stop" 2>/dev/null || true
    if [[ -n "$HARNESS_PID" ]]; then
        wait "$HARNESS_PID" 2>/dev/null || true
    fi
    rm -rf "$HARNESS_DIR"
}
trap cleanup EXIT

echo "STARTING ADMIN SERVER HARNESS (serve_admin_for_cli_harness)"
ZPR_E2E_HARNESS_DIR="$HARNESS_DIR" \
    cargo test -p vs --bin vs --quiet \
    admin_service::e2e_actor_guard::serve_admin_for_cli_harness \
    -- --ignored --exact >/dev/null &
HARNESS_PID=$!

# The launcher writes harness.json only after the server answers requests.
for _ in $(seq 1 120); do
    [[ -f "$HARNESS_DIR/harness.json" ]] && break
    if ! kill -0 "$HARNESS_PID" 2>/dev/null; then
        echo "FAIL: harness launcher exited before serving" >&2
        exit 1
    fi
    sleep 1
done
if [[ ! -f "$HARNESS_DIR/harness.json" ]]; then
    echo "FAIL: harness.json never appeared in $HARNESS_DIR" >&2
    exit 1
fi

BASE_URL=$(jq -r .base_url "$HARNESS_DIR/harness.json")
ACTOR_ADDR=$(jq -r .actor_addr "$HARNESS_DIR/harness.json")
jq -r .api_key "$HARNESS_DIR/harness.json" > "$HARNESS_DIR/apikey"

VSADMIN=("$VS_ADMIN_BIN" --svc-url "$BASE_URL"
    --ca-cert "$HARNESS_DIR/admin-tls-cert.pem"
    --api-key-file "$HARNESS_DIR/apikey" --format compact)

echo "TESTING vs-admin actors: CN-LESS ACTOR LISTED BY ZPR ADDRESS, NULL CN"
"${VSADMIN[@]}" actors 2>/dev/null | jq -e --arg addr "$ACTOR_ADDR" \
    'map(select(.zpr_addr == $addr)) | length == 1 and .[0].cn == null' \
    >/dev/null
echo "TEST OK"

echo "TESTING vs-admin actors --addr: DESCRIPTOR CARRIES user.* ATTRIBUTES"
"${VSADMIN[@]}" actors --addr "$ACTOR_ADDR" 2>/dev/null \
    | jq -e --arg addr "$ACTOR_ADDR" \
        '.zpr_addr == $addr
         and .cn == null
         and ([.attrs[] | select(.key | startswith("user."))] | length > 0)
         and ([.attrs[] | select(.key == "user.oidc-subject")] | length == 1)' \
        >/dev/null
echo "TEST OK"

echo "ALL ADMIN ACTOR TESTS PASSED"

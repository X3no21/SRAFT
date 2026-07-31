#!/usr/bin/env bash
#
# Generates the TLS material required by the mTLS and MQTTS baselines.
#
# It writes exactly the three files that are embedded into the firmware binary
# (see EMBED_TXTFILES in main/CMakeLists.txt) and that scripts/mqtts/
# setup_mqtts_broker.sh installs on the broker:
#
#     main/certs/ca.crt      test CA certificate
#     main/certs/device.crt  device/broker certificate signed by that CA
#     main/certs/device.key  matching private key
#
# The CA private key stays in scripts/tls/ca/ and is never copied into the
# firmware tree. Both scripts/tls/ca/ and scripts/tls/certs/ are gitignored.
#
# The firmware disables common-name verification on both baselines, so a single
# certificate is shared by every node and by the broker. The per-node mode below
# is kept only for experiments that re-enable hostname checking.
#
# Usage:
#   ./generate_certs.sh                    CA + the three files above
#   ./generate_certs.sh --per-node         also one certificate per subnet host
#   CN=192.168.1.125 ./generate_certs.sh   override the certificate subject
#
# Environment overrides: CN, SUBNET, CA_DAYS, LEAF_DAYS
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

FIRMWARE_CERTS="$REPO_ROOT/main/certs"
CA_DIR="$SCRIPT_DIR/ca"
NODE_DIR_BASE="$SCRIPT_DIR/certs"

CN="${CN:-192.168.1.125}"
SUBNET="${SUBNET:-192.168.1}"
CA_DAYS="${CA_DAYS:-3650}"
LEAF_DAYS="${LEAF_DAYS:-825}"

PER_NODE=0
[ "${1:-}" = "--per-node" ] && PER_NODE=1

command -v openssl >/dev/null 2>&1 || { echo "error: openssl not found in PATH" >&2; exit 1; }

# Git Bash / MSYS on Windows rewrites arguments that look like absolute POSIX
# paths, mangling "/CN=..." into "C:/Program Files/Git/CN=...". A leading double
# slash suppresses that conversion and is stripped before openssl sees it.
case "$(uname -s)" in
    MINGW*|MSYS*|CYGWIN*) SUBJ_PREFIX="//" ;;
    *)                    SUBJ_PREFIX="/"  ;;
esac

mkdir -p "$FIRMWARE_CERTS" "$CA_DIR"

san_for() {
    if [[ "$1" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then echo "IP:$1"; else echo "DNS:$1"; fi
}

issue_leaf() {
    local cn="$1" out_key="$2" out_crt="$3" tmp
    tmp="$(mktemp -d)"
    trap 'rm -rf "$tmp"' RETURN

    openssl genrsa -out "$out_key" 2048 2>/dev/null
    openssl req -new -key "$out_key" -out "$tmp/req.csr" -subj "${SUBJ_PREFIX}CN=$cn"

    cat > "$tmp/ext.cnf" <<EOF
basicConstraints = CA:FALSE
keyUsage = digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth, clientAuth
subjectAltName = $(san_for "$cn")
EOF

    openssl x509 -req -in "$tmp/req.csr" \
        -CA "$CA_DIR/ca.crt" -CAkey "$CA_DIR/ca.key" -CAcreateserial \
        -out "$out_crt" -days "$LEAF_DAYS" -sha256 -extfile "$tmp/ext.cnf" 2>/dev/null
}

# --- 1. Certificate Authority (reused if already present) ---------------------
if [ -f "$CA_DIR/ca.key" ] && [ -f "$CA_DIR/ca.crt" ]; then
    echo "==> Reusing existing CA in $CA_DIR"
else
    echo "==> Creating Certificate Authority"
    openssl genrsa -out "$CA_DIR/ca.key" 4096 2>/dev/null
    openssl req -new -x509 -days "$CA_DAYS" -key "$CA_DIR/ca.key" \
        -out "$CA_DIR/ca.crt" -subj "${SUBJ_PREFIX}CN=SRAFT Test CA"
fi

# --- 2. The triple embedded into the firmware ---------------------------------
echo "==> Issuing device certificate (CN=$CN)"
issue_leaf "$CN" "$FIRMWARE_CERTS/device.key" "$FIRMWARE_CERTS/device.crt"
cp "$CA_DIR/ca.crt" "$FIRMWARE_CERTS/ca.crt"

# --- 3. Optional per-node certificates ----------------------------------------
if [ "$PER_NODE" -eq 1 ]; then
    echo "==> Issuing per-node certificates for ${SUBNET}.1-254"
    for i in $(seq 1 254); do
        node_dir="$NODE_DIR_BASE/node_${SUBNET}.${i}"
        mkdir -p "$node_dir"
        issue_leaf "${SUBNET}.${i}" "$node_dir/node.key" "$node_dir/node.crt"
    done
fi

echo
echo "Written for the firmware build:"
for f in ca.crt device.crt device.key; do
    printf '  %s\n' "$FIRMWARE_CERTS/$f"
done
echo
echo "Rebuild and reflash so the new material is embedded:  idf.py build flash"
echo "WARNING: main/certs/ now holds real key material - do not commit it."

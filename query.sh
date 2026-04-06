#!/usr/bin/env bash
# query.sh — issue a malicious-packages DNS lookup
#
# Usage:
#   ./query.sh <ecosystem> <package> <version> [server]
#   ./query.sh npm lodash 4.17.11
#   ./query.sh pypi requests 2.28.0 127.0.0.1:5353
#
# Requires: dig, python3 (for base32 encoding)
#
# Exit codes: 0 = clean, 1 = malicious, 2 = error

set -euo pipefail

if [[ $# -lt 3 ]]; then
  echo "Usage: $0 <ecosystem> <package> <version> [server:port]" >&2
  exit 2
fi

ECOSYSTEM=$(echo "$1" | tr '[:upper:]' '[:lower:]')
PACKAGE=$(echo "$2" | tr '[:upper:]' '[:lower:]')
VERSION="$3"
SERVER="${4:-127.0.0.1:5353}"

# Split server into host and port for dig
SERVER_HOST="${SERVER%:*}"
SERVER_PORT="${SERVER##*:}"
if [[ "$SERVER_HOST" == "$SERVER" ]]; then
  SERVER_PORT=53
fi

# Build labels using the same encoding as the Go server:
#   verLabel  = base32(version_string)          no padding, lowercase alphabet
#   pkgLabel  = base32(sha256(eco:name)[:8])    no padding, lowercase alphabet
#
# Python's base32 uses uppercase A-Z + 2-7; we need lowercase a-z + 2-7 (same bits, different chars).
# tr handles the case mapping after encoding.

VER_LABEL=$(python3 -c "
import base64, sys
ver = sys.argv[1].encode()
print(base64.b32encode(ver).decode().lower().rstrip('='))
" "$VERSION")

PKG_LABEL=$(python3 -c "
import base64, hashlib, sys
eco, name = sys.argv[1], sys.argv[2]
raw = (eco + ':' + name).lower().encode()
digest = hashlib.sha256(raw).digest()[:8]
print(base64.b32encode(digest).decode().lower().rstrip('='))
" "$ECOSYSTEM" "$PACKAGE")

ZONE="maliciouspackages.org"
V_NAME="${VER_LABEL}.${PKG_LABEL}.v.${ZONE}."
P_NAME="${PKG_LABEL}.p.${ZONE}."

dig_query() {
  local qname="$1"
  dig +short +timeout=3 +tries=1 @"${SERVER_HOST}" -p "${SERVER_PORT}" "$qname" A TXT 2>/dev/null
}

echo "ecosystem : $ECOSYSTEM"
echo "package   : $PACKAGE"
echo "version   : $VERSION"
echo "server    : $SERVER"
echo "v-query   : $V_NAME"
echo "p-query   : $P_NAME"
echo ""

V_RESULT=$(dig_query "$V_NAME")
if [[ -n "$V_RESULT" ]]; then
  echo "MALICIOUS (version match)"
  echo "$V_RESULT"
  exit 1
fi

P_RESULT=$(dig_query "$P_NAME")
if [[ -n "$P_RESULT" ]]; then
  echo "MALICIOUS (package match)"
  echo "$P_RESULT"
  exit 1
fi

echo "CLEAN"
exit 0

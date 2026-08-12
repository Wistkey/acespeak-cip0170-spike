#!/usr/bin/env bash
#
# One-command demo.
#
# Verifies the published attestation against the committed KEL, then proves the
# verifier actually rejects tampering. Needs a Blockfrost key for the first
# check (it reads the transaction back off preprod); the tamper checks are
# entirely offline.
#
#   ./scripts/demo.sh
#
set -euo pipefail

cd "$(dirname "$0")/.."

ATTEST_TX="${ATTEST_TX:-$(python3 -c 'import json;print(json.load(open("artifacts/attest.json"))["txHash"])' 2>/dev/null || true)}"

if [ -z "${ATTEST_TX}" ]; then
    echo "No attestation recorded yet. Run: npm run attest"
    exit 1
fi

echo "=============================================================="
echo " 1. The real attestation should be VALID"
echo "=============================================================="
npx tsx src/verify.ts "${ATTEST_TX}"

echo
echo "=============================================================="
echo " 2. A tampered credential should be INVALID"
echo "=============================================================="
if npx tsx test/tamper-demo.ts; then
    echo "TAMPER CHECK FAILED — the verifier accepted an altered credential."
    exit 1
fi

echo
echo "All checks behaved as expected."

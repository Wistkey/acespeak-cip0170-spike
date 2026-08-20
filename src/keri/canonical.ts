/**
 * Canonical ordering for data that round-trips through Cardano metadata.
 *
 * WHY THIS EXISTS — found the hard way, on a real preprod transaction.
 *
 * A SAID is a digest over a serialisation, so it depends on key order. The
 * on-chain CBOR faithfully preserves whatever order you submitted — but almost
 * nobody reads raw CBOR. Verifiers read a JSON indexer API, and those are built
 * on cardano-db-sync, which stores metadata in PostgreSQL `jsonb`. jsonb
 * normalises object keys by length first, then bytewise. So submit
 * `{d, credentialType, schemaVersion, issuedAt, ...}` and the API hands back
 * `{d, issuedAt, holderRef, schemaVersion, credentialType, ...}`.
 *
 * So a digest computed over the issuer's key order cannot be re-derived from
 * what a verifier reads back, and verification fails on a payload nobody
 * touched. CIP-0170 does not mention this: it says `d` is "the digest of the
 * data being signed" without fixing a canonical form. See READINESS.md.
 *
 * The fix is to digest a canonical form, so the answer does not depend on how
 * any particular reader renders the map. We adopt jsonb's ordering because it
 * is what the common APIs already return, making the round trip a no-op.
 */

const utf8 = new TextEncoder();

/** CBOR canonical map ordering: shorter encoded keys first, then bytewise. */
function compareKeys(a: string, b: string): number {
    const ka = utf8.encode(a);
    const kb = utf8.encode(b);
    if (ka.length !== kb.length) return ka.length - kb.length;

    for (let n = 0; n < ka.length; n++) {
        if (ka[n] !== kb[n]) return ka[n]! - kb[n]!;
    }
    return 0;
}

/**
 * Recursively reorder object keys into canonical CBOR order.
 *
 * Arrays keep their order — sequence is meaningful there, and CBOR preserves it.
 */
export function canonicalise<T>(value: T): T {
    if (Array.isArray(value)) {
        return value.map((item) => canonicalise(item)) as unknown as T;
    }
    if (value === null || typeof value !== 'object') return value;

    const source = value as Record<string, unknown>;
    const out: Record<string, unknown> = {};
    for (const key of Object.keys(source).sort(compareKeys)) {
        out[key] = canonicalise(source[key]);
    }
    return out as unknown as T;
}

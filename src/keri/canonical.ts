/**
 * Canonical ordering for data that round-trips through Cardano metadata.
 *
 * WHY THIS EXISTS — found the hard way, on a real preprod transaction.
 *
 * A SAID is a digest over a serialisation, so it depends on key order. Cardano
 * stores transaction metadata as CBOR and returns map keys in canonical CBOR
 * order: sorted by encoded key length first, then bytewise. Submit
 * `{d, credentialType, schemaVersion, issuedAt, ...}` and it comes back as
 * `{d, issuedAt, holderRef, schemaVersion, credentialType, ...}`.
 *
 * So a digest computed over the issuer's key order cannot be re-derived from
 * what a verifier reads back, and verification fails on a payload that was
 * never touched. CIP-0170 does not mention this: it says `d` is "the digest of
 * the data being signed" without fixing a canonical form, and the chain will
 * silently impose one. See READINESS.md.
 *
 * The fix is to adopt the chain's own ordering. Deriving and verifying both
 * canonicalise first, so the round trip is a no-op and the payload comes back
 * in exactly the order it was digested in.
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

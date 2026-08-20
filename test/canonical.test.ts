import { describe, expect, test } from 'vitest';
import { canonicalise } from '../src/keri/canonical.ts';

/**
 * Cardano stores metadata as CBOR and returns map keys in canonical CBOR order:
 * sorted by encoded key length first, then bytewise. Any digest computed over a
 * different key order cannot be re-derived from what the chain gives back.
 */
describe('canonicalise', () => {
    test('orders keys by length, then bytewise — CBOR canonical order', () => {
        const out = canonicalise({
            evidenceDigest: 'e',
            credentialType: 'c',
            schemaVersion: 's',
            holderRef: 'h',
            issuedAt: 'i',
            d: 'd',
        });

        expect(Object.keys(out)).toEqual([
            'd',
            'issuedAt',
            'holderRef',
            'schemaVersion',
            'credentialType',
            'evidenceDigest',
        ]);
    });

    test('is idempotent', () => {
        const once = canonicalise({ bb: 1, a: 2, ccc: 3 });
        expect(Object.keys(canonicalise(once))).toEqual(Object.keys(once));
    });

    test('breaks equal-length ties bytewise', () => {
        expect(Object.keys(canonicalise({ zz: 1, aa: 2 }))).toEqual(['aa', 'zz']);
    });

    test('recurses into nested objects', () => {
        const out = canonicalise({ outer: { bb: 1, a: 2 } }) as { outer: object };
        expect(Object.keys(out.outer)).toEqual(['a', 'bb']);
    });

    test('preserves array order, which is meaningful', () => {
        const out = canonicalise({ list: ['z', 'a', 'm'] }) as { list: string[] };
        expect(out.list).toEqual(['z', 'a', 'm']);
    });

    test('leaves primitives alone', () => {
        expect(canonicalise('x')).toBe('x');
        expect(canonicalise(7)).toBe(7);
        expect(canonicalise(null)).toBe(null);
    });
});

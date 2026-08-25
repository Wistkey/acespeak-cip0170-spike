import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { beforeAll, describe, expect, test } from 'vitest';
import { ready } from 'signify-ts';
import { decodeMetadatum, digestMetadatum, extractMetadatumBytes, metadatumBytes } from '../src/cardano/cbor.ts';

/**
 * Ground truth comes from two independent places: the test vector in
 * cardano-foundation/CIPs#1253, and the bytes of our own published preprod
 * transaction. An encoder that satisfies both is encoding what the spec means
 * AND what the chain actually holds.
 */

// From CIP-0170 PR #1253, "Digest computation" test vector.
const SPEC_VECTOR = { credentialType: 'membership', schemaVersion: 1, issuedAt: '2026-08-20T08:00:00Z' };
const SPEC_CBOR =
    'a36e63726564656e7469616c547970656a6d656d626572736869706d736368656d6156657273696f6e0168697373756564417474323032362d30382d32305430383a30303a30305a';
const SPEC_DIGEST = 'EOpMIJmAaiP4cZgmDkg8rVtl8YU4dDYf_gxrK2sNdfOR';

// The same content in jsonb order, which the spec gives as the WRONG answer.
const JSONB_ORDER = { issuedAt: '2026-08-20T08:00:00Z', schemaVersion: 1, credentialType: 'membership' };
const JSONB_DIGEST = 'EIswjSN1u14y36RGf6TKm-z65R0rMMLjQHnjXofImTmZ';

/** Published before CIP-0170 fixed the digest rule; anchors a JSON-derived SAID. */
const LEGACY_TX = readFileSync(resolve(__dirname, 'fixtures/attest-tx.cbor'), 'utf8').trim();
/** Published against the CBOR rule from cardano-foundation/CIPs#1253. */
const ONCHAIN_TX = readFileSync(resolve(__dirname, 'fixtures/attest-tx-conformant.cbor'), 'utf8').trim();

beforeAll(async () => {
    await ready();
});

describe('metadatumBytes', () => {
    test('reproduces the CIP-0170 PR test vector byte for byte', () => {
        expect(Buffer.from(metadatumBytes(SPEC_VECTOR)).toString('hex')).toBe(SPEC_CBOR);
    });

    test('preserves construction order rather than sorting', () => {
        // The whole point: encoding must not silently reorder, or the digest
        // stops matching what was anchored.
        expect(Buffer.from(metadatumBytes(JSONB_ORDER)).toString('hex')).not.toBe(SPEC_CBOR);
    });

    test('encodes integers, text, arrays and nesting', () => {
        const bytes = metadatumBytes({ n: 1, s: 'x', l: ['a', 'b'], m: { inner: 2 } });
        expect(bytes.length).toBeGreaterThan(0);
    });
});

describe('digestMetadatum', () => {
    test('gives the digest the spec states for the correct byte order', () => {
        expect(digestMetadatum(metadatumBytes(SPEC_VECTOR))).toBe(SPEC_DIGEST);
    });

    test('gives the spec\'s documented WRONG digest for jsonb order', () => {
        // Reproducing the spec's negative case proves we fail the same way an
        // indexer-reading verifier would, rather than by accident.
        expect(digestMetadatum(metadatumBytes(JSONB_ORDER))).toBe(JSONB_DIGEST);
    });

    test('is a CESR qb64 Blake3-256 primitive', () => {
        expect(digestMetadatum(metadatumBytes(SPEC_VECTOR))).toMatch(/^E[A-Za-z0-9_-]{43}$/);
    });
});

describe('extractMetadatumBytes, against our published transaction', () => {
    test('finds the CIP-0170 label', () => {
        expect(extractMetadatumBytes(ONCHAIN_TX, 170).length).toBeGreaterThan(0);
    });

    test('finds the application label', () => {
        expect(extractMetadatumBytes(ONCHAIN_TX, 170170).length).toBeGreaterThan(0);
    });

    test('throws for a label the transaction does not carry', () => {
        expect(() => extractMetadatumBytes(ONCHAIN_TX, 674)).toThrow(/674/);
    });

    test.each([170, 170170])(
        'decoding and re-encoding label %i reproduces the on-chain bytes exactly',
        (label) => {
            // The load-bearing check: our encoder must agree with the transaction
            // builder byte for byte. If it does not, a digest computed before
            // building is anchored against bytes that never reach the chain — and
            // the KEL anchor cannot be taken back.
            const onchain = extractMetadatumBytes(ONCHAIN_TX, label);
            const roundTripped = metadatumBytes(decodeMetadatum(onchain));

            expect(Buffer.from(roundTripped).toString('hex')).toBe(Buffer.from(onchain).toString('hex'));
        }
    );

    test('the conformant transaction digests to exactly what it attested', () => {
        const body = decodeMetadatum(extractMetadatumBytes(ONCHAIN_TX, 170)) as { d: string };

        expect(digestMetadatum(extractMetadatumBytes(ONCHAIN_TX, 170170))).toBe(body.d);
    });

    test('the pre-rule transaction does not, and never can', () => {
        // Real evidence rather than a synthetic case: this is on preprod, it looks
        // well-formed, and it is permanently unverifiable because it anchored a
        // digest over a JSON serialisation instead of the on-chain bytes.
        const body = decodeMetadatum(extractMetadatumBytes(LEGACY_TX, 170)) as { d: string };

        expect(digestMetadatum(extractMetadatumBytes(LEGACY_TX, 170170))).not.toBe(body.d);
    });
});

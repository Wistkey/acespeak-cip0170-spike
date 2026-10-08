import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { beforeAll, describe, expect, test } from 'vitest';
import { ready } from 'signify-ts';
import { verifyAttestation } from '../src/verify.ts';
import { buildAttest, CIP0170_LABEL } from '../src/cardano/metadata.ts';
import { fromMetadatumBytes, metadatumBytes } from '../src/cardano/cbor.ts';
import { ACESPEAK_METADATA_LABEL } from '../src/config.ts';

const artifact = (name: string) => resolve(__dirname, '../artifacts', name);

const KEL = readFileSync(artifact('issuer-kel.cesr'), 'utf8');
const CREDENTIAL = JSON.parse(readFileSync(artifact('credential.json'), 'utf8'));
const ANCHOR = JSON.parse(readFileSync(artifact('anchor.json'), 'utf8')) as {
    i: string;
    d: string;
    s: string;
};

/**
 * A metadatum source equivalent to what the chain holds.
 *
 * Built from real CBOR bytes rather than a JSON object, because that is the
 * only thing the verifier will accept — CIP-0170 forbids verifying from JSON.
 */
function sourceFrom(body: unknown, payload: unknown, appLabel = ACESPEAK_METADATA_LABEL) {
    return fromMetadatumBytes({
        [CIP0170_LABEL]: metadatumBytes(body),
        [appLabel]: metadatumBytes(payload),
    });
}

function attestBody(overrides: Record<string, unknown> = {}) {
    const md = buildAttest({
        signerAid: ANCHOR.i,
        digest: ANCHOR.d,
        sequenceNumber: ANCHOR.s,
        appLabel: ACESPEAK_METADATA_LABEL,
        appData: CREDENTIAL,
    }) as Record<string, Record<string, unknown>>;
    return { ...md[String(CIP0170_LABEL)]!, ...overrides };
}

/** The attestation exactly as it is on-chain. */
function validSource() {
    return sourceFrom(attestBody(), CREDENTIAL);
}

beforeAll(async () => {
    await ready();
});

describe('verifyAttestation, against the real anchored credential', () => {
    test('returns valid', () => {
        const result = verifyAttestation({ source: validSource(), kel: KEL });

        expect(result.reason).toBeUndefined();
        expect(result.valid).toBe(true);
    });

    test('reports the signer, digest and sequence it verified', () => {
        const result = verifyAttestation({ source: validSource(), kel: KEL });

        expect(result.attestation).toMatchObject({ i: ANCHOR.i, d: ANCHOR.d, s: ANCHOR.s });
    });

    test('every individual check passes', () => {
        const result = verifyAttestation({ source: validSource(), kel: KEL });

        expect(result.checks.filter((c) => !c.ok)).toEqual([]);
    });

    test('accepts a matching expected AID', () => {
        const result = verifyAttestation({ source: validSource(), kel: KEL, expectedAid: ANCHOR.i });

        expect(result.valid).toBe(true);
    });

    test('rejects an AID other than the one the caller expected', () => {
        const result = verifyAttestation({
            source: validSource(),
            kel: KEL,
            expectedAid: 'ENotTheIssuerAtAll',
        });

        expect(result.valid).toBe(false);
        expect(result.reason).toMatch(/expected/i);
    });
});

describe('verifyAttestation rejects tampering', () => {
    test('rejects an altered credential field', () => {
        // The learner promotes themselves after issuance.
        const result = verifyAttestation({
            source: sourceFrom(attestBody(), { ...CREDENTIAL, credentialType: 'NativeSpeaker' }),
            kel: KEL,
        });

        expect(result.valid).toBe(false);
        expect(result.reason).toMatch(/digest/i);
    });

    test('rejects a digest that is not anchored in the KEL', () => {
        const result = verifyAttestation({
            source: sourceFrom(attestBody({ d: 'EGzobgWt3CAfs5SOqmGk5BXmHQlOmO4PH08OiBYIlcDX' }), CREDENTIAL),
            kel: KEL,
        });

        expect(result.valid).toBe(false);
    });

    test('rejects a sequence number with no matching event', () => {
        const result = verifyAttestation({ source: sourceFrom(attestBody({ s: 'ff' }), CREDENTIAL), kel: KEL });

        expect(result.valid).toBe(false);
        expect(result.reason).toMatch(/sequence/i);
    });

    test('rejects a digest anchored at a different sequence number than claimed', () => {
        // inception anchors nothing
        const result = verifyAttestation({ source: sourceFrom(attestBody({ s: '0' }), CREDENTIAL), kel: KEL });

        expect(result.valid).toBe(false);
        expect(result.reason).toMatch(/seal|anchor/i);
    });

    test('rejects a KEL belonging to a different identifier', () => {
        const result = verifyAttestation({
            source: sourceFrom(attestBody({ i: 'EKtQ1lymrnrh3qv5S18PBzQ7ukHGFJ7EXkH7B22XEMIL' }), CREDENTIAL),
            kel: KEL,
        });

        expect(result.valid).toBe(false);
        expect(result.reason).toMatch(/identifier|KEL/i);
    });

    test('rejects a KEL whose event chain was edited', () => {
        const tamperedKel = KEL.replace(/"p":"E[A-Za-z0-9_-]{43}"/, '"p":"EAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"');

        const result = verifyAttestation({ source: validSource(), kel: tamperedKel });

        expect(result.valid).toBe(false);
    });
});

describe('verifyAttestation rejects malformed metadata', () => {
    test('rejects metadata with no label 170', () => {
        const result = verifyAttestation({
            source: fromMetadatumBytes({ 674: metadatumBytes({ msg: 'hello' }) }),
            kel: KEL,
        });

        expect(result.valid).toBe(false);
        expect(result.reason).toMatch(/170/);
    });

    test('rejects a CIP-0170 transaction that is not an ATTEST', () => {
        const result = verifyAttestation({
            source: sourceFrom({ t: 'AUTH_BEGIN', i: ANCHOR.i, s: 'E...', c: [], v: { v: '1.0' } }, CREDENTIAL),
            kel: KEL,
        });

        expect(result.valid).toBe(false);
        expect(result.reason).toMatch(/ATTEST/);
    });

    test('rejects an ATTEST missing its digest', () => {
        const body = attestBody();
        delete body.d;

        const result = verifyAttestation({ source: sourceFrom(body, CREDENTIAL), kel: KEL });

        expect(result.valid).toBe(false);
    });

    test('rejects an unsupported CIP version', () => {
        const result = verifyAttestation({ source: sourceFrom(attestBody({ v: { v: '2.0' } }), CREDENTIAL), kel: KEL });

        expect(result.valid).toBe(false);
        expect(result.reason).toMatch(/version/i);
    });

    test('reads an ATTEST without v as version 1.0, as CIP-0170 1.1 specifies', () => {
        const body = attestBody();
        delete body.v;

        const result = verifyAttestation({ source: sourceFrom(body, CREDENTIAL), kel: KEL });

        expect(result.valid).toBe(true);
        expect(result.checks.find((c) => c.name === 'CIP version is supported')?.detail).toBe('1.0 (v absent)');
    });

    test('rejects a malformed v rather than reading it as absent', () => {
        const result = verifyAttestation({ source: sourceFrom(attestBody({ v: '1.0' }), CREDENTIAL), kel: KEL });

        expect(result.valid).toBe(false);
        expect(result.reason).toMatch(/version/i);
    });

    test('rejects a 1.1 ATTEST, whose anchor may be a metadata seal this verifier cannot check', () => {
        const result = verifyAttestation({ source: sourceFrom(attestBody({ v: { v: '1.1' } }), CREDENTIAL), kel: KEL });

        expect(result.valid).toBe(false);
        expect(result.reason).toMatch(/version "1\.1"/);
    });

    test('rejects an attestation whose application payload is missing', () => {
        const result = verifyAttestation({
            source: fromMetadatumBytes({ [CIP0170_LABEL]: metadatumBytes(attestBody()) }),
            kel: KEL,
        });

        expect(result.valid).toBe(false);
        expect(result.reason).toMatch(/payload|application/i);
    });

    test('rejects an empty KEL', () => {
        const result = verifyAttestation({ source: validSource(), kel: '' });

        expect(result.valid).toBe(false);
    });
});

describe('digesting on-chain bytes rather than a JSON view', () => {
    /**
     * The regression a live preprod transaction caught: a payload with the same
     * content in a different key order is a different byte string, and CIP-0170
     * digests bytes. So reordering MUST change the verdict — that is the whole
     * point of the spec's rule, not a bug.
     */
    test('rejects the same content in a different key order', () => {
        const reordered: Record<string, unknown> = {};
        for (const key of Object.keys(CREDENTIAL).reverse()) reordered[key] = CREDENTIAL[key];

        const result = verifyAttestation({ source: sourceFrom(attestBody(), reordered), kel: KEL });

        expect(result.valid).toBe(false);
        expect(result.reason).toMatch(/digests to/i);
    });

    test('accepts the exact bytes that were attested', () => {
        expect(verifyAttestation({ source: validSource(), kel: KEL }).valid).toBe(true);
    });
});

import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { beforeAll, describe, expect, test } from 'vitest';
import { ready } from 'signify-ts';
import { verifyAttestation } from '../src/verify.ts';
import { buildAttest } from '../src/cardano/metadata.ts';
import { ACESPEAK_METADATA_LABEL } from '../src/config.ts';

const artifact = (name: string) => resolve(__dirname, '../artifacts', name);

const KEL = readFileSync(artifact('issuer-kel.cesr'), 'utf8');
const CREDENTIAL = JSON.parse(readFileSync(artifact('credential.json'), 'utf8'));
const ANCHOR = JSON.parse(readFileSync(artifact('anchor.json'), 'utf8')) as {
    i: string;
    d: string;
    s: string;
};

/** The metadata exactly as it is submitted on-chain. */
function validMetadata() {
    return buildAttest({
        signerAid: ANCHOR.i,
        digest: ANCHOR.d,
        sequenceNumber: ANCHOR.s,
        appLabel: ACESPEAK_METADATA_LABEL,
        appData: CREDENTIAL,
    });
}

beforeAll(async () => {
    await ready();
});

describe('verifyAttestation, against the real anchored credential', () => {
    test('returns valid', () => {
        const result = verifyAttestation({ metadata: validMetadata(), kel: KEL });

        expect(result.reason).toBeUndefined();
        expect(result.valid).toBe(true);
    });

    test('reports the signer, digest and sequence it verified', () => {
        const result = verifyAttestation({ metadata: validMetadata(), kel: KEL });

        expect(result.attestation).toMatchObject({ i: ANCHOR.i, d: ANCHOR.d, s: ANCHOR.s });
    });

    test('every individual check passes', () => {
        const result = verifyAttestation({ metadata: validMetadata(), kel: KEL });

        expect(result.checks.filter((c) => !c.ok)).toEqual([]);
    });

    test('accepts a matching expected AID', () => {
        const result = verifyAttestation({ metadata: validMetadata(), kel: KEL, expectedAid: ANCHOR.i });

        expect(result.valid).toBe(true);
    });

    test('rejects an AID other than the one the caller expected', () => {
        const result = verifyAttestation({
            metadata: validMetadata(),
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
        const metadata = validMetadata() as Record<string, unknown>;
        metadata[String(ACESPEAK_METADATA_LABEL)] = {
            ...CREDENTIAL,
            credentialType: 'NativeSpeaker',
        };

        const result = verifyAttestation({ metadata, kel: KEL });

        expect(result.valid).toBe(false);
        expect(result.reason).toMatch(/digest|said/i);
    });

    test('rejects a digest that is not anchored in the KEL', () => {
        const metadata = validMetadata() as Record<string, Record<string, unknown>>;
        metadata['170']!.d = 'EGzobgWt3CAfs5SOqmGk5BXmHQlOmO4PH08OiBYIlcDX';

        const result = verifyAttestation({ metadata, kel: KEL });

        expect(result.valid).toBe(false);
    });

    test('rejects a sequence number with no matching event', () => {
        const metadata = validMetadata() as Record<string, Record<string, unknown>>;
        metadata['170']!.s = 'ff';

        const result = verifyAttestation({ metadata, kel: KEL });

        expect(result.valid).toBe(false);
        expect(result.reason).toMatch(/sequence/i);
    });

    test('rejects a digest anchored at a different sequence number than claimed', () => {
        const metadata = validMetadata() as Record<string, Record<string, unknown>>;
        metadata['170']!.s = '0'; // inception anchors nothing

        const result = verifyAttestation({ metadata, kel: KEL });

        expect(result.valid).toBe(false);
        expect(result.reason).toMatch(/seal|anchor/i);
    });

    test('rejects a KEL belonging to a different identifier', () => {
        const metadata = validMetadata() as Record<string, Record<string, unknown>>;
        metadata['170']!.i = 'EKtQ1lymrnrh3qv5S18PBzQ7ukHGFJ7EXkH7B22XEMIL';

        const result = verifyAttestation({ metadata, kel: KEL });

        expect(result.valid).toBe(false);
        expect(result.reason).toMatch(/identifier|KEL/i);
    });

    test('rejects a KEL whose event chain was edited', () => {
        const tamperedKel = KEL.replace(/"p":"E[A-Za-z0-9_-]{43}"/, '"p":"EAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"');

        const result = verifyAttestation({ metadata: validMetadata(), kel: tamperedKel });

        expect(result.valid).toBe(false);
    });
});

describe('verifyAttestation rejects malformed metadata', () => {
    test('rejects metadata with no label 170', () => {
        const result = verifyAttestation({ metadata: { '674': { msg: 'hello' } }, kel: KEL });

        expect(result.valid).toBe(false);
        expect(result.reason).toMatch(/170/);
    });

    test('rejects a CIP-0170 transaction that is not an ATTEST', () => {
        const result = verifyAttestation({
            metadata: { '170': { t: 'AUTH_BEGIN', i: ANCHOR.i, s: 'E...', c: [], v: { v: '1.0' } } },
            kel: KEL,
        });

        expect(result.valid).toBe(false);
        expect(result.reason).toMatch(/ATTEST/);
    });

    test('rejects an ATTEST missing its digest', () => {
        const metadata = validMetadata() as Record<string, Record<string, unknown>>;
        delete metadata['170']!.d;

        const result = verifyAttestation({ metadata, kel: KEL });

        expect(result.valid).toBe(false);
    });

    test('rejects an unsupported CIP version', () => {
        const metadata = validMetadata() as Record<string, Record<string, unknown>>;
        metadata['170']!.v = { v: '2.0' };

        const result = verifyAttestation({ metadata, kel: KEL });

        expect(result.valid).toBe(false);
        expect(result.reason).toMatch(/version/i);
    });

    test('rejects an attestation whose application payload is missing', () => {
        const metadata = validMetadata() as Record<string, unknown>;
        delete metadata[String(ACESPEAK_METADATA_LABEL)];

        const result = verifyAttestation({ metadata, kel: KEL });

        expect(result.valid).toBe(false);
        expect(result.reason).toMatch(/payload|application/i);
    });

    test('rejects an empty KEL', () => {
        const result = verifyAttestation({ metadata: validMetadata(), kel: '' });

        expect(result.valid).toBe(false);
    });
});

describe('round-tripping through Cardano metadata', () => {
    /**
     * The regression that a live preprod transaction caught and an emulator
     * rehearsal did not: Cardano returns metadata map keys in canonical CBOR
     * order, not the order they were submitted in. A digest computed over the
     * issuer's ordering cannot be re-derived from what a verifier reads back.
     */
    test('accepts a payload whose keys come back reordered by the chain', () => {
        const metadata = validMetadata() as Record<string, unknown>;
        const payload = metadata[String(ACESPEAK_METADATA_LABEL)] as Record<string, unknown>;

        // Reverse the key order, as hostile to the original as possible.
        const reordered: Record<string, unknown> = {};
        for (const key of Object.keys(payload).reverse()) reordered[key] = payload[key];
        metadata[String(ACESPEAK_METADATA_LABEL)] = reordered;

        const result = verifyAttestation({ metadata, kel: KEL });

        expect(result.reason).toBeUndefined();
        expect(result.valid).toBe(true);
    });

    test('still rejects an altered value, not merely a reordered one', () => {
        const metadata = validMetadata() as Record<string, unknown>;
        const payload = metadata[String(ACESPEAK_METADATA_LABEL)] as Record<string, unknown>;
        const reordered: Record<string, unknown> = { credentialType: 'NativeSpeaker' };
        for (const key of Object.keys(payload).reverse()) {
            if (key !== 'credentialType') reordered[key] = payload[key];
        }
        metadata[String(ACESPEAK_METADATA_LABEL)] = reordered;

        expect(verifyAttestation({ metadata, kel: KEL }).valid).toBe(false);
    });
});

import { describe, expect, test } from 'vitest';
import {
    ACDC_VERSION,
    assertMetadataValid,
    buildAttest,
    buildAuthBegin,
    chunk64,
    CIP0170_LABEL,
    CIP_VERSION,
    KERI_VERSION,
    MetadataStringTooLongError,
    toHexSequence,
    unchunk64,
} from '../src/cardano/metadata.ts';

// Values lifted verbatim from the CIP-0170 worked example so that a spec change
// breaks this test rather than sailing through unnoticed.
// https://github.com/cardano-foundation/CIPs/tree/master/CIP-0170
const SPEC_AID = 'EKtQ1lymrnrh3qv5S18PBzQ7ukHGFJ7EXkH7B22XEMIL';
const SPEC_DIGEST = 'ELC5L3iBVD77d_MYbYGGCUQgqQBju1o4x1Ud-z2sL-ux';
const SPEC_SCHEMA = 'EJVgEQO8BEhGGM7GcAjlqoKG1upeuBZj9WjvjZo353sQ';
const SPEC_LABEL = 1447;

describe('constants', () => {
    test('uses the metadata label and version strings the CIP fixes', () => {
        expect(CIP0170_LABEL).toBe(170);
        expect(CIP_VERSION).toBe('1.0');
        expect(KERI_VERSION).toBe('KERI10');
        expect(ACDC_VERSION).toBe('ACDC10');
    });
});

describe('toHexSequence', () => {
    test('encodes the 26th event as "1a", matching the spec example', () => {
        expect(toHexSequence(26)).toBe('1a');
    });

    test('encodes zero as "0", not an empty string', () => {
        expect(toHexSequence(0)).toBe('0');
    });

    test('passes through a string that is already hex', () => {
        expect(toHexSequence('1a')).toBe('1a');
    });

    test('rejects a negative sequence number', () => {
        expect(() => toHexSequence(-1)).toThrow(/sequence/i);
    });

    test('rejects a non-hex string', () => {
        expect(() => toHexSequence('zz')).toThrow(/hex/i);
    });
});

describe('buildAttest', () => {
    test('reproduces the CIP-0170 ATTEST example exactly', () => {
        const md = buildAttest({
            signerAid: SPEC_AID,
            digest: SPEC_DIGEST,
            sequenceNumber: 26,
            appLabel: SPEC_LABEL,
            appData: 'someApplicationMetadata',
        });

        expect(md).toEqual({
            '170': {
                t: 'ATTEST',
                i: SPEC_AID,
                d: SPEC_DIGEST,
                s: '1a',
                v: { v: '1.0' },
            },
            '1447': 'someApplicationMetadata',
        });
    });

    test('omits KERI and ACDC versions, which ATTEST does not carry', () => {
        const md = buildAttest({
            signerAid: SPEC_AID,
            digest: SPEC_DIGEST,
            sequenceNumber: 1,
            appLabel: SPEC_LABEL,
            appData: 'x',
        }) as Record<string, { v: Record<string, string> }>;

        expect(Object.keys(md['170']!.v)).toEqual(['v']);
    });

    test('carries a structured application payload at the sibling label', () => {
        const credential = { d: SPEC_DIGEST, credentialType: 'InterviewReady' };
        const md = buildAttest({
            signerAid: SPEC_AID,
            digest: SPEC_DIGEST,
            sequenceNumber: 3,
            appLabel: SPEC_LABEL,
            appData: credential,
        }) as Record<string, unknown>;

        expect(md['1447']).toEqual(credential);
    });
});

describe('buildAuthBegin', () => {
    test('reproduces the CIP-0170 AUTH_BEGIN example, chunking the credential chain', () => {
        const md = buildAuthBegin({
            signerAid: SPEC_AID,
            schemaSaid: SPEC_SCHEMA,
            chain: 'short-chain',
            extra: { l: [SPEC_LABEL], LEI: '50670047U83746F70E20' },
        });

        expect(md).toEqual({
            '170': {
                t: 'AUTH_BEGIN',
                s: SPEC_SCHEMA,
                i: SPEC_AID,
                c: ['short-chain'],
                v: { v: '1.0', k: 'KERI10', a: 'ACDC10' },
                m: { l: [SPEC_LABEL], LEI: '50670047U83746F70E20' },
            },
        });
    });

    test('omits the optional metadata block when no extra is supplied', () => {
        const md = buildAuthBegin({
            signerAid: SPEC_AID,
            schemaSaid: SPEC_SCHEMA,
            chain: 'c',
        }) as Record<string, Record<string, unknown>>;

        expect(md['170']).not.toHaveProperty('m');
    });
});

describe('chunk64', () => {
    test('leaves a string that already fits as a single chunk', () => {
        expect(chunk64('abc')).toEqual(['abc']);
    });

    test('splits a 200-character stream into 64-byte chunks', () => {
        const stream = 'A'.repeat(200);
        const chunks = chunk64(stream);

        expect(chunks).toEqual(['A'.repeat(64), 'A'.repeat(64), 'A'.repeat(64), 'A'.repeat(8)]);
    });

    test('never emits a chunk longer than 64 bytes for multi-byte input', () => {
        // 'é' is two bytes in UTF-8, so a naive per-character split would emit
        // 128-byte chunks and the node would be rejected at submission.
        const chunks = chunk64('é'.repeat(100));

        for (const c of chunks) {
            expect(new TextEncoder().encode(c).length).toBeLessThanOrEqual(64);
        }
    });

    test('round-trips through unchunk64', () => {
        const stream = 'x'.repeat(150) + 'é'.repeat(30);
        expect(unchunk64(chunk64(stream))).toBe(stream);
    });
});

describe('assertMetadataValid', () => {
    test('accepts metadata whose strings all fit', () => {
        expect(() =>
            assertMetadataValid(
                buildAttest({
                    signerAid: SPEC_AID,
                    digest: SPEC_DIGEST,
                    sequenceNumber: 26,
                    appLabel: SPEC_LABEL,
                    appData: { credentialType: 'InterviewReady' },
                })
            )
        ).not.toThrow();
    });

    test('rejects an over-long string nested inside the application payload', () => {
        const md = buildAttest({
            signerAid: SPEC_AID,
            digest: SPEC_DIGEST,
            sequenceNumber: 26,
            appLabel: SPEC_LABEL,
            appData: { note: 'z'.repeat(65) },
        });

        expect(() => assertMetadataValid(md)).toThrow(MetadataStringTooLongError);
    });

    test('names the offending path so the failure is diagnosable', () => {
        const md = buildAttest({
            signerAid: SPEC_AID,
            digest: SPEC_DIGEST,
            sequenceNumber: 26,
            appLabel: SPEC_LABEL,
            appData: { note: 'z'.repeat(65) },
        });

        expect(() => assertMetadataValid(md)).toThrow(/1447\.note/);
    });

    test('rejects an over-long string measured in bytes, not characters', () => {
        // 40 characters, 80 bytes — a character-counting check would pass this.
        const md = buildAttest({
            signerAid: SPEC_AID,
            digest: SPEC_DIGEST,
            sequenceNumber: 26,
            appLabel: SPEC_LABEL,
            appData: 'é'.repeat(40),
        });

        expect(() => assertMetadataValid(md)).toThrow(MetadataStringTooLongError);
    });

    test('accepts chunked chains, which is the point of chunking them', () => {
        const md = buildAuthBegin({
            signerAid: SPEC_AID,
            schemaSaid: SPEC_SCHEMA,
            chain: 'A'.repeat(5000),
        });

        expect(() => assertMetadataValid(md)).not.toThrow();
    });
});

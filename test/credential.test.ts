import { beforeAll, describe, expect, test } from 'vitest';
import { ready } from 'signify-ts';
import {
    buildCredential,
    DisallowedFieldError,
    opaqueHolderRef,
    verifyCredentialSaid,
    type SpeakingPassportClaim,
} from '../src/keri/credential.ts';

const CLAIM: SpeakingPassportClaim = {
    credentialType: 'InterviewReady',
    schemaVersion: '1.0.0',
    issuedAt: '2026-08-14T00:00:00Z',
    holderRef: 'HxsBhAcE0DBHAqQzB3ldEHVJEeCM8dJUyGmkxD5kLBEQ',
    evidenceDigest: 'ELC5L3iBVD77d_MYbYGGCUQgqQBju1o4x1Ud-z2sL-ux',
};

beforeAll(async () => {
    await ready();
});

describe('buildCredential', () => {
    test('gives the credential a self-addressing identifier', () => {
        const cred = buildCredential(CLAIM);

        expect(cred.d).toMatch(/^E[A-Za-z0-9_-]{43}$/);
    });

    test('is deterministic — the same claim always yields the same SAID', () => {
        expect(buildCredential(CLAIM).d).toBe(buildCredential({ ...CLAIM }).d);
    });

    test('changing any field changes the SAID', () => {
        const other = buildCredential({ ...CLAIM, credentialType: 'ConversationFluent' });

        expect(other.d).not.toBe(buildCredential(CLAIM).d);
    });

    test('preserves every claim field alongside the SAID', () => {
        const cred = buildCredential(CLAIM);

        expect(cred).toMatchObject(CLAIM);
    });

    test('keeps every field within the 64-byte metadata limit', () => {
        const cred = buildCredential(CLAIM);

        for (const value of Object.values(cred)) {
            expect(new TextEncoder().encode(String(value)).length).toBeLessThanOrEqual(64);
        }
    });
});

describe('buildCredential privacy guard', () => {
    // Section 4 of the pilot plan says no personal data, transcript, video or
    // raw score goes on-chain. This payload IS the on-chain payload now, so the
    // guard belongs in code rather than in a review checklist.
    test.each(['email', 'name', 'transcript', 'score', 'videoUrl', 'dateOfBirth'])(
        'refuses to build a credential carrying a %s field',
        (field) => {
            const claim = { ...CLAIM, [field]: 'anything' } as SpeakingPassportClaim;

            expect(() => buildCredential(claim)).toThrow(DisallowedFieldError);
        }
    );

    test('names the offending field', () => {
        const claim = { ...CLAIM, email: 'a@b.c' } as SpeakingPassportClaim;

        expect(() => buildCredential(claim)).toThrow(/email/);
    });
});

describe('verifyCredentialSaid', () => {
    test('accepts a credential built by buildCredential', () => {
        expect(verifyCredentialSaid(buildCredential(CLAIM))).toBe(true);
    });

    test('rejects a credential whose content was altered after SAIDing', () => {
        const tampered = { ...buildCredential(CLAIM), credentialType: 'NativeSpeaker' };

        expect(verifyCredentialSaid(tampered)).toBe(false);
    });

    test('rejects a credential with no SAID at all', () => {
        expect(verifyCredentialSaid({ ...CLAIM } as never)).toBe(false);
    });
});

describe('opaqueHolderRef', () => {
    test('produces a CESR digest rather than the identifier itself', () => {
        const ref = opaqueHolderRef('user-4471', 'a-secret-salt');

        expect(ref).toMatch(/^E[A-Za-z0-9_-]{43}$/);
        expect(ref).not.toContain('4471');
    });

    test('is stable for the same user and salt', () => {
        expect(opaqueHolderRef('user-4471', 'salt')).toBe(opaqueHolderRef('user-4471', 'salt'));
    });

    test('differs for different users', () => {
        expect(opaqueHolderRef('user-1', 'salt')).not.toBe(opaqueHolderRef('user-2', 'salt'));
    });

    test('differs across salts, so one leaked mapping does not unmask the rest', () => {
        expect(opaqueHolderRef('user-1', 'salt-a')).not.toBe(opaqueHolderRef('user-1', 'salt-b'));
    });
});

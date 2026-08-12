/**
 * The Speaking Passport credential payload — a draft of the open Communication
 * Credential Profile.
 *
 * This object is what goes on-chain, under the application metadata label that
 * sits beside label 170 in an ATTEST transaction. CIP-0170's own worked example
 * computes `d` as the digest of that sibling payload, so keeping the payload
 * on-chain makes an attestation verifiable from a transaction hash alone.
 *
 * Because it is public and permanent, section 4 of the pilot plan applies with
 * full force: no video, no transcript, no personal information, no raw score.
 * {@link buildCredential} enforces that rather than trusting a checklist.
 */
import { Diger, MtrDex, Saider } from 'signify-ts';

export interface SpeakingPassportClaim {
    /** The credential being asserted, e.g. `InterviewReady`. */
    credentialType: string;
    /** Version of the Communication Credential Profile this follows. */
    schemaVersion: string;
    /** ISO-8601 issue time. */
    issuedAt: string;
    /** Opaque, non-identifying reference to the holder. See {@link opaqueHolderRef}. */
    holderRef: string;
    /** CESR digest of the private assessment record, which stays off-chain. */
    evidenceDigest: string;
}

export interface SpeakingPassportCredential extends SpeakingPassportClaim {
    /** Self-addressing identifier over the whole payload. */
    d: string;
}

const ALLOWED_FIELDS: ReadonlySet<string> = new Set([
    'credentialType',
    'schemaVersion',
    'issuedAt',
    'holderRef',
    'evidenceDigest',
]);

export class DisallowedFieldError extends Error {
    constructor(readonly field: string) {
        super(
            `field "${field}" is not part of the Communication Credential Profile and must not be published on-chain`
        );
        this.name = 'DisallowedFieldError';
    }
}

/**
 * Build a SAIDified credential from a claim.
 *
 * The returned `d` is the payload's own self-addressing identifier, computed by
 * KERI's standard algorithm: blank the `d` field to a placeholder of the right
 * length, serialise, digest. That is what makes the ATTEST digest unambiguous —
 * a verifier recomputes it from the on-chain payload with no shared convention
 * to agree on beyond KERI itself.
 *
 * `ready()` from signify-ts must have been awaited before calling this.
 */
export function buildCredential(claim: SpeakingPassportClaim): SpeakingPassportCredential {
    for (const field of Object.keys(claim)) {
        if (!ALLOWED_FIELDS.has(field)) throw new DisallowedFieldError(field);
    }

    // Fixed key order so the SAID depends on the claim, not on how the caller
    // happened to build the object.
    const sad = {
        d: '',
        credentialType: claim.credentialType,
        schemaVersion: claim.schemaVersion,
        issuedAt: claim.issuedAt,
        holderRef: claim.holderRef,
        evidenceDigest: claim.evidenceDigest,
    };

    const [, saidified] = Saider.saidify(sad);
    return saidified as unknown as SpeakingPassportCredential;
}

/**
 * Recompute the SAID and confirm it still matches the payload.
 *
 * This is the tamper check: alter any field after issuance and the SAID no
 * longer derives, so the digest anchored in the issuer's KEL no longer matches.
 */
export function verifyCredentialSaid(credential: SpeakingPassportCredential): boolean {
    if (typeof credential?.d !== 'string' || credential.d === '') return false;

    try {
        const [, recomputed] = Saider.saidify({ ...credential, d: '' });
        return (recomputed as { d: string }).d === credential.d;
    } catch {
        return false;
    }
}

/**
 * Derive an opaque holder reference from an internal user identifier.
 *
 * Salted so that the on-chain reference cannot be reversed by digesting a guess
 * at the user id, and so that a leak of one deployment's mapping does not
 * unmask another's. The salt stays in AceSpeak's private configuration.
 */
export function opaqueHolderRef(userId: string, salt: string): string {
    const ser = new TextEncoder().encode(`${salt}:${userId}`);
    return new Diger({ code: MtrDex.Blake3_256 }, ser).qb64;
}

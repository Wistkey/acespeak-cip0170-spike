/**
 * CIP-0170 transaction metadata builders.
 *
 * Spec: https://github.com/cardano-foundation/CIPs/tree/master/CIP-0170
 *
 * Two things the spec leaves open that this module has to decide. Both are
 * written up in READINESS.md rather than buried here:
 *
 *  1. Cardano caps every metadata string at 64 bytes, but CIP-0170 1.0 showed
 *     the credential chain `c` as one `{{byteStream}}`. A real chain is far
 *     longer, so it has to be split. CIP-0170 1.1 (CIPs#1287) settled it: an
 *     ordered list of byte strings of at most 64 bytes each. We first used text
 *     chunks; the AUTH_BEGIN at 123c5d18… is still on chain in that form.
 *  2. The spec says `d` is "the CESR digest of the data" without fixing a
 *     canonical serialisation. We sidestep the ambiguity by SAIDifying the
 *     application payload, so `d` is the payload's own self-addressing
 *     identifier and any verifier recomputes it the same way. See src/keri/credential.ts.
 */

/** The metadata label CIP-0170 fixes for itself. */
export const CIP0170_LABEL = 170;

/** Version strings, from the CIP's worked example. */
export const CIP_VERSION = '1.0';
export const KERI_VERSION = 'KERI10';
export const ACDC_VERSION = 'ACDC10';

/** Cardano rejects any metadata text string longer than this many bytes. */
export const METADATA_STRING_LIMIT = 64;

export class MetadataStringTooLongError extends Error {
    constructor(
        readonly path: string,
        readonly byteLength: number
    ) {
        super(
            `metadata string at ${path} is ${byteLength} bytes, over the ${METADATA_STRING_LIMIT}-byte Cardano limit`
        );
        this.name = 'MetadataStringTooLongError';
    }
}

const utf8 = new TextEncoder();

function byteLength(s: string): number {
    return utf8.encode(s).length;
}

/**
 * Encode a KEL sequence number the way CIP-0170 expects: lowercase hex with no
 * `0x` prefix. The spec's example renders the 26th event as `"1a"`.
 *
 * Already-hex strings pass through, so a sequence number read straight out of a
 * KERI event (where `s` is already hex) can be handed over unchanged.
 */
export function toHexSequence(sequenceNumber: number | string): string {
    if (typeof sequenceNumber === 'string') {
        if (!/^[0-9a-f]+$/i.test(sequenceNumber)) {
            throw new Error(`sequence number "${sequenceNumber}" is not lowercase hex`);
        }
        return sequenceNumber.toLowerCase();
    }
    if (!Number.isInteger(sequenceNumber) || sequenceNumber < 0) {
        throw new Error(`sequence number must be a non-negative integer, got ${sequenceNumber}`);
    }
    return sequenceNumber.toString(16);
}

/**
 * Split a byte stream into chunks of at most 64 bytes, in order.
 *
 * The chunks are Uint8Arrays, which Lucid encodes as CBOR byte strings: CIP-0170
 * types `c` as bytes, and a schema-validating indexer rejects text chunks.
 */
export function chunk64(stream: Uint8Array): Uint8Array[] {
    const chunks: Uint8Array[] = [];
    for (let at = 0; at < stream.length; at += METADATA_STRING_LIMIT) {
        chunks.push(stream.slice(at, at + METADATA_STRING_LIMIT));
    }
    return chunks.length > 0 ? chunks : [new Uint8Array(0)];
}

/** Inverse of {@link chunk64}. */
export function unchunk64(chunks: readonly Uint8Array[]): Uint8Array {
    const out = new Uint8Array(chunks.reduce((n, c) => n + c.length, 0));
    let at = 0;
    for (const c of chunks) {
        out.set(c, at);
        at += c.length;
    }
    return out;
}

export interface AttestArgs {
    /** The signer's AID in CESR qb64 — AceSpeak's issuer identifier. */
    signerAid: string;
    /** CESR qb64 digest of the data being signed. */
    digest: string;
    /** Sequence number of the KEL event anchoring the digest as a seal. */
    sequenceNumber: number | string;
    /** Label the application payload sits under, alongside label 170. */
    appLabel: number;
    /** The application payload itself. */
    appData: unknown;
}

/**
 * Build an `ATTEST` transaction metadata object.
 *
 * Note what this function does *not* take: a wallet, a key, a signature. The
 * signer's authority lives entirely in the KEL seal that `digest` and
 * `sequenceNumber` point at, which is why anyone at all can pay for and submit
 * the resulting transaction while `i` still names AceSpeak.
 */
export function buildAttest(args: AttestArgs): Record<string, unknown> {
    const { signerAid, digest, sequenceNumber, appLabel, appData } = args;

    return {
        [String(CIP0170_LABEL)]: {
            t: 'ATTEST',
            i: signerAid,
            d: digest,
            s: toHexSequence(sequenceNumber),
            v: { v: CIP_VERSION },
        },
        [String(appLabel)]: appData,
    };
}

export interface AuthArgs {
    signerAid: string;
    /** SAID of the leaf credential's schema. */
    schemaSaid: string;
    /** CESR stream of the credential chain (or revocation events for AUTH_END). */
    chain: string;
    /** Optional `m` block, used for indexing. */
    extra?: Record<string, unknown>;
}

function buildAuth(type: 'AUTH_BEGIN' | 'AUTH_END', args: AuthArgs): Record<string, unknown> {
    const { signerAid, schemaSaid, chain, extra } = args;

    const body: Record<string, unknown> = {
        t: type,
        s: schemaSaid,
        i: signerAid,
        // The qb64b variant: the CESR text stream's UTF-8 bytes.
        c: chunk64(utf8.encode(chain)),
        v: { v: CIP_VERSION, k: KERI_VERSION, a: ACDC_VERSION },
    };
    if (extra !== undefined) body.m = extra;

    return { [String(CIP0170_LABEL)]: body };
}

/** Build an `AUTH_BEGIN` transaction, publishing the issuer's credential chain. */
export function buildAuthBegin(args: AuthArgs): Record<string, unknown> {
    return buildAuth('AUTH_BEGIN', args);
}

/** Build an `AUTH_END` transaction, revoking signing authority. */
export function buildAuthEnd(args: AuthArgs): Record<string, unknown> {
    return buildAuth('AUTH_END', args);
}

/**
 * Walk a metadata object and throw on the first text or byte string over the 64-byte limit.
 *
 * Call this before every submission. Blockfrost's rejection message for an
 * oversized node is not obviously about string length, so failing here with a
 * path is worth the traversal.
 */
export function assertMetadataValid(metadata: unknown, path = ''): void {
    if (typeof metadata === 'string') {
        const len = byteLength(metadata);
        if (len > METADATA_STRING_LIMIT) {
            throw new MetadataStringTooLongError(path || '<root>', len);
        }
        return;
    }
    if (metadata instanceof Uint8Array) {
        if (metadata.length > METADATA_STRING_LIMIT) {
            throw new MetadataStringTooLongError(path || '<root>', metadata.length);
        }
        return;
    }
    if (Array.isArray(metadata)) {
        metadata.forEach((item, i) => assertMetadataValid(item, `${path}[${i}]`));
        return;
    }
    if (metadata !== null && typeof metadata === 'object') {
        for (const [key, value] of Object.entries(metadata)) {
            assertMetadataValid(value, path ? `${path}.${key}` : key);
        }
    }
}

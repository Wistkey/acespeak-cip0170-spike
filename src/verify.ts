/**
 * Verify a CIP-0170 ATTEST attestation.
 *
 * This is the seed of the public verifier promised in section 6 of the pilot
 * plan, built as the real thing in miniature. It answers exactly the question
 * the CIP poses:
 *
 *   > If the KEL of identifier `i` contains an event at sequence number `s`
 *   > with a seal value of `{ d: "<digest>" }`, it serves as cryptographically
 *   > verifiable proof.
 *
 * WHAT THIS VERIFIES
 *   - the transaction carries a well-formed CIP-0170 ATTEST at label 170
 *   - the CBOR bytes of the application payload digest to the attested `d`
 *   - the KEL is internally consistent and belongs to `i`
 *   - the event at sequence `s` anchors `{ d }` as a seal
 *
 * It works from raw metadatum bytes, never a JSON view. CIP-0170 forbids
 * recomputing `d` from JSON, because indexers normalise map key order at write
 * time and destroy the information the digest depends on. The API takes a
 * MetadatumSource precisely so there is no way to pass JSON in by mistake.
 *
 * WHAT THIS DOES NOT VERIFY
 *   - the controller's signatures on the KEL events (see READINESS.md)
 *   - that `i` holds signing authority for the label — that needs the
 *     AUTH_BEGIN credential chain and an ACDC verifier
 *
 * Nothing here needs the transaction's signature or its payer. That is the
 * point of the spike: `i` names AceSpeak while anyone at all pays the fee.
 */
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
import { ready } from 'signify-ts';
import { CIP0170_LABEL, CIP_VERSION } from './cardano/metadata.ts';
import { decodeMetadatum, digestMetadatum, type MetadatumSource } from './cardano/cbor.ts';
import { findEventBySequence, hasDigestSeal, parseKel, verifyKelLinkage } from './keri/kel.ts';

export interface Check {
    name: string;
    ok: boolean;
    detail?: string;
}

export interface VerificationResult {
    valid: boolean;
    /** Why it failed. Absent when valid. */
    reason?: string;
    checks: Check[];
    attestation?: { t: string; i: string; d: string; s: string };
}

export interface VerifyOptions {
    /** Raw metadatum bytes, keyed by label. Never a JSON representation. */
    source: MetadatumSource;
    /** The issuer's KEL as a CESR stream. */
    kel: string;
    /** Optionally require the attestation to carry a particular AID. */
    expectedAid?: string;
}

interface AttestBody {
    t?: unknown;
    i?: unknown;
    d?: unknown;
    s?: unknown;
    v?: unknown;
}

function isRecord(value: unknown): value is Record<string, unknown> {
    return value !== null && typeof value === 'object' && !Array.isArray(value);
}

export function verifyAttestation(options: VerifyOptions): VerificationResult {
    const { source, kel, expectedAid } = options;
    const checks: Check[] = [];

    const fail = (reason: string): VerificationResult => ({ valid: false, reason, checks });

    const add = (name: string, ok: boolean, detail?: string): boolean => {
        checks.push({ name, ok, detail });
        return ok;
    };

    // ---- 1. The transaction carries a CIP-0170 ATTEST ----------------------
    const cipBytes = source.bytes(CIP0170_LABEL);
    if (cipBytes === undefined) {
        add('metadata carries label 170', false);
        return fail(`transaction has no CIP-0170 metadata at label ${CIP0170_LABEL}`);
    }

    let body: unknown;
    try {
        body = decodeMetadatum(cipBytes);
    } catch {
        add('metadata carries label 170', false);
        return fail('CIP-0170 metadatum at label 170 could not be decoded');
    }
    if (!isRecord(body)) {
        add('metadata carries label 170', false);
        return fail('CIP-0170 metadatum at label 170 is not a map');
    }
    add('metadata carries label 170', true);

    const attest = body as AttestBody;

    if (!add('transaction type is ATTEST', attest.t === 'ATTEST', String(attest.t))) {
        return fail(`CIP-0170 transaction type is "${String(attest.t)}", not ATTEST`);
    }

    const i = attest.i;
    const d = attest.d;
    const s = attest.s;

    if (typeof i !== 'string' || typeof d !== 'string' || typeof s !== 'string') {
        add('ATTEST carries i, d and s', false);
        return fail('ATTEST is missing one of the required fields i, d or s');
    }
    add('ATTEST carries i, d and s', true);

    const version = isRecord(attest.v) ? attest.v.v : undefined;
    if (!add('CIP version is supported', version === CIP_VERSION, String(version))) {
        return fail(`unsupported CIP-0170 version "${String(version)}", expected ${CIP_VERSION}`);
    }

    const attestation = { t: 'ATTEST', i, d, s };

    if (expectedAid !== undefined) {
        if (!add('signer is the expected identifier', i === expectedAid, i)) {
            return { valid: false, reason: `attestation carries ${i}, expected ${expectedAid}`, checks, attestation };
        }
    }

    // ---- 2. The application payload's CBOR bytes digest to `d` -------------
    const appLabels = source.labels().filter((label) => label !== CIP0170_LABEL);

    if (appLabels.length === 0) {
        add('application payload is present', false);
        return { valid: false, reason: 'attestation has no application payload beside label 170', checks, attestation };
    }
    if (appLabels.length > 1) {
        add('application payload is present', false, appLabels.join(', '));
        return {
            valid: false,
            reason: `transaction carries ${appLabels.length} application labels (${appLabels.join(', ')}); CIP-0170 requires the attested label to be unambiguous`,
            checks,
            attestation,
        };
    }
    const appLabel = appLabels[0]!;
    add('application payload is present', true, String(appLabel));

    // Digest the bytes as they exist in the transaction. Re-serialising from a
    // decoded value would reintroduce exactly the ambiguity the spec closed.
    const computed = digestMetadatum(source.bytes(appLabel)!);
    if (!add('payload CBOR digests to d', computed === d, computed)) {
        return {
            valid: false,
            reason: `application payload digests to ${computed}, but the attestation claims ${d} — the payload is not the data that was attested`,
            checks,
            attestation,
        };
    }

    // ---- 3. The KEL is intact and belongs to the signer --------------------
    let events;
    try {
        events = parseKel(kel);
    } catch (error) {
        add('KEL parses', false);
        return {
            valid: false,
            reason: `issuer KEL could not be parsed: ${error instanceof Error ? error.message : String(error)}`,
            checks,
            attestation,
        };
    }
    if (!add('KEL parses', events.length > 0, `${events.length} events`)) {
        return { valid: false, reason: 'issuer KEL is empty', checks, attestation };
    }

    const linkage = verifyKelLinkage(events);
    if (!add('KEL chain is intact', linkage.ok, linkage.reason)) {
        return { valid: false, reason: `issuer KEL failed verification: ${linkage.reason}`, checks, attestation };
    }

    if (!add('KEL belongs to the signer', events[0]!.i === i, events[0]!.i)) {
        return {
            valid: false,
            reason: `KEL belongs to identifier ${events[0]!.i}, but the attestation names ${i}`,
            checks,
            attestation,
        };
    }

    // ---- 4. The digest is anchored at the claimed sequence number ----------
    const event = findEventBySequence(events, s);
    if (!add('KEL has an event at sequence s', event !== undefined, s)) {
        return {
            valid: false,
            reason: `issuer KEL has no event at sequence number ${s}`,
            checks,
            attestation,
        };
    }

    if (!add('event at s anchors the digest as a seal', hasDigestSeal(event!, d))) {
        return {
            valid: false,
            reason: `event at sequence ${s} does not anchor a seal { d: "${d}" }`,
            checks,
            attestation,
        };
    }

    return { valid: true, checks, attestation };
}

// ---------------------------------------------------------------------------
// CLI
// ---------------------------------------------------------------------------

const USAGE = `
Verify a CIP-0170 attestation anchored on Cardano preprod.

  npm run verify -- <txHash> [options]

Options:
  --kel <path>    KEL to verify against  (default: artifacts/issuer-kel.cesr)
  --oobi <url>    Fetch the KEL from an OOBI endpoint instead of a file
  --aid <aid>     Require the attestation to carry this identifier
  --json          Emit the result as JSON

Transaction bytes come from Koios with no API key. The default reads the
committed KEL, so verification needs no KERIA running; --oobi proves the same
result against a live witness resolution.

The digest is computed from the transaction's raw CBOR, never a JSON view --
see CIP-0170 "Digest computation".
`;

function parseArgs(argv: string[]): { txHash?: string; options: Record<string, string | boolean> } {
    const options: Record<string, string | boolean> = {};
    let txHash: string | undefined;

    for (let n = 0; n < argv.length; n++) {
        const arg = argv[n]!;
        if (arg === '--json') {
            options.json = true;
        } else if (arg.startsWith('--')) {
            options[arg.slice(2)] = argv[++n] ?? '';
        } else if (txHash === undefined) {
            txHash = arg;
        }
    }
    return { txHash, options };
}

async function main(): Promise<void> {
    const { txHash, options } = parseArgs(process.argv.slice(2));

    if (txHash === undefined) {
        console.error(USAGE);
        process.exit(2);
    }

    await ready();

    // Imported lazily so the pure verifier stays free of any network code.
    const { fetchTransactionCbor } = await import('./cardano/chain.ts');
    const { fromTransactionCbor } = await import('./cardano/cbor.ts');
    const source = fromTransactionCbor(await fetchTransactionCbor(txHash));

    const kel =
        typeof options.oobi === 'string'
            ? await (await fetch(options.oobi)).text()
            : readFileSync(
                  typeof options.kel === 'string'
                      ? options.kel
                      : resolve(process.cwd(), 'artifacts/issuer-kel.cesr'),
                  'utf8'
              );

    const result = verifyAttestation({
        source,
        kel,
        expectedAid: typeof options.aid === 'string' ? options.aid : undefined,
    });

    if (options.json === true) {
        console.log(JSON.stringify({ txHash, ...result }, null, 2));
    } else {
        for (const check of result.checks) {
            const detail = check.detail === undefined ? '' : `  (${check.detail})`;
            console.log(`  ${check.ok ? '✓' : '✗'} ${check.name}${detail}`);
        }
        console.log('');
        if (result.valid) {
            console.log(`VALID — ${result.attestation!.d} is anchored in ${result.attestation!.i} at sequence ${result.attestation!.s}`);
        } else {
            console.log(`INVALID — ${result.reason}`);
        }
    }

    process.exit(result.valid ? 0 : 1);
}

// Only run the CLI when this file is the entry point, so importing the verifier
// from a test or another script does not trigger a network call.
if (process.argv[1] !== undefined && import.meta.url === pathToFileURL(process.argv[1]).href) {
    main().catch((error: unknown) => {
        console.error(error instanceof Error ? error.message : error);
        process.exit(2);
    });
}

import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { beforeAll, describe, expect, test } from 'vitest';
import {
    Emulator,
    generateEmulatorAccount,
    Lucid,
    PROTOCOL_PARAMETERS_DEFAULT,
    type LucidEvolution,
} from '@lucid-evolution/lucid';
import { ready } from 'signify-ts';
import { buildAttest, buildAuthBegin } from '../src/cardano/metadata.ts';
import { submitMetadata } from '../src/cardano/submit.ts';
import { verifyAttestation } from '../src/verify.ts';
import { ACESPEAK_METADATA_LABEL } from '../src/config.ts';

/**
 * A full dress rehearsal of the submission path, on the emulator.
 *
 * The real transactions are blocked on faucet funding, and the submission code
 * had never actually run. Finding a bug in it at submission time — against a
 * deadline, with rate-limited faucet funds — would be an expensive way to
 * discover that `submitMetadata` mis-attaches a label.
 *
 * This exercises the real builders, the real submit function and the real
 * verifier against the real committed artifacts. Everything but the network.
 */

const artifact = (name: string) => resolve(__dirname, '../artifacts', name);

const ANCHOR = JSON.parse(readFileSync(artifact('anchor.json'), 'utf8')) as {
    i: string;
    d: string;
    s: string;
};
const CREDENTIAL = JSON.parse(readFileSync(artifact('credential.json'), 'utf8'));
const KEL = readFileSync(artifact('issuer-kel.cesr'), 'utf8');
const SCHEMA_SAID: string = JSON.parse(
    readFileSync(resolve(__dirname, '../schema/communication-credential-profile.v1.json'), 'utf8')
).$id;

let lucid: LucidEvolution;
let emulator: Emulator;
let payer: string;

/**
 * Submit, then let a block settle.
 *
 * Without this the change UTxO from the previous transaction is still pending
 * and coin selection finds nothing to spend. The real run does not hit this —
 * ATTEST and AUTH_BEGIN come from two different wallets, by design — but the
 * rehearsal drives both from one account.
 */
async function submitAndSettle(metadata: Record<string, unknown>) {
    const result = await submitMetadata(lucid, metadata);
    emulator.awaitBlock(1);
    return result;
}

beforeAll(async () => {
    await ready();
    const account = generateEmulatorAccount({ lovelace: 1_000_000_000n });
    emulator = new Emulator([account], PROTOCOL_PARAMETERS_DEFAULT);
    lucid = await Lucid(emulator, 'Custom');
    lucid.selectWallet.fromSeed(account.seedPhrase);
    payer = account.address;
});

describe('ATTEST submission', () => {
    test('submits and returns a transaction hash', async () => {
        const metadata = buildAttest({
            signerAid: ANCHOR.i,
            digest: ANCHOR.d,
            sequenceNumber: ANCHOR.s,
            appLabel: ACESPEAK_METADATA_LABEL,
            appData: CREDENTIAL,
        });

        const result = await submitAndSettle(metadata);

        expect(result.txHash).toMatch(/^[0-9a-f]{64}$/);
        expect(result.payer).toBe(payer);
        expect(result.fee).toBeGreaterThan(0n);
    });

    test('the submitted metadata verifies as VALID', async () => {
        // What a reviewer will do with the published hash, minus the network.
        const metadata = buildAttest({
            signerAid: ANCHOR.i,
            digest: ANCHOR.d,
            sequenceNumber: ANCHOR.s,
            appLabel: ACESPEAK_METADATA_LABEL,
            appData: CREDENTIAL,
        });
        await submitAndSettle(metadata);

        const result = verifyAttestation({ metadata, kel: KEL, expectedAid: ANCHOR.i });

        expect(result.reason).toBeUndefined();
        expect(result.valid).toBe(true);
    });

    test('refuses metadata with no CIP-0170 body rather than spending a fee', async () => {
        await expect(submitMetadata(lucid, { '674': { msg: 'hello' } })).rejects.toThrow(/170/);
    });

    test('refuses an oversized string rather than letting the node reject it', async () => {
        const metadata = buildAttest({
            signerAid: ANCHOR.i,
            digest: ANCHOR.d,
            sequenceNumber: ANCHOR.s,
            appLabel: ACESPEAK_METADATA_LABEL,
            appData: { note: 'z'.repeat(65) },
        });

        await expect(submitMetadata(lucid, metadata)).rejects.toThrow(/64-byte/);
    });
});

describe('AUTH_BEGIN submission', () => {
    test('submits the chunked credential chain', async () => {
        const metadata = buildAuthBegin({
            signerAid: ANCHOR.i,
            schemaSaid: SCHEMA_SAID,
            chain: readFileSync(artifact('auth-begin-chain.cesr'), 'utf8'),
            extra: { l: [ACESPEAK_METADATA_LABEL] },
        });

        const result = await submitAndSettle(metadata);

        expect(result.txHash).toMatch(/^[0-9a-f]{64}$/);
    });

    test('the real credential chain fits within the transaction size limit', () => {
        const chain = readFileSync(artifact('auth-begin-chain.cesr'), 'utf8');
        const metadata = buildAuthBegin({
            signerAid: ANCHOR.i,
            schemaSaid: SCHEMA_SAID,
            chain,
            extra: { l: [ACESPEAK_METADATA_LABEL] },
        });

        expect(JSON.stringify(metadata).length).toBeLessThan(PROTOCOL_PARAMETERS_DEFAULT.maxTxSize);
    });
});

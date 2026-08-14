import { beforeAll, describe, expect, test } from 'vitest';
import {
    Emulator,
    generateEmulatorAccount,
    Lucid,
    PROTOCOL_PARAMETERS_DEFAULT,
    type LucidEvolution,
} from '@lucid-evolution/lucid';
import { ready } from 'signify-ts';
import { assertMetadataValid, buildAttest, buildAuthBegin } from '../src/cardano/metadata.ts';
import { buildCredential, opaqueHolderRef } from '../src/keri/credential.ts';
import { ACESPEAK_METADATA_LABEL, HOLDER_REF_SALT } from '../src/config.ts';

/**
 * The measured CIP-0170 fee is quoted in the Catalyst application, the pilot
 * plan and the video plan, and it sets the declared usage target — which is
 * final at submission and cannot be revised.
 *
 * So this is not a curiosity test. If a dependency upgrade or a metadata change
 * moves the fee, these assertions fail and someone re-runs the target
 * arithmetic before a stale number reaches a grant reviewer.
 */

const AID = 'ENIjVYIWIcxMekADdujdjlmLt0m8XKDiHVLsAkdRc_o2';

let lucid: LucidEvolution;

async function feeOf(metadata: Record<string, unknown>): Promise<number> {
    assertMetadataValid(metadata);

    let tx = lucid.newTx();
    for (const [label, value] of Object.entries(metadata)) {
        tx = tx.attachMetadata(Number(label), value as never);
    }
    const completed = await tx.complete();
    return Number(completed.toTransaction().body().fee()) / 1_000_000;
}

function attestFor(credentialType: string): Record<string, unknown> {
    const credential = buildCredential({
        credentialType,
        schemaVersion: '1.0.0',
        issuedAt: '2026-08-14T00:00:00Z',
        holderRef: opaqueHolderRef('demo-learner-0001', HOLDER_REF_SALT),
        evidenceDigest: opaqueHolderRef(`evidence-${credentialType}`, HOLDER_REF_SALT),
    });

    return buildAttest({
        signerAid: AID,
        digest: credential.d,
        sequenceNumber: '1',
        appLabel: ACESPEAK_METADATA_LABEL,
        appData: credential,
    });
}

beforeAll(async () => {
    await ready();
    const account = generateEmulatorAccount({ lovelace: 1_000_000_000n });
    lucid = await Lucid(new Emulator([account], PROTOCOL_PARAMETERS_DEFAULT), 'Custom');
    lucid.selectWallet.fromSeed(account.seedPhrase);
});

describe('protocol parameters', () => {
    // Cross-checked against live preprod via Koios at epoch 307. If these move,
    // every fee below moves with them.
    test('match the preprod values the measurements were taken against', () => {
        expect(PROTOCOL_PARAMETERS_DEFAULT.minFeeA).toBe(44);
        expect(PROTOCOL_PARAMETERS_DEFAULT.minFeeB).toBe(155381);
        expect(PROTOCOL_PARAMETERS_DEFAULT.maxTxSize).toBe(16384);
    });
});

describe('counted ATTEST fees', () => {
    test.each([
        'LearnerIdentity',
        'SpeakingBaseline',
        'MonthlyProgress',
        'InterviewReady',
        'PresentationReady',
        'OralCommunication',
        'PitchReady',
    ])('a %s attestation costs the documented 0.1834 ADA', async (credentialType) => {
        const fee = await feeOf(attestFor(credentialType));

        expect(fee).toBeGreaterThan(0.1825);
        expect(fee).toBeLessThan(0.1845);
    });

    test('costs materially less than the 0.20 ADA the application first assumed', async () => {
        expect(await feeOf(attestFor('InterviewReady'))).toBeLessThan(0.2);
    });

    test('500 counted attestations fall short of a 100 ADA target', async () => {
        // The finding that forced the target decision. If this ever stops being
        // true the recommendation in the application answers is stale.
        const delivered = (await feeOf(attestFor('InterviewReady'))) * 500;

        expect(delivered).toBeLessThan(100);
        expect(delivered).toBeGreaterThan(90);
    });
});

describe('AUTH_BEGIN', () => {
    test('the credential chain fits inside one transaction', async () => {
        const metadata = buildAuthBegin({
            signerAid: AID,
            schemaSaid: 'EFbV8Sf-2j4M99YbtStDPL5zkuA8hZNdYsN3ic9XFD3w',
            chain: 'A'.repeat(7260), // the real chain length, from 04-auth-begin
            extra: { l: [ACESPEAK_METADATA_LABEL] },
        });

        await expect(feeOf(metadata)).resolves.toBeLessThan(1);
    });

    test('costs more than an attestation, and is not counted as adoption', async () => {
        const authBegin = await feeOf(
            buildAuthBegin({
                signerAid: AID,
                schemaSaid: 'EFbV8Sf-2j4M99YbtStDPL5zkuA8hZNdYsN3ic9XFD3w',
                chain: 'A'.repeat(7260),
                extra: { l: [ACESPEAK_METADATA_LABEL] },
            })
        );

        expect(authBegin).toBeGreaterThan(await feeOf(attestFor('InterviewReady')));
    });
});

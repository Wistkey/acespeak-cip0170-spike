/**
 * Measure the real network fee of each CIP-0170 event AceSpeak will emit.
 *
 * The Catalyst application currently assumes "about 0.20 ADA per representative
 * CIP-0170 event". That assumption sets the declared usage target, and the
 * target is final at submission — so it is worth measuring rather than guessing.
 *
 * Transactions are built and balanced against Lucid's emulator using preprod
 * protocol parameters. The fee a node charges is a deterministic function of
 * transaction size: fee = minFeeA * size + minFeeB. No node discretion, no
 * network variance. So a fully-built, balanced transaction gives the real fee
 * without spending anything.
 *
 * The emulator's defaults were checked field by field against live preprod via
 * Koios (epoch 307): minFeeA 44, minFeeB 155381, maxTxSize 16384,
 * coinsPerUtxoByte 4310, priceMem 0.0577, priceStep 0.0000721.
 *
 *   npx tsx scripts/measure-fees.ts
 */
import { writeFileSync } from 'node:fs';
import { resolve } from 'node:path';
import {
    Emulator,
    generateEmulatorAccount,
    Lucid,
    PROTOCOL_PARAMETERS_DEFAULT,
    type LucidEvolution,
} from '@lucid-evolution/lucid';
import { ready } from 'signify-ts';
import { assertMetadataValid, buildAttest, buildAuthBegin } from '../src/cardano/metadata.ts';
import { buildCredential, opaqueHolderRef, type SpeakingPassportClaim } from '../src/keri/credential.ts';
import { ACESPEAK_METADATA_LABEL, HOLDER_REF_SALT } from '../src/config.ts';

const AID = 'ENIjVYIWIcxMekADdujdjlmLt0m8XKDiHVLsAkdRc_o2';
const SEQ = '1';

/** A representative ATTEST for one product event. */
function attestFor(credentialType: string, sequence: string): Record<string, unknown> {
    const claim: SpeakingPassportClaim = {
        credentialType,
        schemaVersion: '1.0.0',
        issuedAt: '2026-08-14T00:00:00Z',
        holderRef: opaqueHolderRef('demo-learner-0001', HOLDER_REF_SALT),
        evidenceDigest: opaqueHolderRef(`evidence-${credentialType}`, HOLDER_REF_SALT),
    };
    const credential = buildCredential(claim);

    return buildAttest({
        signerAid: AID,
        digest: credential.d,
        sequenceNumber: sequence,
        appLabel: ACESPEAK_METADATA_LABEL,
        appData: credential,
    });
}

interface Measurement {
    event: string;
    counts: boolean;
    metadataBytes: number;
    txBytes: number;
    feeLovelace: number;
    feeAda: number;
}

async function measure(
    lucid: LucidEvolution,
    event: string,
    counts: boolean,
    metadata: Record<string, unknown>
): Promise<Measurement> {
    assertMetadataValid(metadata);

    let tx = lucid.newTx();
    for (const [label, value] of Object.entries(metadata)) {
        tx = tx.attachMetadata(Number(label), value as never);
    }

    const completed = await tx.complete();
    const cbor = completed.toCBOR();
    const feeLovelace = Number(completed.toTransaction().body().fee());

    return {
        event,
        counts,
        metadataBytes: JSON.stringify(metadata).length,
        txBytes: cbor.length / 2, // hex-encoded
        feeLovelace,
        feeAda: feeLovelace / 1_000_000,
    };
}

async function main(): Promise<void> {
    await ready();

    const account = generateEmulatorAccount({ lovelace: 1_000_000_000n });
    const emulator = new Emulator([account], PROTOCOL_PARAMETERS_DEFAULT);
    const lucid = await Lucid(emulator, 'Custom');
    lucid.selectWallet.fromSeed(account.seedPhrase);

    const events: Array<[string, boolean, Record<string, unknown>]> = [
        ['Learner identity established (one-time)', true, attestFor('LearnerIdentity', '1')],
        ['Baseline assessment (one-time)', true, attestFor('SpeakingBaseline', '2')],
        ['Monthly progress attestation (recurring)', true, attestFor('MonthlyProgress', '3')],
        ['Interview Ready pathway', true, attestFor('InterviewReady', '4')],
        ['Presentation Ready pathway', true, attestFor('PresentationReady', '5')],
        ['Oral Communication pathway', true, attestFor('OralCommunication', '6')],
        ['Pitch Ready pathway', true, attestFor('PitchReady', '7')],
    ];

    const results: Measurement[] = [];
    for (const [name, counts, metadata] of events) {
        results.push(await measure(lucid, name, counts, metadata));
    }

    // A real learner wallet rarely holds exactly one UTxO, and every extra input
    // enlarges the transaction. Measure that rather than assume it: split the
    // balance, then force the builder to collect several inputs.
    const inputCosts: Array<{ inputs: number; feeAda: number }> = [];
    const self = await lucid.wallet().address();
    const split = await lucid
        .newTx()
        .pay.ToAddress(self, { lovelace: 100_000_000n })
        .pay.ToAddress(self, { lovelace: 100_000_000n })
        .pay.ToAddress(self, { lovelace: 100_000_000n })
        .complete();
    await (await split.sign.withWallet().complete()).submit();
    emulator.awaitBlock(1);

    const utxos = await lucid.wallet().getUtxos();
    for (const count of [1, 2, 3]) {
        if (utxos.length < count) continue;
        const attest = attestFor('InterviewReady', '4');
        let tx = lucid.newTx().collectFrom(utxos.slice(0, count));
        for (const [label, value] of Object.entries(attest)) {
            tx = tx.attachMetadata(Number(label), value as never);
        }
        const built = await tx.complete();
        inputCosts.push({ inputs: count, feeAda: Number(built.toTransaction().body().fee()) / 1_000_000 });
    }

    // AUTH_BEGIN: AceSpeak's own setup transaction, deliberately not counted.
    const chain = 'A'.repeat(7260); // the real chain measured in 04-auth-begin
    results.push(
        await measure(lucid, 'AUTH_BEGIN issuer setup (AceSpeak pays)', false, {
            ...buildAuthBegin({
                signerAid: AID,
                schemaSaid: 'EFbV8Sf-2j4M99YbtStDPL5zkuA8hZNdYsN3ic9XFD3w',
                chain,
                extra: { l: [ACESPEAK_METADATA_LABEL] },
            }),
        })
    );

    const counted = results.filter((r) => r.counts);
    const mean = counted.reduce((sum, r) => sum + r.feeAda, 0) / counted.length;
    const min = Math.min(...counted.map((r) => r.feeAda));
    const max = Math.max(...counted.map((r) => r.feeAda));

    console.log('');
    console.log('  Event                                      Metadata    Tx     Fee (ADA)');
    console.log('  ' + '-'.repeat(74));
    for (const r of results) {
        const mark = r.counts ? ' ' : '*';
        console.log(
            `${mark} ${r.event.padEnd(42)} ${String(r.metadataBytes).padStart(6)}B ${String(r.txBytes).padStart(6)}B     ${r.feeAda.toFixed(6)}`
        );
    }
    console.log('  ' + '-'.repeat(74));
    console.log(`  * excluded from adoption counting (paid from an AceSpeak wallet)`);
    console.log('');
    console.log(`  Counted events: mean ${mean.toFixed(4)} ADA  (range ${min.toFixed(4)}-${max.toFixed(4)})`);
    console.log('');
    console.log('  Implications for the declared target:');
    for (const target of [100, 140]) {
        console.log(`    ${target} ADA target -> ${Math.ceil(target / mean).toLocaleString()} counted transactions needed`);
    }
    console.log('');
    console.log('  At an assumed 0.20 ADA/event the same targets would need:');
    for (const target of [100, 140]) {
        console.log(`    ${target} ADA target -> ${Math.ceil(target / 0.2).toLocaleString()} transactions`);
    }
    console.log('');
    console.log('  Cost of extra wallet inputs (measured, not assumed):');
    for (const c of inputCosts) {
        console.log(`    ${c.inputs} input(s) -> ${c.feeAda.toFixed(6)} ADA`);
    }

    writeFileSync(
        resolve(process.cwd(), 'artifacts/fee-measurements.json'),
        JSON.stringify(
            {
                method: 'Transactions built and balanced against Lucid Evolution\'s emulator using preprod protocol parameters. Cardano fees are deterministic in transaction size (minFeeA * size + minFeeB), so a fully-built transaction yields the exact fee without submitting it.',
                protocolParameters: {
                    source: 'Koios preprod, epoch 307, cross-checked against Lucid defaults',
                    minFeeA: PROTOCOL_PARAMETERS_DEFAULT.minFeeA,
                    minFeeB: PROTOCOL_PARAMETERS_DEFAULT.minFeeB,
                    maxTxSize: PROTOCOL_PARAMETERS_DEFAULT.maxTxSize,
                },
                caveat: 'Headline fees assume a single-input balanced transaction. A learner wallet holding several UTxOs pays more; inputCostByCount measures that directly.',
                inputCostByCount: inputCosts,
                measurements: results,
                countedMeanAda: Number(mean.toFixed(6)),
                countedMinAda: min,
                countedMaxAda: max,
            },
            null,
            2
        ) + '\n'
    );
}

main().catch((error: unknown) => {
    console.error(error instanceof Error ? error.message : error);
    process.exit(1);
});

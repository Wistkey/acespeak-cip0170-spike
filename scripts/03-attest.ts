/**
 * Submit the ATTEST transaction — the point of the whole spike.
 *
 * The transaction is built, signed and PAID FOR by `learner-demo`, a wallet
 * funded independently from the faucet. The attestation it carries names
 * AceSpeak's AID in `i`. Nothing in CIP-0170 ties the payer to the signer: the
 * proof is the KEL seal, not the transaction witness.
 *
 * That is exactly Catalyst's counting rule — a fee counts only when it is not
 * paid from the applicant's own wallets — so this transaction demonstrates that
 * AceSpeak's adoption model produces countable transactions.
 *
 *   npm run attest
 */
import { readFileSync, writeFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { ready } from 'signify-ts';
import { buildAttest } from '../src/cardano/metadata.ts';
import { buildMetadataTx, connectWallet } from '../src/cardano/submit.ts';
import { verifyAttestation } from '../src/verify.ts';
import { digestMetadatum, extractMetadatumBytes, fromTransactionCbor } from '../src/cardano/cbor.ts';
import { ACESPEAK_METADATA_LABEL, CARDANOSCAN_TX } from '../src/config.ts';
import { loadEnv } from '../src/env.ts';

const ARTIFACTS = resolve(process.cwd(), 'artifacts');
const artifact = (name: string) => resolve(ARTIFACTS, name);

async function main(): Promise<void> {
    loadEnv();
    await ready();

    const anchor = JSON.parse(readFileSync(artifact('anchor.json'), 'utf8')) as {
        i: string;
        d: string;
        s: string;
    };
    const credential = JSON.parse(readFileSync(artifact('credential.json'), 'utf8'));
    const kel = readFileSync(artifact('issuer-kel.cesr'), 'utf8');

    const metadata = buildAttest({
        signerAid: anchor.i,
        digest: anchor.d,
        sequenceNumber: anchor.s,
        appLabel: ACESPEAK_METADATA_LABEL,
        appData: credential,
    });

    const lucid = await connectWallet('learner');

    // Build first, then verify the BUILT transaction rather than the object we
    // handed the builder. `d` is a digest over the bytes the builder emits, and
    // the KEL anchor committing to that digest already exists and cannot be
    // retracted -- so if the builder encodes even one byte differently, this is
    // the last moment the mistake is free. (Raised upstream as a SHOULD on
    // cardano-foundation/CIPs#1253.)
    const built = await buildMetadataTx(lucid, metadata);

    const onChainBytes = extractMetadatumBytes(built.cborHex, ACESPEAK_METADATA_LABEL);
    const onChainDigest = digestMetadatum(onChainBytes);
    if (onChainDigest !== anchor.d) {
        throw new Error(
            `the built transaction's payload digests to ${onChainDigest}, but ${anchor.d} is anchored in the KEL. ` +
                'The transaction builder encoded the payload differently from what was digested; submitting would ' +
                'create a permanently unverifiable attestation.'
        );
    }
    console.log(`Built transaction payload digests to ${onChainDigest} — matches the KEL anchor.`);

    const preflight = verifyAttestation({
        source: fromTransactionCbor(built.cborHex),
        kel,
        expectedAid: anchor.i,
    });
    if (!preflight.valid) {
        throw new Error(`refusing to submit an attestation that does not verify: ${preflight.reason}`);
    }
    console.log('Pre-flight verification passed. Submitting from learner-demo...');

    const { txHash, fee, payer } = await built.submit();

    writeFileSync(
        artifact('attest.json'),
        JSON.stringify(
            {
                type: 'ATTEST',
                txHash,
                explorer: CARDANOSCAN_TX(txHash),
                network: 'preprod',
                signerAid: anchor.i,
                digest: anchor.d,
                sequenceNumber: anchor.s,
                applicationLabel: ACESPEAK_METADATA_LABEL,
                feePaidBy: payer,
                feeLovelace: fee.toString(),
                note: 'The fee was paid by learner-demo, which is not an AceSpeak wallet. The attestation carries the AceSpeak issuer AID.',
            },
            null,
            2
        ) + '\n'
    );

    console.log('');
    console.log(`  tx        ${txHash}`);
    console.log(`  explorer  ${CARDANOSCAN_TX(txHash)}`);
    console.log(`  fee       ${Number(fee) / 1_000_000} tADA, paid by ${payer}`);
    console.log(`  signer    ${anchor.i}  <- AceSpeak, who paid nothing`);
    console.log('');
    console.log('Once it settles, verify it end to end:');
    console.log(`  npm run verify -- ${txHash}`);
}

main().catch((error: unknown) => {
    console.error(error instanceof Error ? error.message : error);
    process.exit(1);
});

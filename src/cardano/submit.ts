/**
 * Building and submitting metadata-carrying transactions on preprod.
 *
 * Note how little is here. A CIP-0170 attestation is an ordinary transaction
 * that happens to carry metadata — no script, no minting, no datum. The
 * cryptographic weight sits entirely in KERI, which is precisely why the
 * transaction can be paid for by a wallet with no relationship to the signer.
 */
import { Blockfrost, Lucid, type LucidEvolution } from '@lucid-evolution/lucid';
import { assertMetadataValid, CIP0170_LABEL } from './metadata.ts';
import { required } from '../env.ts';

const BLOCKFROST_PREPROD = 'https://cardano-preprod.blockfrost.io/api/v0';

export type WalletName = 'issuer' | 'learner';

const MNEMONIC_VAR: Record<WalletName, string> = {
    issuer: 'ISSUER_MNEMONIC',
    learner: 'LEARNER_MNEMONIC',
};

/** Connect to preprod through Blockfrost with the named wallet selected. */
export async function connectWallet(wallet: WalletName): Promise<LucidEvolution> {
    const projectId = required('BLOCKFROST_PROJECT_ID');
    const lucid = await Lucid(new Blockfrost(BLOCKFROST_PREPROD, projectId), 'Preprod');

    lucid.selectWallet.fromSeed(required(MNEMONIC_VAR[wallet]));
    return lucid;
}

export interface SubmitResult {
    txHash: string;
    /** Fee in lovelace, and who paid it. */
    fee: bigint;
    payer: string;
}

/**
 * Attach a CIP-0170 metadata object to a self-payment and submit it.
 *
 * Every label in the object is attached, so an ATTEST carries both label 170
 * and its sibling application payload in one transaction, as the spec's worked
 * example shows.
 */
export async function submitMetadata(
    lucid: LucidEvolution,
    metadata: Record<string, unknown>
): Promise<SubmitResult> {
    // Fail here, with a path, rather than on an opaque Blockfrost rejection.
    assertMetadataValid(metadata);

    if (metadata[String(CIP0170_LABEL)] === undefined) {
        throw new Error(`metadata has no CIP-0170 body at label ${CIP0170_LABEL}`);
    }

    const payer = await lucid.wallet().address();

    let tx = lucid.newTx();
    for (const [label, value] of Object.entries(metadata)) {
        // Lucid types the payload as its own TransactionMetadata union; any
        // JSON-shaped value is valid on the wire once assertMetadataValid passes.
        tx = tx.attachMetadata(Number(label), value as never);
    }

    const completed = await tx.complete();
    const signed = await completed.sign.withWallet().complete();
    const txHash = await signed.submit();

    return { txHash, fee: completed.toTransaction().body().fee(), payer };
}

/** Fetch a transaction's metadata back from Blockfrost, keyed by label. */
export async function fetchTransactionMetadata(txHash: string): Promise<Record<string, unknown>> {
    const projectId = required('BLOCKFROST_PROJECT_ID');

    const response = await fetch(`${BLOCKFROST_PREPROD}/txs/${txHash}/metadata`, {
        headers: { project_id: projectId },
    });

    if (response.status === 404) {
        throw new Error(`transaction ${txHash} not found on preprod`);
    }
    if (!response.ok) {
        throw new Error(`Blockfrost returned ${response.status} for ${txHash}`);
    }

    const entries = (await response.json()) as Array<{ label: string; json_metadata: unknown }>;

    return Object.fromEntries(entries.map((e) => [e.label, e.json_metadata]));
}

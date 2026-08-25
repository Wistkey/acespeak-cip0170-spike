/**
 * Building and submitting metadata-carrying transactions on preprod.
 *
 * Note how little is here. A CIP-0170 attestation is an ordinary transaction
 * that happens to carry metadata — no script, no minting, no datum. The
 * cryptographic weight sits entirely in KERI, which is precisely why the
 * transaction can be paid for by a wallet with no relationship to the signer.
 */
import { Blockfrost, Koios, Lucid, type LucidEvolution } from '@lucid-evolution/lucid';
import { assertMetadataValid, CIP0170_LABEL } from './metadata.ts';
import { BLOCKFROST_PREPROD, KOIOS_PREPROD } from './chain.ts';
import { optional, required } from '../env.ts';

export { fetchTransactionMetadata } from './chain.ts';

export type WalletName = 'issuer' | 'learner';

const MNEMONIC_VAR: Record<WalletName, string> = {
    issuer: 'ISSUER_MNEMONIC',
    learner: 'LEARNER_MNEMONIC',
};

/**
 * Connect to preprod with the named wallet selected.
 *
 * Koios by default, so submitting needs no API key and no account signup.
 * Blockfrost is used instead when BLOCKFROST_PROJECT_ID is set.
 */
export async function connectWallet(wallet: WalletName): Promise<LucidEvolution> {
    const projectId = optional('BLOCKFROST_PROJECT_ID', '');
    const provider =
        projectId === ''
            ? new Koios(KOIOS_PREPROD)
            : new Blockfrost(BLOCKFROST_PREPROD, projectId);

    const lucid = await Lucid(provider, 'Preprod');
    lucid.selectWallet.fromSeed(required(MNEMONIC_VAR[wallet]));
    return lucid;
}

export interface SubmitResult {
    txHash: string;
    /** Fee in lovelace, and who paid it. */
    fee: bigint;
    payer: string;
}

export interface BuiltTransaction {
    /** The signed transaction's CBOR, for inspecting the bytes before submitting. */
    cborHex: string;
    fee: bigint;
    payer: string;
    submit(): Promise<SubmitResult>;
}

/**
 * Build and sign a metadata transaction WITHOUT submitting it.
 *
 * Separated from submission so callers can digest the metadatum bytes the
 * builder actually emitted and compare them against what was anchored, while
 * backing out is still free. See scripts/03-attest.ts.
 */
export async function buildMetadataTx(
    lucid: LucidEvolution,
    metadata: Record<string, unknown>
): Promise<BuiltTransaction> {
    assertMetadataValid(metadata);

    if (metadata[String(CIP0170_LABEL)] === undefined) {
        throw new Error(`metadata has no CIP-0170 body at label ${CIP0170_LABEL}`);
    }

    const payer = await lucid.wallet().address();

    let tx = lucid.newTx();
    for (const [label, value] of Object.entries(metadata)) {
        tx = tx.attachMetadata(Number(label), value as never);
    }

    const completed = await tx.complete();
    const fee = completed.toTransaction().body().fee();
    const signed = await completed.sign.withWallet().complete();

    return {
        cborHex: signed.toCBOR(),
        fee,
        payer,
        submit: async () => ({ txHash: await signed.submit(), fee, payer }),
    };
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


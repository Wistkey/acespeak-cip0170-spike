/**
 * Reading preprod without an API key.
 *
 * `verify.ts` is the deliverable, and a verifier that first demands the reader
 * sign up for a Blockfrost account is a verifier most people will never run.
 * Koios serves the same data keylessly, so the default path from `git clone` to
 * VALID has no account creation in it.
 *
 * Blockfrost stays supported: set BLOCKFROST_PROJECT_ID and it is used instead.
 */
import { optional } from '../env.ts';

/** Keyless preprod endpoint. */
export const KOIOS_PREPROD = 'https://preprod.koios.rest/api/v1';
export const BLOCKFROST_PREPROD = 'https://cardano-preprod.blockfrost.io/api/v0';

export class TransactionNotFoundError extends Error {
    constructor(readonly txHash: string) {
        super(`transaction ${txHash} was not found on preprod`);
        this.name = 'TransactionNotFoundError';
    }
}

/**
 * Turn a Koios `/tx_metadata` response into a label-keyed object.
 *
 * Koios answers with one row per requested hash. A transaction that exists but
 * carries no metadata has `metadata: null` — which is a very different thing
 * from a transaction that is not on chain, and the two must not collapse into
 * the same result: one means "not an attestation", the other means "wrong hash".
 */
export function normaliseKoiosMetadata(response: unknown, txHash: string): Record<string, unknown> {
    if (!Array.isArray(response)) {
        throw new Error(`unexpected response from Koios for ${txHash}: expected an array`);
    }
    if (response.length === 0) throw new TransactionNotFoundError(txHash);

    const metadata = (response[0] as { metadata?: unknown }).metadata;
    if (metadata === null || metadata === undefined) return {};

    return metadata as Record<string, unknown>;
}

async function fetchViaKoios(txHash: string): Promise<Record<string, unknown>> {
    const response = await fetch(`${KOIOS_PREPROD}/tx_metadata`, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ _tx_hashes: [txHash] }),
    });
    if (!response.ok) throw new Error(`Koios returned ${response.status} for ${txHash}`);

    return normaliseKoiosMetadata(await response.json(), txHash);
}

async function fetchViaBlockfrost(txHash: string, projectId: string): Promise<Record<string, unknown>> {
    const response = await fetch(`${BLOCKFROST_PREPROD}/txs/${txHash}/metadata`, {
        headers: { project_id: projectId },
    });
    if (response.status === 404) throw new TransactionNotFoundError(txHash);
    if (!response.ok) throw new Error(`Blockfrost returned ${response.status} for ${txHash}`);

    const entries = (await response.json()) as Array<{ label: string; json_metadata: unknown }>;
    return Object.fromEntries(entries.map((e) => [e.label, e.json_metadata]));
}

/** Fetch a transaction's metadata, keyed by label. Keyless unless a Blockfrost key is set. */
export async function fetchTransactionMetadata(txHash: string): Promise<Record<string, unknown>> {
    const projectId = optional('BLOCKFROST_PROJECT_ID', '');

    return projectId === '' ? await fetchViaKoios(txHash) : await fetchViaBlockfrost(txHash, projectId);
}

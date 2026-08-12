/**
 * Connecting to the local KERIA agent.
 *
 * signify-ts signs at the edge: the passcode (`bran`) never leaves this
 * process, and KERIA stores only encrypted key material. That property is why
 * the architecture is defensible for a credential issuer — see READINESS.md.
 */
import { randomPasscode, ready, SignifyClient, Tier } from 'signify-ts';
import { optional } from '../env.ts';

/**
 * The witness-demo pool's well-known AIDs, from KERIA's own bootstrap config.
 * These are fixed, published test identifiers — not secrets.
 */
export const WITNESS_POOL = [
    { alias: 'wan', aid: 'BBilc4-L3tFUnfM_wJr4S4OJanAv_VmF_dJNN6vkf2Ha', url: 'http://localhost:5642' },
    { alias: 'wil', aid: 'BLskRTInXnMxWaGqcpSyMgo0nYbalW99cGZESrz3zapM', url: 'http://localhost:5643' },
    { alias: 'wes', aid: 'BIKKuvBwpmDVA4Ds-EpL5bt9OqPzWPja2LigFYZN2YfX', url: 'http://localhost:5644' },
] as const;

export const WITNESS_AIDS = WITNESS_POOL.map((w) => w.aid);

/** The alias the issuer identifier is managed under. */
export const ISSUER_ALIAS = 'acespeak-issuer';

export interface Connection {
    client: SignifyClient;
    bran: string;
    /** True when this call created the agent rather than reconnecting to it. */
    booted: boolean;
}

/**
 * Connect to KERIA, booting a new agent if this passcode has not been used.
 *
 * Pass a bran to reconnect to an existing identity; omit it to generate one.
 * A generated bran is returned, never written to disk — the caller decides
 * where it goes, and the answer must not be this repository.
 */
export async function connect(bran?: string): Promise<Connection> {
    await ready();

    const url = optional('KERIA_URL', 'http://127.0.0.1:3901');
    const bootUrl = optional('KERIA_BOOT_URL', 'http://127.0.0.1:3903');
    const passcode = bran ?? randomPasscode();

    const client = new SignifyClient(url, passcode, Tier.low, bootUrl);

    // Reconnecting is the common case, so try it before booting. Booting an
    // already-booted agent is an error, and the reverse is too, so probe.
    try {
        await client.connect();
        return { client, bran: passcode, booted: false };
    } catch {
        await client.boot();
        await client.connect();
        return { client, bran: passcode, booted: true };
    }
}

/**
 * Fetch an identifier's KEL as a raw CESR stream, straight from a witness.
 *
 * KERIA's `keyEvents()` returns parsed JSON records; this returns the signed
 * stream with its attachments intact, which is what belongs in
 * `artifacts/issuer-kel.cesr` as durable evidence.
 */
export async function fetchKelFromWitness(
    aid: string,
    witnessUrl = WITNESS_POOL[0].url
): Promise<string> {
    const response = await fetch(`${witnessUrl}/oobi/${aid}/witness`);
    if (!response.ok) {
        throw new Error(`witness at ${witnessUrl} returned ${response.status} for ${aid}`);
    }
    return await response.text();
}

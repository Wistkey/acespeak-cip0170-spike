/**
 * Publish AceSpeak's credential chain with an AUTH_BEGIN transaction.
 *
 * This is the supporting half of the spike. It establishes, on-chain, that the
 * issuer AID holds authority over the application metadata label. The chain is
 * self-issued: CIP-0170 is trust-agnostic about the root of trust, and rooting
 * AceSpeak's chain in a stronger authority is a later decision rather than a
 * Milestone 1 blocker. READINESS.md says so plainly rather than leaving it
 * implied.
 *
 * Unlike ATTEST, this transaction IS paid by AceSpeak — it is our own setup, so
 * its fee is deliberately not part of any adoption count.
 *
 *   npx tsx scripts/04-auth-begin.ts --dry-run   # build the chain, submit nothing
 *   npm run auth-begin                           # build and submit
 */
import { readFileSync, writeFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { ready } from 'signify-ts';
import { buildAuthBegin, chunk64 } from '../src/cardano/metadata.ts';
import { connectWallet, submitMetadata } from '../src/cardano/submit.ts';
import { connect, ISSUER_ALIAS } from '../src/keri/client.ts';
import { ACESPEAK_METADATA_LABEL, CARDANOSCAN_TX } from '../src/config.ts';
import { loadEnv, optional, required } from '../src/env.ts';

const ARTIFACTS = resolve(process.cwd(), 'artifacts');
const REGISTRY = 'acespeak-credentials';

/** Cardano rejects transactions above this size; metadata competes with everything else in it. */
const TX_SIZE_LIMIT = 16384;

async function main(): Promise<void> {
    loadEnv();
    await ready();

    const dryRun = process.argv.includes('--dry-run');

    const schema = JSON.parse(
        readFileSync(resolve(process.cwd(), 'schema/communication-credential-profile.v1.json'), 'utf8')
    ) as { $id: string };
    const schemaSaid = schema.$id;

    const { client } = await connect(required('KERI_BRAN'));
    const aid = (await client.identifiers().get(ISSUER_ALIAS)).prefix;

    // KERIA resolves the schema over the compose network, not via localhost.
    const schemaOobi = optional('SCHEMA_OOBI', `http://schema-server:7724/oobi/${schemaSaid}`);
    console.log(`Resolving schema ${schemaSaid}...`);
    await client.operations().wait(await client.oobis().resolve(schemaOobi));

    // Reuse the registry if it is already there, so re-running is safe.
    let registryId: string;
    const registries = (await client.registries().list(ISSUER_ALIAS)) as Array<{
        name: string;
        regk: string;
    }>;
    const existing = registries.find((r) => r.name === REGISTRY);

    if (existing !== undefined) {
        registryId = existing.regk;
        console.log(`Registry "${REGISTRY}" already exists.`);
    } else {
        console.log(`Creating registry "${REGISTRY}"...`);
        const created = await client.registries().create({ name: ISSUER_ALIAS, registryName: REGISTRY });
        await client.operations().wait(await created.op());

        // RegistryResult exposes the inception event, not a `regk` field; the
        // registry identifier is that event's prefix. Reading a non-existent
        // `regk` here yields undefined, which surfaces much later as an `iss`
        // event missing `ri` and a bare "Invalid sad for Serder" from KERIA.
        registryId = created.regser.pre as string;
    }

    if (typeof registryId !== 'string' || registryId === '') {
        throw new Error('could not determine the registry identifier');
    }

    // Self-issued: the issuee is the issuer, which satisfies CIP-0170's rule
    // that `i` MUST match the issuee of the leaf credential.
    console.log('Issuing the authority credential...');
    const issued = await client.credentials().issue(ISSUER_ALIAS, {
        ri: registryId,
        s: schemaSaid,
        a: {
            i: aid,
            dt: new Date().toISOString().replace(/\.\d{3}Z$/, 'Z'),
            credentialType: 'InterviewReady',
            schemaVersion: '1.0.0',
        },
    });
    await client.operations().wait(issued.op);

    const credentialSaid = issued.acdc.sad.d as string;
    const chain = await client.credentials().get(credentialSaid, true);

    const metadata = buildAuthBegin({
        signerAid: aid,
        schemaSaid,
        chain,
        extra: { l: [ACESPEAK_METADATA_LABEL] },
    });

    const chunks = chunk64(chain);
    const encoded = JSON.stringify(metadata).length;

    console.log('');
    console.log(`  credential   ${credentialSaid}`);
    console.log(`  registry     ${registryId}`);
    console.log(`  chain        ${chain.length} bytes -> ${chunks.length} chunks of <=64 bytes`);
    console.log(`  metadata     ${encoded} bytes encoded (transaction limit ${TX_SIZE_LIMIT})`);

    if (encoded > TX_SIZE_LIMIT) {
        console.log('');
        console.log('  The chain does not fit in a single transaction. That is a reportable');
        console.log('  finding, not a bug — see READINESS.md.');
    }

    writeFileSync(
        resolve(ARTIFACTS, 'auth-begin-chain.cesr'),
        typeof chain === 'string' ? chain : JSON.stringify(chain)
    );

    if (dryRun) {
        console.log('');
        console.log('  --dry-run: nothing submitted.');
        return;
    }

    const lucid = await connectWallet('issuer');
    const { txHash, fee, payer } = await submitMetadata(lucid, metadata);

    writeFileSync(
        resolve(ARTIFACTS, 'auth-begin.json'),
        JSON.stringify(
            {
                type: 'AUTH_BEGIN',
                txHash,
                explorer: CARDANOSCAN_TX(txHash),
                network: 'preprod',
                signerAid: aid,
                schemaSaid,
                credentialSaid,
                registryId,
                chainBytes: chain.length,
                chainChunks: chunks.length,
                feePaidBy: payer,
                feeLovelace: fee.toString(),
                note: 'Paid by AceSpeak. This is our own setup transaction and is deliberately excluded from any adoption count.',
            },
            null,
            2
        ) + '\n'
    );

    console.log('');
    console.log(`  tx        ${txHash}`);
    console.log(`  explorer  ${CARDANOSCAN_TX(txHash)}`);
    console.log(`  fee       ${Number(fee) / 1_000_000} tADA, paid by AceSpeak`);
}

main().catch((error: unknown) => {
    console.error(error instanceof Error ? error.message : error);
    process.exit(1);
});

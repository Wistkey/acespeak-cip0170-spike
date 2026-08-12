/**
 * Create AceSpeak's issuer identifier.
 *
 * The AID this produces is the "declared identifier" the Catalyst proposal
 * refers to — the value that appears in `i` on every ATTEST transaction. Run
 * this once. The passcode it prints derives the signing keys; losing it loses
 * the identity, and publishing it gives the identity away.
 *
 *   npm run incept
 */
import { writeFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { connect, fetchKelFromWitness, ISSUER_ALIAS, WITNESS_AIDS, WITNESS_POOL } from '../src/keri/client.ts';
import { loadEnv } from '../src/env.ts';

const ARTIFACTS = resolve(process.cwd(), 'artifacts');

async function main(): Promise<void> {
    loadEnv();

    const existingBran = process.env.KERI_BRAN;
    const { client, bran, booted } = await connect(existingBran);

    console.log(booted ? 'Booted a new KERIA agent.' : 'Reconnected to the existing KERIA agent.');

    // Reuse the identifier if it is already there, so re-running is safe.
    let aid: string;
    try {
        const existing = await client.identifiers().get(ISSUER_ALIAS);
        aid = existing.prefix;
        console.log(`Identifier "${ISSUER_ALIAS}" already exists.`);
    } catch {
        console.log(`Incepting "${ISSUER_ALIAS}" with ${WITNESS_AIDS.length} witnesses, toad 2...`);

        const result = await client.identifiers().create(ISSUER_ALIAS, {
            toad: 2,
            wits: [...WITNESS_AIDS],
        });
        await client.operations().wait(await result.op());

        aid = (await client.identifiers().get(ISSUER_ALIAS)).prefix;

        // Authorise the agent to act for this identifier, which is what makes
        // the OOBI resolvable by anyone who wants to fetch the KEL.
        const role = await client.identifiers().addEndRole(ISSUER_ALIAS, 'agent', client.agent!.pre);
        await client.operations().wait(await role.op());
    }

    const oobi = await client.oobis().get(ISSUER_ALIAS, 'agent');
    const witnessOobi = `${WITNESS_POOL[0].url}/oobi/${aid}/witness`;

    const kel = await fetchKelFromWitness(aid);
    writeFileSync(resolve(ARTIFACTS, 'issuer-kel.cesr'), kel);

    const record = {
        alias: ISSUER_ALIAS,
        aid,
        witnesses: WITNESS_POOL.map((w) => ({ alias: w.alias, aid: w.aid })),
        toad: 2,
        agentOobi: oobi.oobis?.[0] ?? null,
        witnessOobi,
        note: 'Both OOBIs are localhost-only. artifacts/issuer-kel.cesr is the portable copy — see READINESS.md.',
    };
    writeFileSync(resolve(ARTIFACTS, 'issuer-aid.json'), JSON.stringify(record, null, 2) + '\n');

    console.log('');
    console.log(`  AID          ${aid}`);
    console.log(`  witness OOBI ${witnessOobi}`);
    console.log(`  KEL          artifacts/issuer-kel.cesr (${kel.length} bytes)`);

    if (!existingBran) {
        console.log('');
        console.log('  Save this passcode outside the repository, then set KERI_BRAN in .env:');
        console.log('');
        console.log(`    KERI_BRAN=${bran}`);
        console.log('');
        console.log('  It derives the issuer signing keys. Anyone holding it controls the identifier.');
    }
}

main().catch((error: unknown) => {
    console.error(error instanceof Error ? error.message : error);
    process.exit(1);
});

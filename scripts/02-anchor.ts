/**
 * Issue a Speaking Passport credential and anchor its digest in the issuer's KEL.
 *
 * The anchor is an interaction event carrying the seal `{ d: <credential SAID> }`.
 * Anchoring rather than merely signing is deliberate: the record stays
 * verifiable after the issuer rotates keys, which matters for a credential
 * meant to outlive AceSpeak's subscription relationship with the learner.
 *
 *   npm run anchor
 */
import { writeFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { connect, fetchKelFromWitness, ISSUER_ALIAS } from '../src/keri/client.ts';
import { buildCredential, opaqueHolderRef } from '../src/keri/credential.ts';
import { findEventBySequence, hasDigestSeal, parseKel, verifyKelLinkage } from '../src/keri/kel.ts';
import { HOLDER_REF_SALT } from '../src/config.ts';
import { loadEnv, required } from '../src/env.ts';

const ARTIFACTS = resolve(process.cwd(), 'artifacts');

async function main(): Promise<void> {
    loadEnv();

    const { client } = await connect(required('KERI_BRAN'));
    const aid = (await client.identifiers().get(ISSUER_ALIAS)).prefix;

    // A minimal claim. No video, transcript, personal data or raw score — this
    // payload goes on-chain, so section 4 of the pilot plan is load-bearing.
    const credential = buildCredential({
        credentialType: 'InterviewReady',
        schemaVersion: '1.0.0',
        issuedAt: process.env.CREDENTIAL_ISSUED_AT ?? new Date().toISOString().replace(/\.\d{3}Z$/, 'Z'),
        holderRef: opaqueHolderRef('demo-learner-0001', HOLDER_REF_SALT),
        evidenceDigest: opaqueHolderRef('demo-assessment-record-0001', HOLDER_REF_SALT),
    });

    console.log(`Anchoring credential ${credential.d} in ${aid}...`);

    const result = await client.identifiers().interact(ISSUER_ALIAS, { d: credential.d });
    await client.operations().wait(await result.op());

    // Read the sequence number back off the witness-served KEL rather than
    // trusting the local response — this is the value a verifier will look up.
    const kel = await fetchKelFromWitness(aid);
    const events = parseKel(kel);

    const linkage = verifyKelLinkage(events);
    if (!linkage.ok) throw new Error(`issuer KEL failed linkage verification: ${linkage.reason}`);

    const anchoring = events.find((e) => hasDigestSeal(e, credential.d));
    if (anchoring === undefined) {
        throw new Error(`no event in the KEL anchors ${credential.d}`);
    }

    // Belt and braces: prove the lookup a verifier performs actually resolves.
    const found = findEventBySequence(events, anchoring.s);
    if (found === undefined || !hasDigestSeal(found, credential.d)) {
        throw new Error(`seal is not retrievable at sequence ${anchoring.s}`);
    }

    writeFileSync(resolve(ARTIFACTS, 'issuer-kel.cesr'), kel);
    writeFileSync(resolve(ARTIFACTS, 'credential.json'), JSON.stringify(credential, null, 2) + '\n');
    writeFileSync(
        resolve(ARTIFACTS, 'anchor.json'),
        JSON.stringify({ i: aid, d: credential.d, s: anchoring.s, eventDigest: anchoring.d }, null, 2) + '\n'
    );

    console.log('');
    console.log(`  digest (d)   ${credential.d}`);
    console.log(`  sequence (s) ${anchoring.s}  (event ${parseInt(anchoring.s, 16)} of the KEL)`);
    console.log(`  KEL          ${events.length} key events, linkage OK`);
}

main().catch((error: unknown) => {
    console.error(error instanceof Error ? error.message : error);
    process.exit(1);
});

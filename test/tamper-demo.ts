/**
 * Show the verifier rejecting an altered credential.
 *
 * Runs offline against the committed KEL. Exits 0 if the tampering was
 * accepted (which would be a failure of the verifier) and 1 if it was
 * correctly rejected, so `demo.sh` can assert on it.
 */
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { ready } from 'signify-ts';
import { buildAttest } from '../src/cardano/metadata.ts';
import { verifyAttestation } from '../src/verify.ts';
import { ACESPEAK_METADATA_LABEL } from '../src/config.ts';

const artifact = (name: string) => resolve(process.cwd(), 'artifacts', name);

async function main(): Promise<void> {
    await ready();

    const anchor = JSON.parse(readFileSync(artifact('anchor.json'), 'utf8'));
    const credential = JSON.parse(readFileSync(artifact('credential.json'), 'utf8'));
    const kel = readFileSync(artifact('issuer-kel.cesr'), 'utf8');

    // A learner upgrades their own credential after issuance.
    const tampered = { ...credential, credentialType: 'NativeSpeaker' };

    console.log(`  issued:   credentialType = ${credential.credentialType}`);
    console.log(`  altered:  credentialType = ${tampered.credentialType}`);
    console.log('');

    const result = verifyAttestation({
        metadata: buildAttest({
            signerAid: anchor.i,
            digest: anchor.d,
            sequenceNumber: anchor.s,
            appLabel: ACESPEAK_METADATA_LABEL,
            appData: tampered,
        }),
        kel,
    });

    for (const check of result.checks) {
        console.log(`  ${check.ok ? '✓' : '✗'} ${check.name}`);
    }
    console.log('');
    console.log(result.valid ? 'VALID' : `INVALID — ${result.reason}`);

    process.exit(result.valid ? 0 : 1);
}

main().catch((error: unknown) => {
    console.error(error instanceof Error ? error.message : error);
    process.exit(2);
});

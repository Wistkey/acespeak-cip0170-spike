/**
 * Generate the two preprod wallets the spike needs.
 *
 *   acespeak-issuer — publishes AUTH_BEGIN. This is AceSpeak's own wallet.
 *   learner-demo    — pays for ATTEST. This one stands in for a learner.
 *
 * The two MUST be funded independently from the faucet and MUST NEVER send
 * funds to each other. Catalyst's adoption rule counts a fee only when it is
 * not paid from the applicant's own wallets, so an on-chain transfer between
 * these two would destroy the very thing the spike exists to demonstrate.
 *
 *   npm run wallets
 */
import { existsSync, writeFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { generateSeedPhrase, walletFromSeed } from '@lucid-evolution/lucid';
import { CARDANOSCAN_ADDRESS } from '../src/config.ts';
import { loadEnv } from '../src/env.ts';

const ARTIFACTS = resolve(process.cwd(), 'artifacts');
const SECRETS = resolve(ARTIFACTS, 'wallets.json'); // gitignored
const PUBLIC = resolve(ARTIFACTS, 'wallets-public.json'); // committed evidence

function addressFor(mnemonic: string): string {
    return walletFromSeed(mnemonic, { addressType: 'Base', network: 'Preprod' }).address;
}

function main(): void {
    loadEnv();

    if (existsSync(SECRETS)) {
        console.error(`${SECRETS} already exists. Delete it deliberately if you really want new wallets.`);
        process.exit(1);
    }

    const issuer = process.env.ISSUER_MNEMONIC || generateSeedPhrase();
    const learner = process.env.LEARNER_MNEMONIC || generateSeedPhrase();

    const issuerAddress = addressFor(issuer);
    const learnerAddress = addressFor(learner);

    writeFileSync(
        SECRETS,
        JSON.stringify(
            {
                warning: 'SECRET. Gitignored. These mnemonics control preprod test funds.',
                issuer: { address: issuerAddress, mnemonic: issuer },
                learner: { address: learnerAddress, mnemonic: learner },
            },
            null,
            2
        ) + '\n'
    );

    writeFileSync(
        PUBLIC,
        JSON.stringify(
            {
                note: 'Both wallets are funded directly from the Cardano testnet faucet. Neither has ever sent funds to the other — check the address histories.',
                network: 'preprod',
                acespeakIssuer: { address: issuerAddress, role: 'publishes AUTH_BEGIN', explorer: CARDANOSCAN_ADDRESS(issuerAddress) },
                learnerDemo: { address: learnerAddress, role: 'pays for ATTEST', explorer: CARDANOSCAN_ADDRESS(learnerAddress) },
            },
            null,
            2
        ) + '\n'
    );

    console.log('Wrote artifacts/wallets.json (secret) and artifacts/wallets-public.json (committed).');
    console.log('');
    console.log('Add these to .env:');
    console.log('');
    console.log(`  ISSUER_MNEMONIC="${issuer}"`);
    console.log(`  LEARNER_MNEMONIC="${learner}"`);
    console.log('');
    console.log('Now fund BOTH from https://docs.cardano.org/cardano-testnets/tools/faucet');
    console.log('separately — never move funds between them:');
    console.log('');
    console.log(`  learner-demo     ${learnerAddress}`);
    console.log(`  acespeak-issuer  ${issuerAddress}`);
    console.log('');
    console.log('Fund learner-demo first. It pays the fee that actually counts, and the');
    console.log('faucet rate-limits, so if only one goes through today it should be that one.');
}

main();

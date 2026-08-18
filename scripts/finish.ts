/**
 * Run everything that is left, once the wallets are funded.
 *
 * Checks funding, submits both transactions, verifies the attestation against
 * live chain data, and writes the real hashes into the README. One command,
 * because the remaining work happens under a submission deadline and six
 * sequential steps is six chances to fumble one.
 *
 *   npx tsx scripts/finish.ts
 */
import { execFileSync } from 'node:child_process';
import { existsSync, readFileSync, writeFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { CARDANOSCAN_TX, CARDANOSCAN_ADDRESS } from '../src/config.ts';
import { KOIOS_PREPROD } from '../src/cardano/chain.ts';
import { loadEnv } from '../src/env.ts';

const artifact = (name: string) => resolve(process.cwd(), 'artifacts', name);
const FAUCET = 'https://docs.cardano.org/cardano-testnets/tools/faucet';

async function balances(addresses: string[]): Promise<Record<string, bigint>> {
    const response = await fetch(`${KOIOS_PREPROD}/address_info`, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ _addresses: addresses }),
    });
    if (!response.ok) throw new Error(`Koios returned ${response.status} checking balances`);

    const rows = (await response.json()) as Array<{ address: string; balance?: string }>;
    const out: Record<string, bigint> = Object.fromEntries(addresses.map((a) => [a, 0n]));
    for (const row of rows) out[row.address] = BigInt(row.balance ?? '0');
    return out;
}

function run(script: string): void {
    console.log(`\n$ npx tsx ${script}`);
    execFileSync('npx', ['tsx', script], { stdio: 'inherit' });
}

/** Replace the pending block in the README with the real hashes. */
function updateReadme(attestTx: string, authBeginTx: string | null, wallets: {
    learner: string;
    issuer: string;
}): void {
    const path = resolve(process.cwd(), 'README.md');
    const readme = readFileSync(path, 'utf8');

    const pending =
        /> \*\*Status: pending funding\.\*\*[\s\S]*?\| \*\*`AUTH_BEGIN`\*\* \|[^\n]*\n/;
    if (!pending.test(readme)) {
        console.log('\nREADME already carries the transactions; leaving it alone.');
        return;
    }

    const authRow =
        authBeginTx === null
            ? `| **\`AUTH_BEGIN\`** | _not submitted_ | \`acespeak-issuer\` — AceSpeak's own wallet | No, by design |\n`
            : `| **\`AUTH_BEGIN\`** | [\`${authBeginTx.slice(0, 16)}…\`](${CARDANOSCAN_TX(authBeginTx)}) | \`acespeak-issuer\` — AceSpeak's own wallet | No, by design |\n`;

    const block =
        `| | Transaction | Fee paid by | Counts as adoption |\n` +
        `|---|---|---|---|\n` +
        `| **\`ATTEST\`** | [\`${attestTx.slice(0, 16)}…\`](${CARDANOSCAN_TX(attestTx)}) | \`learner-demo\` — funded independently from the faucet | **Yes** |\n` +
        authRow;

    writeFileSync(
        path,
        readme.replace(pending, block) +
            `\n<!-- attest: ${attestTx} -->\n` +
            `<!-- learner: ${CARDANOSCAN_ADDRESS(wallets.learner)} -->\n` +
            `<!-- issuer:  ${CARDANOSCAN_ADDRESS(wallets.issuer)} -->\n`
    );
    console.log('\nREADME updated with the real hashes.');
}

async function main(): Promise<void> {
    loadEnv();

    const wallets = JSON.parse(readFileSync(artifact('wallets-public.json'), 'utf8')) as {
        acespeakIssuer: { address: string };
        learnerDemo: { address: string };
    };
    const learner = wallets.learnerDemo.address;
    const issuer = wallets.acespeakIssuer.address;

    const balance = await balances([learner, issuer]);
    const ada = (n: bigint) => `${(Number(n) / 1_000_000).toFixed(2)} tADA`;

    console.log(`  learner-demo     ${ada(balance[learner]!)}`);
    console.log(`  acespeak-issuer  ${ada(balance[issuer]!)}`);

    if (balance[learner] === 0n) {
        console.log('');
        console.log('learner-demo is not funded, and it pays the fee that actually counts.');
        console.log(`Fund it at ${FAUCET}:`);
        console.log('');
        console.log(`  ${learner}`);
        console.log('');
        console.log('Then run this again. Never move funds between the two wallets.');
        process.exit(1);
    }

    // ATTEST first: it is the transaction the whole spike exists to produce, and
    // it must not be held up if the issuer wallet is still waiting on the faucet.
    if (existsSync(artifact('attest.json'))) {
        console.log('\nATTEST already submitted; skipping.');
    } else {
        run('scripts/03-attest.ts');
    }

    const attest = JSON.parse(readFileSync(artifact('attest.json'), 'utf8')) as { txHash: string };

    let authBeginTx: string | null = null;
    if (balance[issuer] === 0n) {
        console.log('');
        console.log('acespeak-issuer is not funded, so AUTH_BEGIN is skipped for now.');
        console.log(`Fund it at ${FAUCET} and re-run:`);
        console.log('');
        console.log(`  ${issuer}`);
        console.log('');
        console.log('The faucet rate-limits, so this may need to wait a day. ATTEST already');
        console.log('carries the claim, so the spike stands without it.');
    } else if (existsSync(artifact('auth-begin.json'))) {
        authBeginTx = (JSON.parse(readFileSync(artifact('auth-begin.json'), 'utf8')) as { txHash: string }).txHash;
        console.log('\nAUTH_BEGIN already submitted; skipping.');
    } else {
        run('scripts/04-auth-begin.ts');
        authBeginTx = (JSON.parse(readFileSync(artifact('auth-begin.json'), 'utf8')) as { txHash: string }).txHash;
    }

    console.log('\nVerifying the attestation against live chain data...');
    try {
        execFileSync('npx', ['tsx', 'src/verify.ts', attest.txHash], { stdio: 'inherit' });
    } catch {
        console.error('\nVerification did not return VALID. Do not publish until it does.');
        process.exit(1);
    }

    updateReadme(attest.txHash, authBeginTx, { learner, issuer });

    console.log('');
    console.log('Done. To publish:');
    console.log('');
    console.log('  git add -A && git commit -m "spike: record the preprod transactions"');
    console.log('  gh auth switch --user wistkeylab   # or: gh auth login');
    console.log('  gh repo create wistkeylab/acespeak-cip0170-spike --public --source=. --push');
    console.log('');
    console.log(`Then check it opens logged out, and add the URL plus ${CARDANOSCAN_TX(attest.txHash)}`);
    console.log('to the supporting-links field in the application.');
}

main().catch((error: unknown) => {
    console.error(error instanceof Error ? error.message : error);
    process.exit(1);
});

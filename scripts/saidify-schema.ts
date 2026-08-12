/**
 * Compute the SAID of the Communication Credential Profile schema and write it
 * into the schema's own `$id`.
 *
 * An ACDC schema is self-addressing: its identifier is the digest of its own
 * content, so a schema cannot be altered without changing the identifier every
 * credential references. That is what makes "the open profile" a real
 * commitment rather than a document that can be quietly edited later.
 *
 *   npx tsx scripts/saidify-schema.ts
 */
import { mkdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { ready, Saider } from 'signify-ts';

const SCHEMA = resolve(process.cwd(), 'schema/communication-credential-profile.v1.json');
const OOBI_DIR = resolve(process.cwd(), 'schema/oobi');

async function main(): Promise<void> {
    await ready();

    const schema = JSON.parse(readFileSync(SCHEMA, 'utf8')) as Record<string, unknown>;

    // Nested blocks are SAIDified first: an outer SAID computed over stale
    // inner SAIDs would not be reproducible by a verifier who re-derives from
    // the bottom up.
    const properties = schema.properties as Record<string, { oneOf?: Array<Record<string, unknown>> }>;
    const attributes = properties?.a;
    const attributeBlock = attributes?.oneOf?.[1];
    if (attributes?.oneOf === undefined || attributeBlock === undefined) {
        throw new Error('schema has no properties.a.oneOf[1] attributes block to SAIDify');
    }

    const [, saidifiedAttributes] = Saider.saidify(
        { ...attributeBlock, $id: '' },
        undefined,
        undefined,
        '$id'
    );
    attributes.oneOf[1] = saidifiedAttributes as Record<string, unknown>;

    const [, out] = Saider.saidify({ ...schema, $id: '' }, undefined, undefined, '$id');
    const said = (out as { $id: string }).$id;
    const serialised = JSON.stringify(out, null, 2) + '\n';

    writeFileSync(SCHEMA, serialised);

    // Publish it at the path an OOBI resolves to, so KERIA can fetch the schema
    // by its SAID. Rebuilt from scratch because a stale copy under a previous
    // SAID would silently keep resolving.
    rmSync(OOBI_DIR, { recursive: true, force: true });
    mkdirSync(OOBI_DIR, { recursive: true });
    writeFileSync(resolve(OOBI_DIR, said), serialised);

    console.log(`schema SAID: ${said}`);
    console.log(`served at:   http://localhost:7724/oobi/${said}`);
}

main().catch((error: unknown) => {
    console.error(error instanceof Error ? error.message : error);
    process.exit(1);
});

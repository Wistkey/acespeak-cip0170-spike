/**
 * Computing the CIP-0170 `d` digest over on-chain CBOR bytes.
 *
 * CIP-0170 (as clarified by cardano-foundation/CIPs#1253, which this repo's
 * findings prompted) defines `d` as the digest of the CBOR encoding of the
 * metadatum *value* at the application label — byte-identical to the bytes in
 * the transaction's auxiliary data. Not the label/value pair, not the whole
 * metadata map, and explicitly not any JSON re-serialisation.
 *
 * THE HAZARD THIS MODULE EXISTS TO AVOID
 *
 * `d` has to be anchored in the KEL *before* the transaction is built, and a
 * KEL is append-only. So if our encoding differs from the builder's by even one
 * byte, we anchor a digest that nothing on chain will ever match, and burn a
 * sequence number doing it. Encoding is therefore not a detail to approximate:
 *
 *   - {@link metadatumBytes} encodes exactly as the transaction builder does,
 *     via the same CML detailed-schema path, which preserves key order.
 *   - {@link extractMetadatumBytes} reads the bytes back out of a built or
 *     on-chain transaction, so the two can be compared before submitting.
 *
 * A worked example of getting this wrong is on preprod at f690640a…, left there
 * deliberately. See READINESS.md §3.2.
 */
import { CML } from '@lucid-evolution/lucid';
import { Diger, MtrDex } from 'signify-ts';

/**
 * CML's "detailed schema" representation: every value is a tagged object, and
 * maps are ordered lists of key/value pairs rather than JSON objects — which is
 * what preserves ordering through the encoder.
 *
 * This mirrors what the transaction builder does internally. Diverging from it
 * silently is the failure mode described above, which is why
 * `metadatum-matches-builder` in test/cbor.test.ts checks the result against
 * the bytes of a real published transaction.
 */
function toDetailedSchema(value: unknown): unknown {
    if (typeof value === 'string') return { string: value };
    if (typeof value === 'number') return { int: value };
    if (typeof value === 'bigint') return { int: Number(value) };
    if (value instanceof Uint8Array) return { bytes: Buffer.from(value).toString('hex') };
    if (Array.isArray(value)) return { list: value.map(toDetailedSchema) };
    if (value !== null && typeof value === 'object') {
        return {
            map: Object.entries(value).map(([k, v]) => ({
                k: toDetailedSchema(k),
                v: toDetailedSchema(v),
            })),
        };
    }
    throw new Error(`value of type ${typeof value} cannot be encoded as transaction metadata`);
}

/** Encode a metadatum value to the exact CBOR bytes the builder will embed. */
export function metadatumBytes(value: unknown): Uint8Array {
    const datum = CML.TransactionMetadatum.from_json(JSON.stringify(toDetailedSchema(value)));
    try {
        return datum.to_cbor_bytes();
    } finally {
        datum.free();
    }
}

/**
 * Read the CBOR bytes of one label's metadatum out of a transaction.
 *
 * Takes the transaction CBOR as hex — from a local node, Koios `/tx_cbor`, or
 * the builder's own output before submission.
 */
export function extractMetadatumBytes(txCborHex: string, label: number): Uint8Array {
    const tx = CML.Transaction.from_cbor_hex(txCborHex);
    try {
        const metadata = tx.auxiliary_data()?.metadata();
        if (metadata === undefined) {
            throw new Error(`transaction carries no metadata, so label ${label} is absent`);
        }
        const datum = metadata.get(BigInt(label) as never);
        if (datum === undefined) {
            throw new Error(`transaction carries no metadata at label ${label}`);
        }
        return datum.to_cbor_bytes();
    } finally {
        tx.free();
    }
}

/**
 * Digest metadatum bytes into a CESR qb64 primitive.
 *
 * Blake3-256, derivation code `E` — which CIP-0170 requires implementations to
 * support and recommends for new attestations.
 */
export function digestMetadatum(bytes: Uint8Array): string {
    return new Diger({ code: MtrDex.Blake3_256 }, bytes).qb64;
}

/** Convenience: digest a value by encoding it first. Prefer digesting real bytes where you have them. */
export function digestOf(value: unknown): string {
    return digestMetadatum(metadatumBytes(value));
}

/**
 * A source of raw metadatum bytes, keyed by label.
 *
 * The verifier takes one of these rather than a parsed object, so there is no
 * API through which a JSON representation can be verified by mistake — which
 * CIP-0170 now forbids outright.
 */
export interface MetadatumSource {
    labels(): number[];
    /** Raw CBOR bytes for a label, or undefined if absent. */
    bytes(label: number): Uint8Array | undefined;
}

/** Read metadatum bytes straight out of a transaction. */
export function fromTransactionCbor(txCborHex: string): MetadatumSource {
    const tx = CML.Transaction.from_cbor_hex(txCborHex);
    const metadata = tx.auxiliary_data()?.metadata();

    const found = new Map<number, Uint8Array>();
    if (metadata !== undefined) {
        const labels = metadata.labels();
        for (let n = 0; n < labels.len(); n++) {
            const label = labels.get(n);
            const datum = metadata.get(label);
            if (datum !== undefined) found.set(Number(label), datum.to_cbor_bytes());
        }
    }
    tx.free();

    return {
        labels: () => [...found.keys()],
        bytes: (label) => found.get(label),
    };
}

/** Build a source directly from bytes. Used by tests to construct cases a real transaction cannot cheaply produce. */
export function fromMetadatumBytes(entries: Record<number, Uint8Array>): MetadatumSource {
    const found = new Map(Object.entries(entries).map(([k, v]) => [Number(k), v]));
    return { labels: () => [...found.keys()], bytes: (label) => found.get(label) };
}

/** Decode a metadatum's bytes to a plain value, for reading fields that are not digested. */
export function decodeMetadatum(bytes: Uint8Array): unknown {
    const datum = CML.TransactionMetadatum.from_cbor_bytes(bytes);
    try {
        return fromDetailedSchema(JSON.parse(datum.to_json()));
    } finally {
        datum.free();
    }
}

function fromDetailedSchema(node: unknown): unknown {
    if (node === null || typeof node !== 'object') return node;
    const n = node as Record<string, unknown>;
    if ('string' in n) return n.string;
    if ('int' in n) return Number(n.int);
    if ('bytes' in n) return n.bytes;
    if ('list' in n) return (n.list as unknown[]).map(fromDetailedSchema);
    if ('map' in n) {
        const out: Record<string, unknown> = {};
        for (const pair of n.map as Array<{ k: unknown; v: unknown }>) {
            out[String(fromDetailedSchema(pair.k))] = fromDetailedSchema(pair.v);
        }
        return out;
    }
    return node;
}

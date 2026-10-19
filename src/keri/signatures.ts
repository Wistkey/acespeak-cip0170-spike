/**
 * Cryptographic verification of a Key Event Log.
 *
 * {@link ./kel.ts} establishes what a KEL stream *says* and that its events
 * name each other in order. That alone is not proof: an event can be edited
 * while keeping its `d` field, and the chain still looks intact. This module
 * checks what makes a KEL authentic:
 *
 *   1. Each event's SAID: `d` (and `i` on inception) is the Blake3-256 digest
 *      of the event with those fields blanked to 44 `#` characters.
 *   2. Controller signatures: at least `kt` of the current keys `k` signed
 *      the event's exact bytes (indexed signatures, attachment group `-A`).
 *   3. Witness receipts: at least `bt` (the TOAD) of the current witnesses
 *      `b` signed the event (indexed witness signatures, group `-B`). Witness
 *      identifiers are non-transferable (`B…`), so each is its own public key.
 *   4. Rotation: the new keys were pre-committed as next-key digests `n`, and
 *      the witness list moves by `br` (cuts) and `ba` (adds).
 *
 * Scope: Ed25519 keys, numeric thresholds, non-delegated identifiers — what
 * KERIA produced for this spike. Anything else is rejected, never skipped.
 */
import { ed25519 } from '@noble/curves/ed25519.js';
import { blake3 } from '@noble/hashes/blake3.js';

const B64 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';
const utf8 = new TextEncoder();
const decoder = new TextDecoder();

export class KelSignatureError extends Error {
    constructor(message: string) {
        super(message);
        this.name = 'KelSignatureError';
    }
}

function b64Decode(text: string): Uint8Array {
    const out: number[] = [];
    let bits = 0;
    let acc = 0;
    for (const ch of text) {
        const v = B64.indexOf(ch);
        if (v < 0) throw new KelSignatureError(`bad base64url character "${ch}"`);
        acc = (acc << 6) | v;
        bits += 6;
        if (bits >= 8) {
            bits -= 8;
            out.push((acc >> bits) & 0xff);
        }
    }
    return new Uint8Array(out);
}

function b64Encode(bytes: Uint8Array): string {
    let out = '';
    let bits = 0;
    let acc = 0;
    for (const b of bytes) {
        acc = (acc << 8) | b;
        bits += 8;
        while (bits >= 6) {
            bits -= 6;
            out += B64[(acc >> bits) & 0x3f];
        }
    }
    if (bits > 0) out += B64[(acc << (6 - bits)) & 0x3f];
    return out;
}

const b64Int = (text: string) => [...text].reduce((n, ch) => n * 64 + B64.indexOf(ch), 0);

/** CESR qb64 of a Blake3-256 digest (derivation code `E`). */
export function blake3Qb64(data: Uint8Array): string {
    return 'E' + b64Encode(new Uint8Array([0, ...blake3(data)])).slice(1);
}

/** The raw 32-byte Ed25519 key of a qb64 key: `D` (transferable) or `B` (non-transferable). */
function publicKey(qb64: string): Uint8Array {
    if (qb64.length !== 44 || (qb64[0] !== 'D' && qb64[0] !== 'B')) {
        throw new KelSignatureError(`unsupported key type "${qb64.slice(0, 4)}…" (only Ed25519 is supported)`);
    }
    return b64Decode(qb64).subarray(1);
}

interface Message {
    raw: Uint8Array;
    event: Record<string, unknown> & { t: string; d: string; i: string; s: string };
    /** Controller signatures: [index into `k`, signature]. */
    controller: Array<[number, Uint8Array]>;
    /** Witness signatures: [index into the current `b`, signature]. */
    witness: Array<[number, Uint8Array]>;
}

/** Parse a CESR stream into messages with their raw bytes and the signatures attached to each. */
function parseSigned(stream: string): Message[] {
    const text = stream.trim();
    const out: Message[] = [];
    let o = 0;
    while (o < text.length) {
        const m = /^\{"v":"(?:KERI|ACDC)10JSON([0-9a-f]{6})_"/.exec(text.slice(o, o + 32));
        if (!m) throw new KelSignatureError(`expected a message at offset ${o}`);
        const size = parseInt(m[1]!, 16);
        const raw = utf8.encode(text).slice(utf8.encode(text.slice(0, o)).length, utf8.encode(text.slice(0, o)).length + size);
        const json = decoder.decode(raw);
        o += json.length;
        const controller: Array<[number, Uint8Array]> = [];
        const witness: Array<[number, Uint8Array]> = [];
        let groupEnd = text.length;
        while (o < groupEnd && text[o] === '-') {
            const code = text.slice(o, o + 2);
            const count = b64Int(text.slice(o + 2, o + 4));
            o += 4;
            if (code === '-V') {
                groupEnd = o + count * 4; // attachment group, sized in quadlets
            } else if (code === '-A' || code === '-B') {
                for (let n = 0; n < count; n++, o += 88) {
                    const sig = text.slice(o, o + 88);
                    if (sig[0] !== 'A' && sig[0] !== 'B') throw new KelSignatureError(`unsupported signature code "${sig[0]}"`);
                    (code === '-A' ? controller : witness).push([B64.indexOf(sig[1]!), b64Decode(sig).subarray(2)]);
                }
            } else if (code === '-C') {
                o += count * (44 + 88); // non-transferable receipt couples (on `rpy` messages)
            } else if (code === '-E') {
                o += count * (24 + 36); // first-seen replay couples (sequence, datetime)
            } else {
                throw new KelSignatureError(`unsupported attachment group "${code}"`);
            }
        }
        if (groupEnd !== text.length && o !== groupEnd) throw new KelSignatureError('attachment group size does not match its contents');
        out.push({ raw, event: JSON.parse(json), controller, witness });
    }
    return out;
}

function threshold(value: unknown, of: number, what: string): number {
    if (typeof value !== 'string' || !/^[0-9a-f]+$/.test(value)) {
        throw new KelSignatureError(`${what} threshold ${JSON.stringify(value)} is not numeric (weighted thresholds are not supported)`);
    }
    const n = parseInt(value, 16);
    if (n > of) throw new KelSignatureError(`${what} threshold ${n} exceeds the ${of} available`);
    return n;
}

function countValid(sigs: Array<[number, Uint8Array]>, keys: readonly string[], raw: Uint8Array): number {
    const good = new Set<number>();
    for (const [index, sig] of sigs) {
        const key = keys[index];
        if (key !== undefined && ed25519.verify(sig, raw, publicKey(key))) good.add(index);
    }
    return good.size;
}

export interface KelVerification {
    ok: boolean;
    reason?: string;
    /** Per key event: controller signatures and witness receipts that verified. */
    events: Array<{ s: string; t: string; signatures: number; receipts: number }>;
}

/**
 * Verify a KEL cryptographically, from inception: SAIDs, controller signatures
 * against the current keys and threshold, witness receipts against the current
 * witnesses and TOAD, and pre-rotation. Non-key messages (`rpy`) are skipped.
 */
export function verifyKelSignatures(stream: string, aid: string): KelVerification {
    const events: KelVerification['events'] = [];
    let keys: string[] = [];
    let kt = 0;
    let next: string[] = [];
    let nt = 0;
    let witnesses: string[] = [];
    let toad = 0;
    let previous: string | undefined;
    try {
        const messages = parseSigned(stream).filter((m) => ['icp', 'rot', 'ixn', 'dip', 'drt'].includes(m.event.t));
        if (!messages.length) return { ok: false, reason: 'KEL is empty', events };
        for (const [n, { raw, event, controller, witness }] of messages.entries()) {
            const where = `event ${event.s} (${event.t})`;
            if (event.t === 'dip' || event.t === 'drt') throw new KelSignatureError(`${where}: delegated identifiers are not supported`);
            if (event.i !== aid) throw new KelSignatureError(`${where} belongs to ${event.i}, not ${aid}`);
            if (parseInt(event.s, 16) !== n) throw new KelSignatureError(`${where} is out of sequence (expected ${n.toString(16)})`);
            if (n === 0 ? event.t !== 'icp' : event.t === 'icp') throw new KelSignatureError(`${where} is in the wrong place`);
            if (n > 0 && event.p !== previous) throw new KelSignatureError(`${where} does not chain to the previous event`);

            // 1. SAID over the exact serialisation, with `d` (and `i` on inception) blanked.
            if (JSON.stringify(event) !== decoder.decode(raw)) throw new KelSignatureError(`${where} is not in compact JSON form`);
            const blank = '#'.repeat(44);
            const blanked = { ...event, d: blank, ...(event.t === 'icp' ? { i: blank } : {}) };
            if (blake3Qb64(utf8.encode(JSON.stringify(blanked))) !== event.d) throw new KelSignatureError(`${where}: SAID does not match its content`);
            if (event.t === 'icp' && event.i !== event.d) throw new KelSignatureError(`${where}: identifier is not self-addressing`);

            // 4. Establishment events set the keys, the next-key commitment and the witnesses.
            if (event.t === 'icp' || event.t === 'rot') {
                const k = event.k as string[];
                if (!Array.isArray(k) || !k.length) throw new KelSignatureError(`${where} has no keys`);
                if (event.t === 'rot') {
                    const committed = k.filter((key) => next.includes(blake3Qb64(utf8.encode(key)))).length;
                    if (committed < nt) throw new KelSignatureError(`${where}: rotated to keys that were not pre-committed`);
                    const cuts = (event.br as string[]) ?? [];
                    witnesses = [...witnesses.filter((w) => !cuts.includes(w)), ...((event.ba as string[]) ?? [])];
                } else {
                    witnesses = (event.b as string[]) ?? [];
                }
                keys = k;
                kt = threshold(event.kt, keys.length, 'signing');
                next = (event.n as string[]) ?? [];
                if (!next.length) throw new KelSignatureError(`${where}: non-transferable identifiers are not supported`);
                nt = threshold(event.nt, next.length, 'next-key');
                toad = threshold(event.bt, witnesses.length, 'witness (TOAD)');
            }

            // 2. Controller signatures, 3. witness receipts.
            const signatures = countValid(controller, keys, raw);
            if (signatures < kt) throw new KelSignatureError(`${where}: ${signatures} valid controller signature(s), needs ${kt}`);
            const receipts = countValid(witness, witnesses, raw);
            if (receipts < toad) throw new KelSignatureError(`${where}: ${receipts} valid witness receipt(s), needs ${toad} of ${witnesses.length}`);

            events.push({ s: event.s, t: event.t, signatures, receipts });
            previous = event.d;
        }
        return { ok: true, events };
    } catch (error) {
        return { ok: false, reason: error instanceof Error ? error.message : String(error), events };
    }
}

/**
 * Reading a Key Event Log.
 *
 * A KEL arrives as a CESR stream: each event is a JSON object introduced by a
 * 17-character version string that declares its own byte length, immediately
 * followed by CESR attachments (signatures, witness receipts) that are not
 * JSON. So the stream cannot be parsed as JSON, and it cannot be split on
 * braces either — the declared length is the only reliable frame boundary.
 *
 *   {"v":"KERI10JSON0000fd_","t":"ixn",...}-AABAAD9dcRM...{"v":"KERI10JSON...
 *   |<------------ 0xfd bytes ----------->||<- attachments ->|
 *
 * This module reads that structure and answers the question CIP-0170 asks of a
 * verifier: is `digest` anchored as a seal in this identifier's KEL at sequence
 * number `s`?
 */

/** A KERI key event. Only the fields this spike relies on are named. */
export interface KeriEvent {
    /** Version string, e.g. `KERI10JSON0000fd_`. */
    v: string;
    /** Event type: `icp`, `rot`, `ixn`, `dip`, `drt`. */
    t: string;
    /** The event's own self-addressing identifier. */
    d: string;
    /** The identifier (AID) this KEL belongs to. */
    i: string;
    /** Sequence number, hex-encoded. */
    s: string;
    /** Digest of the prior event. Absent on inception. */
    p?: string;
    /** Anchored seals. */
    a?: unknown[];
    [key: string]: unknown;
}

export class KelParseError extends Error {
    constructor(message: string) {
        super(message);
        this.name = 'KelParseError';
    }
}

/** `KERI` | major | minor | serialisation | 6 hex size digits | `_` */
const VERSION_STRING = /(KERI|ACDC)([0-9a-f])([0-9a-f])([A-Z]{4})([0-9a-f]{6})_/g;

const utf8 = new TextEncoder();
const decoder = new TextDecoder();

/**
 * The message types that actually form a Key Event Log.
 *
 * A witness OOBI endpoint serves more than the KEL: `rpy` messages carrying
 * endpoint-role and location-scheme records are interleaved with the events.
 * They have no sequence number and no place in the chain, so they must be
 * filtered out before any linkage check — otherwise a perfectly good KEL fails
 * verification for reasons that have nothing to do with its integrity.
 */
const KEY_EVENT_TYPES: ReadonlySet<string> = new Set(['icp', 'rot', 'ixn', 'dip', 'drt']);

/**
 * Parse a CESR stream into every message it carries, discarding attachments.
 *
 * Discarding the attachments is a real limitation, not an oversight: it means
 * this parser establishes *what the stream says*, not that the controller
 * signed it. {@link verifyKelLinkage} covers tamper-evidence within the stream.
 * READINESS.md states the boundary plainly.
 */
export function parseCesrStream(stream: string): KeriEvent[] {
    const trimmed = stream.trim();
    if (trimmed === '') return [];

    // Work in bytes: the version string declares a byte length, and a
    // character-indexed slice would drift on any non-ASCII content.
    const bytes = utf8.encode(trimmed);
    const events: KeriEvent[] = [];

    VERSION_STRING.lastIndex = 0;
    let match: RegExpExecArray | null;

    while ((match = VERSION_STRING.exec(trimmed)) !== null) {
        const size = parseInt(match[5]!, 16);

        // The frame starts at the opening brace of the object, which sits a
        // fixed `{"v":"` ahead of the version string itself.
        const versionByteOffset = utf8.encode(trimmed.slice(0, match.index)).length;
        const start = versionByteOffset - '{"v":"'.length;

        if (start < 0) {
            throw new KelParseError(`version string at offset ${match.index} is not at the start of an event`);
        }
        if (start + size > bytes.length) {
            throw new KelParseError(
                `event at offset ${start} declares ${size} bytes but only ${bytes.length - start} remain — stream is truncated`
            );
        }

        const raw = decoder.decode(bytes.slice(start, start + size));

        let event: KeriEvent;
        try {
            event = JSON.parse(raw) as KeriEvent;
        } catch {
            throw new KelParseError(
                `event at offset ${start} declares ${size} bytes but that span is not valid JSON`
            );
        }

        events.push(event);

        // Resume scanning past this frame so version strings that happen to
        // appear inside attachments are not mistaken for new events.
        VERSION_STRING.lastIndex = decoder.decode(bytes.slice(0, start + size)).length;
    }

    return events;
}

/**
 * Parse a CESR stream into the key events that form the KEL, dropping the
 * reply messages a witness interleaves with them.
 *
 * This is what a verifier wants: the chain itself, ready for
 * {@link verifyKelLinkage} and {@link findEventBySequence}.
 */
export function parseKel(stream: string): KeriEvent[] {
    return parseCesrStream(stream).filter((event) => KEY_EVENT_TYPES.has(event.t));
}

/**
 * Find the event at a sequence number.
 *
 * Compares numerically. CIP-0170 hex-encodes `s` (its example renders the 26th
 * event as `1a`), and a string comparison would miss `01` against `1` — and,
 * worse, silently match the wrong event once past the ninth.
 */
export function findEventBySequence(
    events: readonly KeriEvent[],
    sequenceNumber: string
): KeriEvent | undefined {
    const target = parseInt(sequenceNumber, 16);
    if (Number.isNaN(target)) return undefined;

    return events.find((e) => parseInt(e.s, 16) === target);
}

/** Is `digest` anchored as a `{ d: ... }` seal in this event? */
export function hasDigestSeal(event: KeriEvent, digest: string): boolean {
    if (!Array.isArray(event.a)) return false;

    return event.a.some(
        (seal) =>
            seal !== null &&
            typeof seal === 'object' &&
            (seal as { d?: unknown }).d === digest
    );
}

export interface LinkageResult {
    ok: boolean;
    reason?: string;
}

/**
 * Check that a KEL is internally consistent: one identifier, starting at
 * inception, with no gaps and every event naming its predecessor's digest.
 *
 * This is what makes the committed `artifacts/issuer-kel.cesr` tamper-evident
 * without a live witness: altering an event breaks the `p` link of the one
 * after it. It does not verify signatures — see the module note.
 */
export function verifyKelLinkage(events: readonly KeriEvent[]): LinkageResult {
    if (events.length === 0) return { ok: false, reason: 'KEL is empty' };

    const first = events[0]!;
    if (first.t !== 'icp' && first.t !== 'dip') {
        return { ok: false, reason: `KEL does not begin with an inception event (found "${first.t}")` };
    }
    if (parseInt(first.s, 16) !== 0) {
        return { ok: false, reason: `inception event has sequence number ${first.s}, expected 0` };
    }

    const aid = first.i;

    for (let n = 1; n < events.length; n++) {
        const event = events[n]!;
        const previous = events[n - 1]!;

        if (event.i !== aid) {
            return {
                ok: false,
                reason: `event ${event.s} belongs to identifier ${event.i}, not ${aid}`,
            };
        }
        if (parseInt(event.s, 16) !== parseInt(previous.s, 16) + 1) {
            return {
                ok: false,
                reason: `sequence jumps from ${previous.s} to ${event.s} — the KEL has a gap`,
            };
        }
        if (event.p !== previous.d) {
            return {
                ok: false,
                reason: `event ${event.s} names prior digest ${event.p}, but event ${previous.s} is ${previous.d}`,
            };
        }
    }

    return { ok: true };
}

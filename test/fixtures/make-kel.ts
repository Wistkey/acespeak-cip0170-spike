/**
 * Builds structurally-real KERI streams for tests.
 *
 * The framing is exact — a correct `KERI10JSON{size}_` version string, events
 * concatenated with CESR attachments between them — so the parser is exercised
 * against the real format. The SAIDs and signatures are not cryptographically
 * derived, so these fixtures prove framing and linkage only. Anything that
 * depends on real derivation is tested against artifacts/issuer-kel.cesr.
 */

export interface FixtureEvent {
    t: string;
    d: string;
    /** Absent on `rpy` messages, which are not key events. */
    i?: string;
    /** Absent on `rpy` messages, which have no place in the chain. */
    s?: string;
    p?: string;
    a?: unknown;
    [key: string]: unknown;
}

/** Serialise one event with a correctly-sized KERI version string. */
export function frame(event: FixtureEvent): string {
    const withPlaceholder = { v: 'KERI10JSON000000_', ...event };
    const size = new TextEncoder().encode(JSON.stringify(withPlaceholder)).length;
    const versioned = {
        ...withPlaceholder,
        v: `KERI10JSON${size.toString(16).padStart(6, '0')}_`,
    };
    return JSON.stringify(versioned);
}

/** A plausible CESR attachment group, as a witness or controller signature would appear. */
export const ATTACHMENT = '-AABAAD9dcRMSCyugcXPncXNw2Xw5EnyMJfXdJgLXcMYpJRfQmNBqvTx3lJXfvfCkzGYYE_YJJZ8pCQ8vB0eO0gJmuAF';

/**
 * Build a KEL: an inception event followed by interaction events, each carrying
 * whatever seals the caller asks for.
 */
export function makeKel(
    aid: string,
    interactionSeals: ReadonlyArray<readonly unknown[]>
): { stream: string; events: FixtureEvent[] } {
    const events: FixtureEvent[] = [];
    const digestOf = (n: number) => `E${String(n).padStart(3, '0')}AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA`;

    events.push({ t: 'icp', d: digestOf(0), i: aid, s: '0' });

    interactionSeals.forEach((seals, idx) => {
        const n = idx + 1;
        events.push({
            t: 'ixn',
            d: digestOf(n),
            i: aid,
            s: n.toString(16),
            p: digestOf(n - 1),
            a: [...seals],
        });
    });

    const stream = events.map((e) => frame(e) + ATTACHMENT).join('');
    return { stream, events };
}

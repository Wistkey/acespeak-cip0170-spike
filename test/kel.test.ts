import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { describe, expect, test } from 'vitest';
import {
    findEventBySequence,
    hasDigestSeal,
    KelParseError,
    parseCesrStream,
    parseKel,
    verifyKelLinkage,
} from '../src/keri/kel.ts';
import { ATTACHMENT, frame, makeKel } from './fixtures/make-kel.ts';

const AID = 'EKtQ1lymrnrh3qv5S18PBzQ7ukHGFJ7EXkH7B22XEMIL';
const DIGEST = 'ELC5L3iBVD77d_MYbYGGCUQgqQBju1o4x1Ud-z2sL-ux';

/**
 * A witness serves more than key events on its OOBI endpoint: `rpy` messages
 * carrying endpoint and location records are interleaved with the KEL. They
 * have no sequence number and are not part of the chain, so treating them as
 * events breaks linkage verification outright.
 */
const WITNESS_RPY = frame({
    t: 'rpy',
    d: 'EPnS5DzgxoZY-04Mvj5hd8kAUHaGxSpmWQ6vGVvQLn3o',
    dt: '2026-08-12T10:47:00.000000+00:00',
    r: '/loc/scheme',
    a: { eid: 'BBilc4-L3tFUnfM_wJr4S4OJanAv_VmF_dJNN6vkf2Ha', scheme: 'http', url: 'http://witness-demo:5642/' },
});

describe('parseKel', () => {
    test('extracts every event from a stream, in order', () => {
        const { stream } = makeKel(AID, [[{ d: DIGEST }], [{ d: 'EOther' }]]);

        const events = parseKel(stream);

        expect(events.map((e) => e.s)).toEqual(['0', '1', '2']);
    });

    test('skips the CESR attachments that follow each event', () => {
        const { stream } = makeKel(AID, [[{ d: DIGEST }]]);

        const events = parseKel(stream);

        expect(events).toHaveLength(2);
        expect(events[1]!.t).toBe('ixn');
    });

    test('preserves seals verbatim', () => {
        const { stream } = makeKel(AID, [[{ d: DIGEST }]]);

        expect(parseKel(stream)[1]!.a).toEqual([{ d: DIGEST }]);
    });

    test('returns no events for an empty stream', () => {
        expect(parseKel('')).toEqual([]);
    });

    test('tolerates leading and trailing whitespace', () => {
        const { stream } = makeKel(AID, []);

        expect(parseKel(`\n  ${stream}  \n`)).toHaveLength(1);
    });

    test('rejects a stream whose frame is truncated', () => {
        const { stream } = makeKel(AID, [[{ d: DIGEST }]]);

        expect(() => parseKel(stream.slice(0, stream.length - 200))).toThrow(KelParseError);
    });

    test('drops the rpy messages a witness interleaves with the KEL', () => {
        const { stream } = makeKel(AID, [[{ d: DIGEST }]]);
        const withReplies = stream + WITNESS_RPY + ATTACHMENT;

        const events = parseKel(withReplies);

        expect(events.map((e) => e.t)).toEqual(['icp', 'ixn']);
    });

    test('keeps a KEL verifiable even when reply messages sit between events', () => {
        const { stream } = makeKel(AID, [[{ d: DIGEST }]]);
        const interleaved = stream + WITNESS_RPY + ATTACHMENT;

        expect(verifyKelLinkage(parseKel(interleaved))).toEqual({ ok: true });
    });

    test('rejects a frame whose declared size does not match its content', () => {
        // Declare 900 bytes for an event that is nowhere near that long.
        const lying = frame({ t: 'icp', d: 'E0', i: AID, s: '0' }).replace(
            /KERI10JSON[0-9a-f]{6}_/,
            'KERI10JSON000384_'
        );

        expect(() => parseKel(lying + ATTACHMENT)).toThrow(KelParseError);
    });
});

describe('parseCesrStream', () => {
    test('keeps every message, including the replies parseKel drops', () => {
        const { stream } = makeKel(AID, [[{ d: DIGEST }]]);

        const messages = parseCesrStream(stream + WITNESS_RPY + ATTACHMENT);

        expect(messages.map((m) => m.t)).toEqual(['icp', 'ixn', 'rpy']);
    });
});

describe('the committed issuer KEL', () => {
    // artifacts/issuer-kel.cesr is the evidence a curator verifies against, so
    // it has to parse and chain-verify with no network and no KERIA running.
    const kel = readFileSync(resolve(__dirname, '../artifacts/issuer-kel.cesr'), 'utf8');

    test('parses into key events', () => {
        expect(parseKel(kel).length).toBeGreaterThan(0);
    });

    test('begins with an inception event', () => {
        expect(parseKel(kel)[0]!.t).toBe('icp');
    });

    test('passes linkage verification', () => {
        expect(verifyKelLinkage(parseKel(kel))).toEqual({ ok: true });
    });

    test('contains only key events, no reply messages', () => {
        for (const event of parseKel(kel)) {
            expect(['icp', 'rot', 'ixn', 'dip', 'drt']).toContain(event.t);
        }
    });
});

describe('findEventBySequence', () => {
    test('finds the event at a hex sequence number', () => {
        const { stream } = makeKel(AID, [[{ d: 'E1' }], [{ d: DIGEST }]]);

        expect(findEventBySequence(parseKel(stream), '2')!.a).toEqual([{ d: DIGEST }]);
    });

    test('compares numerically, so a zero-padded sequence still matches', () => {
        const { stream } = makeKel(AID, [[{ d: DIGEST }]]);

        expect(findEventBySequence(parseKel(stream), '01')).toBeDefined();
    });

    test('finds an event past the tenth, where hex and decimal diverge', () => {
        const seals = Array.from({ length: 12 }, (_, i) => [{ d: `E${i}` }]);
        const events = parseKel(makeKel(AID, seals).stream);

        // Event 11 is "b" in hex. A decimal-minded lookup would find the wrong one.
        expect(findEventBySequence(events, 'b')!.a).toEqual([{ d: 'E10' }]);
    });

    test('returns undefined when no event has that sequence number', () => {
        const { stream } = makeKel(AID, [[{ d: DIGEST }]]);

        expect(findEventBySequence(parseKel(stream), 'ff')).toBeUndefined();
    });
});

describe('hasDigestSeal', () => {
    test('finds a digest seal anchored in the event', () => {
        const { stream } = makeKel(AID, [[{ d: DIGEST }]]);
        const event = findEventBySequence(parseKel(stream), '1')!;

        expect(hasDigestSeal(event, DIGEST)).toBe(true);
    });

    test('finds the seal even when other seals sit beside it', () => {
        const { stream } = makeKel(AID, [[{ d: 'EOther' }, { d: DIGEST }]]);
        const event = findEventBySequence(parseKel(stream), '1')!;

        expect(hasDigestSeal(event, DIGEST)).toBe(true);
    });

    test('rejects a digest that is not anchored', () => {
        const { stream } = makeKel(AID, [[{ d: 'ESomethingElse' }]]);
        const event = findEventBySequence(parseKel(stream), '1')!;

        expect(hasDigestSeal(event, DIGEST)).toBe(false);
    });

    test('rejects an event with no seals at all', () => {
        const { stream } = makeKel(AID, []);

        expect(hasDigestSeal(parseKel(stream)[0]!, DIGEST)).toBe(false);
    });
});

describe('verifyKelLinkage', () => {
    test('accepts a well-formed chain', () => {
        const { stream } = makeKel(AID, [[{ d: DIGEST }], [{ d: 'E2' }]]);

        expect(verifyKelLinkage(parseKel(stream))).toEqual({ ok: true });
    });

    test('rejects a chain whose prior-event digest does not match', () => {
        const { stream } = makeKel(AID, [[{ d: DIGEST }]]);
        const events = parseKel(stream);
        events[1]!.p = 'ETamperedPriorDigest';

        const result = verifyKelLinkage(events);

        expect(result.ok).toBe(false);
        expect(result.reason).toMatch(/prior/i);
    });

    test('rejects a chain with a gap in the sequence', () => {
        const { stream } = makeKel(AID, [[{ d: DIGEST }], [{ d: 'E2' }]]);
        const events = parseKel(stream);
        events.splice(1, 1);

        const result = verifyKelLinkage(events);

        expect(result.ok).toBe(false);
        expect(result.reason).toMatch(/sequence/i);
    });

    test('rejects a chain that does not begin with an inception event', () => {
        const { stream } = makeKel(AID, [[{ d: DIGEST }]]);
        const events = parseKel(stream).slice(1);

        const result = verifyKelLinkage(events);

        expect(result.ok).toBe(false);
        expect(result.reason).toMatch(/inception/i);
    });

    test('rejects a chain mixing two identifiers', () => {
        const { stream } = makeKel(AID, [[{ d: DIGEST }]]);
        const events = parseKel(stream);
        events[1]!.i = 'EDifferentIdentifier';

        const result = verifyKelLinkage(events);

        expect(result.ok).toBe(false);
        expect(result.reason).toMatch(/identifier/i);
    });

    test('rejects an empty KEL', () => {
        expect(verifyKelLinkage([]).ok).toBe(false);
    });
});

import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import { blake3Qb64, verifyKelSignatures } from '../src/keri/signatures.ts';

const KEL = readFileSync(new URL('../artifacts/issuer-kel.cesr', import.meta.url), 'utf8');
const AID = 'ENIjVYIWIcxMekADdujdjlmLt0m8XKDiHVLsAkdRc_o2';

describe('verifyKelSignatures (real KERIA KEL)', () => {
    it('verifies every event: SAID, controller signature, witness receipts', () => {
        const r = verifyKelSignatures(KEL, AID);
        expect(r.ok).toBe(true);
        expect(r.events).toHaveLength(7);
        for (const e of r.events) {
            expect(e.signatures).toBe(1);
            expect(e.receipts).toBeGreaterThanOrEqual(2); // TOAD 2 of 3
        }
    });

    it('rejects an event whose content changed but kept its d', () => {
        // Swap an anchored seal digest in event 6; d (and so the chain) is untouched.
        const seal = /"a":\[\{"i":"[^"]+","s":"[^"]+","d":"(E[A-Za-z0-9_-]{43})"\}\]/.exec(KEL)?.[1]
            ?? /"a":\[\{"d":"(E[A-Za-z0-9_-]{43})"\}\]/.exec(KEL)![1]!;
        const forged = KEL.replace(seal, 'E' + 'A'.repeat(43));
        expect(verifyKelSignatures(forged, AID)).toMatchObject({ ok: false, reason: expect.stringMatching(/SAID does not match/) });
    });

    it('rejects a forged controller signature', () => {
        const at = KEL.indexOf('-AABAA') + 6;
        const ch = KEL[at + 10] === 'A' ? 'B' : 'A';
        const forged = KEL.slice(0, at + 10) + ch + KEL.slice(at + 11);
        expect(verifyKelSignatures(forged, AID)).toMatchObject({ ok: false, reason: expect.stringMatching(/controller signature/) });
    });

    it('rejects an event receipted by fewer witnesses than the TOAD', () => {
        // Corrupt two of the three witness signatures on inception.
        const start = KEL.indexOf('-BAD') + 4;
        let forged = KEL;
        for (const off of [0, 88]) {
            const p = start + off + 10;
            forged = forged.slice(0, p) + (forged[p] === 'A' ? 'B' : 'A') + forged.slice(p + 1);
        }
        expect(verifyKelSignatures(forged, AID)).toMatchObject({ ok: false, reason: expect.stringMatching(/witness receipt\(s\), needs 2 of 3/) });
    });

    it('rejects a KEL presented for another identifier', () => {
        expect(verifyKelSignatures(KEL, 'E' + 'A'.repeat(43)).ok).toBe(false);
    });

    it('computes Blake3 qb64 digests as CIP-0170 specifies', () => {
        const bytes = Buffer.from('a36e63726564656e7469616c547970656a6d656d626572736869706d736368656d6156657273696f6e0168697373756564417474323032362d30382d32305430383a30303a30305a', 'hex');
        expect(blake3Qb64(bytes)).toBe('EOpMIJmAaiP4cZgmDkg8rVtl8YU4dDYf_gxrK2sNdfOR');
    });
});

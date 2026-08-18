import { describe, expect, test } from 'vitest';
import { KOIOS_PREPROD, normaliseKoiosMetadata, TransactionNotFoundError } from '../src/cardano/chain.ts';

// Real Koios /tx_metadata response shapes, taken from live preprod.
const WITH_METADATA = [
    {
        tx_hash: 'fd9b4ab86521959a350f0d97f2d73ffa72141b6b47d80d4b33553565a93dade1',
        metadata: { '55534473': { source: 'internal-sdk', version: '0.0.0-dev' } },
    },
];
const NO_METADATA = [
    { tx_hash: '790cd265b6bf57fba9ab4521074d75c58a515fce56c3e796819273c2c6c4f1ab', metadata: null },
];

describe('normaliseKoiosMetadata', () => {
    test('returns the metadata keyed by label', () => {
        expect(normaliseKoiosMetadata(WITH_METADATA, 'fd9b')).toEqual({
            '55534473': { source: 'internal-sdk', version: '0.0.0-dev' },
        });
    });

    test('returns an empty object for a transaction carrying no metadata', () => {
        expect(normaliseKoiosMetadata(NO_METADATA, '790c')).toEqual({});
    });

    test('throws when the transaction is not on chain at all', () => {
        expect(() => normaliseKoiosMetadata([], 'deadbeef')).toThrow(TransactionNotFoundError);
    });

    test('names the missing hash, so a typo is obvious', () => {
        expect(() => normaliseKoiosMetadata([], 'deadbeef')).toThrow(/deadbeef/);
    });

    test('rejects a response that is not an array', () => {
        expect(() => normaliseKoiosMetadata({ error: 'rate limited' }, 'abc')).toThrow(/unexpected/i);
    });
});

describe('KOIOS_PREPROD', () => {
    test('points at preprod and needs no API key', () => {
        expect(KOIOS_PREPROD).toBe('https://preprod.koios.rest/api/v1');
    });
});

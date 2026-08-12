import { optional } from './env.ts';

/**
 * The metadata label the Speaking Passport payload sits under, beside label 170.
 *
 * PROVISIONAL. CIP-0170's worked example puts application data at the label the
 * signer holds authority over (1447 in the spec's vLEI example). Catalyst
 * publishes its message-tag spec before onboarding, and at Milestone 1 this
 * becomes whatever that spec says. Overridable so the switch is a config
 * change, not a code change.
 */
export const ACESPEAK_METADATA_LABEL = Number(optional('ACESPEAK_METADATA_LABEL', '170170'));

/** Salt for deriving opaque holder references. Never the real one in this repo. */
export const HOLDER_REF_SALT = optional('HOLDER_REF_SALT', 'acespeak-preprod-spike-salt');

/** Cardano network the spike runs against. */
export const NETWORK = optional('CARDANO_NETWORK', 'preprod');

export const CARDANOSCAN_TX = (hash: string): string => `https://preprod.cardanoscan.io/transaction/${hash}`;
export const CARDANOSCAN_ADDRESS = (addr: string): string => `https://preprod.cardanoscan.io/address/${addr}`;

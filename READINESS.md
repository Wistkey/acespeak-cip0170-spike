# Readiness note

CIP-0170 is a **Proposed** standard, not a finalised one, and parts of the reference
toolchain are still maturing. This note records what we hit building the spike, what the
spike does and does not prove, and what we would do if a dependency slips. It is
deliberately specific: a vague "some components are still maturing" tells a reviewer
nothing.

---

## 1. What the spike proves

**The claim:** in a CIP-0170 `ATTEST` transaction, the field `i` carries AceSpeak's
identifier while the transaction is built, signed and paid for by someone else's wallet.

The spec supports this directly. Its `ATTEST` validation rule is entirely KERI-side:

> If the KEL of identifier `i` contains an event at sequence number `s` with a seal value
> of `{ d: "{{digest}}" }`, it serves as cryptographically verifiable proof.

Nothing there refers to the Cardano transaction's witness set. The proof is the KEL seal,
not the signature on the transaction — so the payer and the signer are free to be
different parties. `verify.ts` never looks at who signed the transaction, which is the
cleanest possible demonstration of the point.

This matters because Catalyst counts a fee only when it is **not** paid from the
applicant's own wallets. AceSpeak's adoption model therefore produces countable
transactions rather than sponsored ones.

## 2. What the spike does *not* prove

Stated plainly, because overclaiming here would be worse than a narrow scope honestly
described.

| Not verified | Why | What would close it |
|---|---|---|
| **Controller signatures on KEL events** | `verify.ts` parses the CESR stream and discards the attachments. It confirms the KEL is internally consistent — every event names its predecessor's digest, sequence numbers are gapless, one identifier throughout — which makes the committed KEL tamper-evident, but it does not verify the indexed signatures. | Verify each event's indexed signatures against the key state from the preceding establishment event, using signify-ts' `Verfer`. Scoped for the Pilot build, not the spike. |
| **Signing authority over the metadata label** | That requires validating the `AUTH_BEGIN` credential chain with an ACDC verifier. The spike publishes the chain but does not verify it back. | An ACDC v1 verifier in the public verifier service. |
| **Root of trust** | The credential chain is self-issued. | CIP-0170 is explicitly trust-agnostic about the root, so this is a later decision — rooting AceSpeak's chain under a stronger authority — not a Milestone 1 blocker. |
| **Mainnet behaviour** | Everything here is preprod. | Mainnet deployment is an explicit Pilot deliverable. |

## 3. Gaps in the spec we had to fill

Two places where CIP-0170 does not say enough to build against. We picked an approach and
documented it; both are worth raising with the CIP authors.

### 3.1 Metadata strings are capped at 64 bytes; the spec shows one byte-stream

`AUTH_BEGIN` and `AUTH_END` carry `c`, "the byte-stream of the credential chain". Cardano
rejects any metadata text string over 64 bytes. Our chain is **7,260 bytes** — 114 chunks.
The CIP defines no chunking convention, so we defined one: **`c` is an ordered array of
strings, each at most 64 bytes; concatenating them in order reproduces the stream.**

`assertMetadataValid()` enforces the limit before submission, with the offending path in
the error, because Blockfrost's rejection for an oversized node does not obviously point
at string length.

Related: the spec suggests qb2 "for brevity" but ships its example chain in qb64. We use
qb64. qb2 would be roughly 25% smaller and is worth switching to if a chain ever
approaches the ~16KB transaction limit. Ours does not — the full `AUTH_BEGIN` metadata
encodes to 8,221 bytes.

### 3.2 `d` has no canonical serialisation

The spec says `d` is "the digest of the data being signed" and its worked example computes
it over the sibling application metadata. It never fixes how that data is serialised
before digesting — and JSON key order, whitespace and number formatting all change the
result.

We sidestep the ambiguity: the application payload is **SAIDified**, so `d` is the
payload's own self-addressing identifier, derived by KERI's standard algorithm. Issuer and
verifier arrive at the same value with no convention to agree on beyond KERI itself. A
verifier re-derives it with `Saider.saidify` and compares.

A consequence worth noting: this puts the credential payload on-chain, so an attestation
verifies from a transaction hash alone with no off-chain file to fetch. That is why the
payload is minimal and non-identifying, and why `buildCredential()` refuses to build one
carrying a name, email, transcript or score rather than trusting a review checklist.

## 4. Toolchain rough edges we hit

Recorded because each cost real time and none is in the documentation.

1. **`weboftrust/keri-witness-demo` is amd64-only.** On Apple Silicon under Colima's
   default qemu emulation it dies immediately with
   `ERR: /usr/local/var/keri/ks/wan: Function not implemented` — LMDB's memory-mapped
   writes are not emulated. **Fix:** run Colima with Apple's virtualisation framework and
   Rosetta: `colima start --vm-type=vz --vz-rosetta`. All three services then come up
   healthy. `README.md` says this up front.

2. **`gleif/vlei` returned HTTP 200 with an empty body** for every schema SAID we asked
   for, including the one in its own healthcheck — so the healthcheck passes while the
   server serves nothing. Rather than debug that image, the spike **publishes its own
   schema** from an nginx container, which we wanted anyway: the Communication Credential
   Profile is a deliverable in its own right.

3. **signify-ts and KERIA must be a matched pair.** We pin `signify-ts@0.4.0` against
   `weboftrust/keria:0.4.0`. A mismatch surfaces as `Invalid sad for Serder` from KERIA,
   which does not point at the version.

4. **`RegistryResult` has no `regk`.** Reading one yields `undefined`, which propagates
   silently into an `iss` event missing its `ri` field and finally surfaces as the same
   opaque `Invalid sad for Serder`. The registry identifier is `regser.pre`. Noted in the
   code where it bites.

5. **Witness OOBI endpoints interleave `rpy` messages with key events.** These endpoint
   and location records have no sequence number and no place in the chain. Treating them
   as KEL entries makes a perfectly good KEL fail linkage verification, so `parseKel()`
   filters by event type. Our fixtures did not show this; the real KEL did, on the first
   run against live data.

## 5. Discovery, and why the KEL is committed

Watcher networks are not widely deployed. CIP-0170 acknowledges this and names publishing
an OOBI on a known persistent channel as the interim discovery mechanism.

The witness pool in `docker-compose.yaml` is localhost-only, so an OOBI pointing at it
resolves for nobody else — a reviewer running `verify.ts` against it would get INVALID for
reasons that have nothing to do with the attestation. So the issuer's KEL is **committed
to this repository** as `artifacts/issuer-kel.cesr`, and `verify.ts` reads it by default.
Verification therefore works offline, with no KERIA running and nothing of ours reachable.

`--oobi <url>` verifies against a live resolution instead, for anyone who wants to confirm
the committed copy matches what a witness serves.

This is an interim measure, not the production design. In production the issuer's witnesses
are publicly reachable and the OOBI is published on a stable AceSpeak-controlled URL.

## 6. Provisional choices

- **Application metadata label `170170`.** CIP-0170's example puts application data at the
  label the signer holds authority over. Catalyst publishes its message-tag spec before
  onboarding; at Milestone 1 this becomes whatever that spec says. It is a config value
  (`ACESPEAK_METADATA_LABEL`), not a constant in code, so the switch is a config change.
- **Communication Credential Profile v1** is a draft. Its SAID is
  `EPJf2sb-UftDmFkY2e8icfcA-RPeUVfkYQR3Qw2fAsAy`; being self-addressing, it cannot be
  edited without changing the identifier every credential references.

## 7. Fallbacks if the tooling slips

| If | Then |
|---|---|
| KERIA/signify-ts break compatibility mid-build | Pin both to the matched pair recorded here. The dependency is a KERI agent, not a specific one — `cf-signify-java` (Cardano Foundation) is the alternate implementation, and the metadata layer in `src/cardano/` is independent of both. |
| The witness-demo pool stays amd64-only and Rosetta regresses | Run witnesses natively from `keripy` (`kli witness demo`); no container involved. |
| CIP-0170 changes before finalisation | The changes land in `src/cardano/metadata.ts`, which is 200 lines with tests asserting the spec's worked example verbatim. A spec change fails those tests loudly rather than passing silently. |
| ACDC credential chains prove impractical on-chain | `ATTEST` stands alone and is the transaction Catalyst counts. `AUTH_BEGIN` is supporting evidence, which is why it is sequenced second. |

## 8. Reproducing this

Everything in `artifacts/` is committed evidence. `npm test` runs entirely offline — no
Docker, no network, no Blockfrost key — and covers the metadata builders against the
spec's worked example, the KEL parser against the real committed KEL, and the verifier
against both a genuine attestation and tampered ones.

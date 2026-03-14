# Draft Email — `rats@ietf.org` Introduction (Not Sent)

**Status:** Updated 2026-03-12 after `-01` audit cleanup. Draft is scoped for the first architectural intro on `rats@ietf.org`.

## Subject (draft)

`Introducing draft-tsyrulnikov-rats-attested-inference-receipt-01`

## Body (draft)

Hello RATS WG,

I would appreciate feedback on `draft-tsyrulnikov-rats-attested-inference-receipt-01`:

https://datatracker.ietf.org/doc/draft-tsyrulnikov-rats-attested-inference-receipt/

AIR defines an application-layer EAT/CWT profile for **per-inference** receipts. The goal is to carry a signed record of one inference event that binds:

- model identity / hash
- request and response hashes
- attestation-linked metadata
- limited runtime fields

The scope is intentionally narrow:

- one receipt per inference
- COSE_Sign1 envelope with CWT/EAT claims
- attestation-linked, but not a replacement for platform-specific attestation verification
- not an Attestation Result format
- not transport, appraisal policy, or transparency-log protocol

The main questions I would value feedback on are:

1. Does this kind of per-inference evidence artifact fit the RATS problem space?
2. Is the current role split reasonable, where AIR-local verification is separate from platform-specific attestation verification and key binding?
3. Does the current claim shape look like a reasonable use of CWT/EAT for this scope?

IPR disclosure:
https://datatracker.ietf.org/ipr/7182/

I have also reviewed `draft-messous-eat-ai` and see AIR as complementary: AIR is focused on per-inference execution evidence rather than general AI-agent identity or provenance claims.

Thanks for any feedback.

Borys Tsyrulnikov
Cyntrisec

## Notes Before Sending

- Keep the first post architectural. Do not add compliance, healthcare, legal, or NIST framing.
- Send this version only after `-01` is actually posted on Datatracker.
- If challenged on charter fit, answer narrowly: AIR is an application-layer EAT/CWT profile for per-inference evidence, not an Attestation Result format or appraisal-policy protocol.
- If challenged on "why not just attestation + logs?", answer: platform evidence proves workload state; ordinary logs are implementation-specific and often unsigned; AIR standardizes a signed per-inference artifact that a third party can verify independently.
- If challenged on malicious signers, answer: AIR only has end-to-end value when the receipt signing key is bound to an attested workload accepted by the verifier.
- If challenged on replay or relay attacks, answer:
  `AIR provides receipt-level replay resistance via eat_nonce, cti deduplication, and sequence_number, but it does not define transport or session binding. End-to-end TEE assurance still requires platform-specific verification of the attestation evidence and the binding between that evidence and the AIR signing key. Deployments that need stronger anti-relay guarantees must combine AIR with transport- or session-level mechanisms outside the AIR v1 scope.`

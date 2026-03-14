# Attested Inference Receipt (AIR) — Specification v1

A cryptographically signed proof that an ML inference was executed inside a hardware-attested confidential workload.

## Status

**v1.0:** FROZEN — All normative documents locked. Issue #80 (model_hash_scheme) resolved.

## Naming and RATS Positioning (Non-Normative)

- **AIR** in this specification means **Attested Inference Receipt** (EphemeralML) and is not the IHE Radiology **AI Results (AIR)** profile.
- AIR v1 is an application-specific receipt profile for confidential AI inference built on COSE_Sign1, CWT, and EAT profile identification, with AI-specific provenance claims (for example `model_id`, `model_hash`, `request_hash`, `response_hash`).
- AIR v1 is **not** an implementation of IETF EAR (EAT Attestation Results).
- In a RATS-based deployment, an external verifier can consume AIR v1 receipts plus platform attestation evidence and emit an EAR for relying-party policy decisions.

## Documents

| Document | Description |
|----------|-------------|
| [naming.md](naming.md) | Standard name (AIR) and versioning policy |
| [scope-v1.md](scope-v1.md) | What v1 defines and what it does not |
| [dependencies.md](dependencies.md) | Normative references and MTI algorithms |
| [threat-model.md](threat-model.md) | Trust assumptions and threat analysis |
| [limitations-v1.md](limitations-v1.md) | Explicit non-claims and limitations |
| [claim-mapping.md](claim-mapping.md) | EAT claim mapping and verification semantics |
| [air-v1.cddl](air-v1.cddl) | CDDL wire schema |
| [vectors/](../vectors/) | Golden test vectors (10 vectors: 2 valid, 8 invalid) |
| [interop-kit.md](interop-kit.md) | Quick-start guide for external implementors |
| [implementation-status.md](implementation-status.md) | Reference implementation status, platform coverage, and known gaps (non-normative) |

## Public Entry Point

Start here if you are evaluating AIR v1 externally:

1. [interop-kit.md](interop-kit.md) — minimum information to build a verifier
2. [air-v1.cddl](air-v1.cddl) — wire schema
3. [vectors/](../vectors/) — conformance corpus (valid + invalid vectors)
4. [implementation-status.md](implementation-status.md) — current Rust implementation coverage and gaps
5. [limitations-v1.md](limitations-v1.md) — explicit non-claims

## Format

AIR v1 receipts are COSE_Sign1 envelopes (RFC 9052) carrying CWT claims (RFC 8392) with EAT profile identification (RFC 9711). Signed with Ed25519 (RFC 8032, verify_strict).

## Repository Layout

```
spec/                Normative spec documents (this directory)
vectors/             Golden test vectors (2 valid, 8 invalid)
draft/               IETF Internet-Draft source and built artifacts
scripts/             Interop test script
docs/                Publication docs, submission checklists
```

## IETF Internet-Draft (Non-Normative)

The current local IETF Internet-Draft revision (`draft-tsyrulnikov-rats-attested-inference-receipt-01`)
is maintained under `draft/`, alongside the older `-00` snapshot. It is a non-normative
presentation of the AIR v1 specification for IETF review and is not part of the normative
specification freeze.

## License

CC BY 4.0 — See [LICENSE](../LICENSE).

# AIR v1 (Attested Inference Receipt)

Standalone standards workspace for AIR v1: an open, implementation-independent receipt profile for attestation-linked AI inference evidence.

AIR is the standards/moat layer behind EphemeralML. This repository exists so external reviewers can evaluate the receipt format, verifier behavior, and conformance corpus without first navigating the full product repo.

## Fast Diligence Summary

| Question | Short answer |
|----------|--------------|
| What is AIR? | An application-layer COSE/CWT + EAT-profile receipt for one AI inference in an attested confidential workload. |
| Why does this repo exist separately? | To keep the spec, vectors, and interop materials legible as a standalone asset rather than a product subfolder. |
| What is in scope here? | Normative spec docs, CDDL, golden vectors, IETF draft sources/renders, and interop tooling. |
| What is not in scope here? | The production inference runtime, gateway, cloud deployment scripts, or commercial product UX. Those remain in `EphemeralML-cyntrisec`. |
| What should a reviewer read first? | `spec/README.md`, then `vectors/`, then the draft in `draft/`. |

## Why AIR Matters

Most confidential-compute products prove that a workload booted in an attested environment. AIR adds a portable, signed artifact for a single inference event: which model ran, what request/response hashes were involved, and what attestation-linked metadata is available for verification.

That is the category boundary for this repository:

- infrastructure proves the room is locked
- AIR proves what happened inside for one inference

## Scope

- AIR v1 normative spec and release docs
- IETF Internet-Draft source and rendered artifacts
- CDDL schema and golden vectors
- Interop verifier script
- Submission support docs used for standards and review workflows

## Suggested Review Path

1. [`spec/README.md`](spec/README.md) — frozen v1 scope and normative documents
2. [`spec/interop-kit.md`](spec/interop-kit.md) — fastest external verifier path
3. [`vectors/`](vectors/) — golden corpus (`2 valid + 8 invalid`)
4. [`draft/`](draft/) — IETF Internet-Draft source and rendered artifacts
5. [`spec/implementation-status.md`](spec/implementation-status.md) — current reference implementation coverage and gaps

## Layout

- `draft/` - IETF draft sources and rendered artifacts (`.md`, `.xml`, `.txt`, `.html`)
- `spec/` - AIR v1 normative specification docs + CDDL
- `vectors/` - Golden vectors (`2 valid + 8 invalid`)
- `scripts/` - Interop tooling
- `docs/` - Verification reports, submission checklists, and claim/evidence support docs

## Baseline Source

- Source repository: `EphemeralML-cyntrisec`
- Source commit: `4b4091c`
- Snapshot date: `2026-02-28`

This split is non-destructive: `EphemeralML-cyntrisec` remains the current production implementation, while this repository keeps the AIR v1 standards surface stable and independently reviewable.

## Contacts

- Primary author/submission email: `borys@cyntrisec.com`
- Organization: Cyntrisec

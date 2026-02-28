# AIR v1 (Attested Inference Receipt)

Standalone specification workspace for AIR v1.

This repository is split from the EphemeralML product repository to keep AIR v1 positioned as an open, implementation-independent standard profile.

## Scope

- AIR v1 normative spec and release docs
- IETF Internet-Draft source and rendered artifacts
- CDDL schema and golden vectors
- Interop verifier script
- NIST/IETF submission support docs

## Layout

- `draft/` - IETF draft (`-00`) sources and renders (`.md`, `.xml`, `.txt`, `.html`)
- `spec/` - AIR v1 normative specification docs + CDDL
- `vectors/` - Golden vectors (`2 valid + 8 invalid`)
- `scripts/` - Interop tooling
- `docs/` - Claim/evidence matrix, verification report, submission checklists

## Baseline Source

- Source repository: `EphemeralML-cyntrisec`
- Source commit: `4b4091c`
- Snapshot date: `2026-02-28`

## Contacts

- Primary author/submission email: `borys@cyntrisec.com`
- Organization: Cyntrisec

## Notes

- This split is non-destructive: EphemeralML remains the current production implementation.
- After IETF `-00` submission, update `Implementation Status` in future draft versions to reference this repo directly.

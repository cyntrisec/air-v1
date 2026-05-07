# Standard Name and Versioning Policy

**Issue:** #63
**Status:** AIR v1.0.x stable
**Original freeze date:** 2026-02-25

## Standard Name

**Attested Inference Receipt (AIR)**

### Rationale

- **Neutral:** Does not reference EphemeralML, Cyntrisec, or any vendor.
- **Descriptive:** "Attested" (hardware-backed), "Inference" (ML scope), "Receipt" (proof artifact).
- **Compact:** Three words, pronounceable acronym (AIR).
- **Domain-searchable:** No collision with existing IETF/W3C/ISO standards.

### Rejected Alternatives

| Name | Rejection Reason |
|------|-----------------|
| Attested Execution Receipt (AER) | Too generic — covers any workload, not ML-specific |
| Confidential Inference Token (CIT) | "Token" overloaded (JWT, access tokens, ML tokens) |
| Trusted Inference Proof (TIP) | "Trusted" implies trust assumption; we prove, not trust |
| EphemeralML Receipt | Vendor-specific, blocks third-party adoption |

## Version Scheme

Versions follow a two-part scheme: **`air-v{major}.{minor}`**

| Component | Meaning |
|-----------|---------|
| `major` | Breaking wire-format change (new COSE structure, removed required field) |
| `minor` | Backward-compatible addition (new optional claim, new algorithm option) |

### Rules

1. **v1.0** is the first standardized version (replaces EphemeralML's internal v0.1).
2. A conformant verifier MUST reject unknown required wire semantics. Current v1.0.x verifiers are fail-closed on unknown claim keys, unknown protected header parameters, unknown measurement types, and unknown model hash schemes.
3. Major version bumps (v2.0) require a new `eat_profile` URI.
4. Minor version bumps (v1.1) MUST NOT remove or redefine existing claims. Any extension that keeps the v1 `eat_profile` URI MUST define explicit downgrade behavior for older fail-closed verifiers.

## EAT Profile URI

The `eat_profile` claim (EAT RFC 9711) identifies which specification governs the receipt:

```
https://spec.cyntrisec.com/air/v1
```

### URI Structure

```
https://spec.cyntrisec.com/air/v{major}
```

- Major version only in the URI (minor versions are wire-compatible).
- The URI is an identifier, not necessarily a fetchable URL (per EAT convention).
- Once v1 is adopted by a standards body (e.g., IETF), the URI migrates to that body's namespace.

## File Naming Convention

Spec documents use the pattern:

```
spec/<document-name>.md         — prose specification
spec/air-v1.cddl                — CDDL schema
vectors/<category>/             — test vectors
```

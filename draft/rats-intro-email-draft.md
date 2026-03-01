# Draft Email — `rats@ietf.org` Introduction (Not Sent)

**Status:** Draft for M5 prep (do not send until at least one external interop run is complete)

## Subject (draft)

`[RATS] Technical review requested: AIR (Attested Inference Receipt) COSE/CWT profile for confidential AI inference`

## Body (draft)

Hello RATS WG,

I am preparing an individual draft for **AIR** (Attested Inference Receipt), an open profile for
per-inference evidence in confidential AI inference. AIR profiles existing IETF standards
(COSE/CWT/EAT) to bind model identity, input/output hashes, execution metadata, and signature into
a single verifiable artifact.

Problem statement:

- Existing attestation mechanisms prove platform identity / evidence validity.
- In practice, there is no widely used interoperable receipt format for a **single AI inference**
  that binds model identity (`model_hash`), input/output hashes, timestamp/nonce, attestation-linked
  metadata, and signature.

Draft scope:

- AIR v1 is a **COSE_Sign1** envelope (RFC 9052)
- payload is **CWT/EAT-style claims** with an AIR-specific profile (`eat_profile`)
- single-inference scope only (no pipeline chaining in v1)

What is already available publicly:

- draft spec (frozen v1.0 docs)
- CDDL schema
- conformance vectors (valid + invalid)
- reference Rust verifier (4-layer verification model)
- implementation status / limitations documentation

Request for WG technical review:

1. Does a COSE/CWT/EAT-based "inference receipt" profile fit the RATS problem space?
2. Would this be better framed as an individual RATS profile draft, or outside RATS initially?
3. Are there existing RATS/EAT efforts we should align with before publishing a `-00` draft?

Draft materials (placeholders to fill before sending):

- Spec root: `<LINK>`
- CDDL: `<LINK>`
- Conformance vectors: `<LINK>`
- Reference verifier: `<LINK>`
- Implementation status / limitations: `<LINK>`

I can provide a short architecture summary and sample vectors in follow-up if helpful.

Thanks,

`<Name>`
`<Affiliation (optional)>`

## Notes Before Sending

- Replace placeholder links with stable public URLs
- Include implementation/interoperability status (do not overstate)
- Keep the message technical and narrow (single-inference receipt profile only)
- Avoid claims about pipeline chaining / deletion proof / SCITT integration in v1

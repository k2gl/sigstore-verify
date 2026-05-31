# Changelog

## 0.3.0

RFC 3161 timestamp verification.

- **RFC 3161 timestamps** — when a bundle carries one or more
  `verificationMaterial.timestampVerificationData.rfc3161Timestamps`, each is now verified
  (fail-closed) against the trusted root's timestamp authorities: the CMS SignedData
  signature under a trusted Timestamp Authority certificate whose chain is valid at the
  token's genTime, the message-digest signed attribute, and the message imprint over the
  bundle's signature. A verified timestamp's genTime becomes the signing time for the
  certificate-chain check; with no timestamp, the Rekor integrated time is used, as before.
- New **`Rfc3161Timestamp`** value object. **`TrustedRoot`** now parses `timestampAuthorities`
  (exposed as `TrustedRoot::$timestampAuthorities`) and **`Bundle`** exposes
  `Bundle::$rfc3161Timestamps`.
- Validated against a real time-stamp token from the sigstore conformance suite, plus
  rejection tests for a tampered token, a timestamp over a different signature, an untrusted
  authority and a genTime outside the authority's validity.

No API changes to `verify()` / `verifyArtifact()`: timestamps are verified automatically
when present, and bundles without them behave exactly as before.

## 0.2.0

Message-signature (artifact) bundle support, alongside DSSE attestations.

- **`SigstoreVerifier::verifyArtifact()`** (and `verifyArtifactFromJson()`) — verifies a
  `cosign sign-blob`-style bundle against the artifact bytes you supply: the message digest
  matches the artifact, the signature verifies under the Fulcio leaf key, the hashedrekord
  Rekor entry is proven and bound to the artifact digest, and the certificate identity
  matches. Throws unless every step passes.
- **`Bundle`** now parses both DSSE and message-signature content, with `isDsse()` /
  `isMessageSignature()`. New **`MessageSignature`** value object.
- Validated end to end against the public-good sigstore-conformance message-signature
  fixture (certificate chain, artifact signature, Rekor inclusion proof + signed checkpoint,
  hashedrekord binding, identity).

Note: `Bundle::$dsseEnvelope` is now nullable (null for message-signature bundles); use
`isDsse()` before reading it. `verify()` is for DSSE bundles and `verifyArtifact()` for
message-signature bundles — each rejects the other shape as unsupported.

## 0.1.1

- **`SigstoreVerifier::verifyFromJson()`** — convenience entry point that parses a bundle
  and trusted root from JSON strings and verifies them in one call.
- Hardening tests: a tampered Rekor signed entry timestamp, a non-in-toto payload type and
  an empty transparency-log list are all rejected.
- README: `verifyFromJson` shorthand and a worked Statement-v1 / SLSA-provenance example.

No API or behaviour changes to existing methods.

## 0.1.0

First public release. An offline, fail-closed verifier for Sigstore DSSE-attestation
bundles, built on [`k2gl/in-toto-attestation`](https://github.com/k2gl/in-toto-attestation)
and [`k2gl/dsse`](https://github.com/k2gl/dsse).

- **`SigstoreVerifier`** — verifies a bundle end to end against a caller-supplied trusted
  root and identity policy: Fulcio certificate chain (valid at the Rekor integrated time),
  DSSE signature under the leaf key, Rekor proof (signed entry timestamp and/or RFC 6962
  Merkle inclusion proof with a signed checkpoint) bound to the envelope payload, and the
  certificate identity. Returns the verified DSSE `Envelope`; throws on any failure.
- **`Bundle`** — parses `.sigstore.json` (bundle v0.1–v0.3, DSSE content). Message-signature
  and public-key bundles are rejected as unsupported.
- **`TrustedRoot`** — parses `trusted_root.json` (Fulcio certificate authorities and Rekor
  transparency logs); no bundled snapshot and no TUF fetching — the caller supplies it.
- **`IdentityPolicy`** — pins the expected subject alternative name and OIDC issuer.
- Models: `TlogEntry`, `InclusionProof`, `Checkpoint`, `CertificateAuthority`,
  `TransparencyLogInstance`.
- Every error implements `SigstoreException`: `VerificationFailedException`,
  `UnsupportedBundleException`, `InvalidBundleException`, `TrustRootException`.

Scope: DSSE in-toto attestation bundles signed by a keyless Fulcio ECDSA P-256 certificate.
RFC 3161 timestamps, SCT/CT verification, message-signature bundles and TUF-based trust
roots are out of scope and fail closed.

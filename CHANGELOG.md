# Changelog

## Unreleased

Verification hardening toward 1.0.0 conformance parity (fail-closed).

- **Rekor entry binding** — a Merkle inclusion proof is now required for bundle media type
  v0.2+ (an inclusion promise alone is no longer enough; v0.1 bundles may still rely on the
  promise), and the log entry body must record the same signature — and, for a keyless bundle,
  the same certificate — that the bundle carries. This rejects a bundle whose content is genuine
  but whose transparency-log entry was made with different signing material.
- **Checkpoint key hint** — a checkpoint note signature is now accepted only when its four-byte
  key hint matches the transparency log that produced the entry (the first four bytes of the
  log's key id). A note signed by some other key is rejected even if the signature itself is
  well-formed. Adds the `CheckpointSignature` value object; `Checkpoint::signatures()` now returns
  `list<CheckpointSignature>` rather than raw signature strings.

Against sigstore-conformance **v0.0.28** the suite is now 100 pass / 26 xfail / 6 skip.

## 0.7.0

Conformance test harness.

- **`bin/conformance`** — a client-under-test adapter implementing the official
  [sigstore-conformance](https://github.com/sigstore/sigstore-conformance) CLI protocol
  (`verify-bundle`, both the certificate-identity and the public-key form) on top of the existing
  `SigstoreVerifier`. For an attestation bundle it also binds the verified statement to the artifact
  by checking the artifact's digest is one of the statement subjects. It is a development/CI
  artifact and is excluded from the published package.
- **`.github/workflows/conformance.yml`** — runs the sigstore-conformance suite (verification only,
  `--skip-signing`) against that adapter on every push. Against suite **v0.0.28**, 91 of the
  verification cases pass; the remaining 35 are tracked as strict expected failures (`xfail`) and
  are the agenda for the 1.0.0 conformance-parity release: Rekor v2 transparency-log entries,
  message-signature verification from a bare artifact digest, a handful of stricter fail-closed
  checks for malformed Rekor entries and checkpoints, and one bundle-parsing edge case.

No library code changed: existing APIs and verification behavior are unchanged.

## 0.6.0

TUF trusted root.

- **`TrustedRoot::fromTuf()`** — resolve the trusted root from a TUF repository through a
  caller-built `K2gl\Tuf\Updater`: the updater refreshes the top-level metadata, the
  `trusted_root.json` target's length and hashes are verified by the TUF client, and the bytes
  are parsed as before. The target path is overridable. Fail-closed — a TUF verification failure
  (rollback, expiry, threshold, length or hash mismatch) throws a `K2gl\Tuf\Exception\TufException`,
  and a repository that does not publish the target throws `TrustRootException`.
- **`TrustedRoot::fromSigstorePublicGood()`** — the convenience over `fromTuf()` for the public
  Sigstore instance: it points an `Updater` at `tuf-repo-cdn.sigstore.dev` using a bundled
  `root.json` as the trust-on-first-use anchor (TUF rotates it forward from there). The fetcher
  defaults to `K2gl\Tuf\HttpFetcher`; pass your own to control transport, and a `referenceTime`
  to evaluate metadata expiry at a fixed instant.

The verifier core remains offline and reaches the network only through the TUF fetcher, which the
caller can replace. Existing `fromJson()` and all `verify*` signatures are unchanged. Adds a
`k2gl/tuf` dependency. The TUF path is exercised offline against a vendored real Sigstore
public-good snapshot and a self-signed synthetic repository.

## 0.5.0

Public-key bundles and multi-algorithm signing keys.

- **Public-key (non-certificate) bundles** — `SigstoreVerifier::verifyWithPublicKey()` and
  `verifyArtifactWithPublicKey()` (plus their `…FromJson` shorthands) verify a bundle whose
  signing identity is a public-key reference rather than a Fulcio certificate, as produced by
  `cosign sign-blob --key` / `cosign attest --key` or a self-managed-key Sigstore. You supply
  the trusted public key; there is no certificate chain, embedded SCT or identity policy, so
  trust rests on the key, and the Rekor transparency-log proof is still verified. An optional
  `expectedHint` requires the bundle's key hint to match. Such bundles were previously
  rejected at parse time.
- **Multiple signing-key algorithms** — the content signature is now verified for ECDSA over
  NIST P-256, P-384 and P-521 (digest by curve), RSA (PKCS#1 v1.5 over SHA-256), and — for
  DSSE — Ed25519, replacing the previous ECDSA P-256 only restriction. Message-signature
  bundles accept SHA2_256/384/512 digests accordingly.
- **`Bundle`** now parses public-key material (`Bundle::isPublicKey()` /
  `Bundle::hasCertificate()`, with `Bundle::$publicKeyHint`); `Bundle::$leafCertificate` is
  null for a public-key bundle.

Out of scope and rejected with `UnsupportedBundleException`: Ed25519 **message** signatures
(cosign signs the digest, not the artifact) and RSASSA-PSS signatures. The keyless methods
`verify()` / `verifyArtifact()` are unchanged and reject a public-key bundle (and vice versa)
with a pointer to the right method. Public-good Sigstore issues only ECDSA P-256 Fulcio
certificates, so the new algorithm and public-key paths are validated with generated
fixtures rather than captured public-good ones.

## 0.4.0

Certificate-transparency (SCT) verification.

- **Embedded SCT verification** — when the trusted root provides certificate-transparency logs
  (`ctlogs`), the Fulcio leaf certificate's embedded Signed Certificate Timestamp is now verified
  (RFC 6962, fail-closed): the pre-certificate is reconstructed (this leaf's TBSCertificate with
  the SCT extension removed), and the SCT signature is checked against a trusted CT log whose
  operating window covers the SCT timestamp. This proves Fulcio publicly logged the certificate's
  issuance. An unknown log, an out-of-window timestamp, a signature that does not verify, or a
  certificate with no embedded SCT all fail.
- **`TrustedRoot`** now parses `ctlogs` (exposed as `TrustedRoot::$ctLogs`), and
  **`TransparencyLogInstance`** carries its `validFor` window (`isValidAt()`).
- Validated against the real public-good and TSA Sigstore fixtures, plus rejection tests for an
  unknown log, a wrong log key, an out-of-window timestamp, and a certificate without an SCT.

Verification is automatic when the trusted root has CT logs and a no-op when it does not, so
`verify()` / `verifyArtifact()` keep their signatures and bundles behave exactly as before when
no CT logs are configured.

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

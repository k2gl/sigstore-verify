# Changelog

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

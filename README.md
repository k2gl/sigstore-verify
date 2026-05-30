# k2gl/sigstore-verify

Offline, **fail-closed** PHP verifier for [Sigstore](https://www.sigstore.dev/) bundles.
Given a `.sigstore.json` bundle, a trusted root, and the identity you expect, it verifies
the whole chain of evidence and returns the authenticated attestation — or throws.

It answers the question *"is this attestation genuine, and did the identity I trust
produce it?"* in pure PHP, with no network calls during verification.

## What it verifies

For a DSSE-attestation bundle (the kind produced by `cosign attest`, npm provenance,
`gitsign`, …), every one of these must pass or verification throws:

1. **Certificate chain** — the Fulcio leaf certificate chains to a trusted CA from the
   supplied trusted root, and every certificate in the path is valid at the signing time
   (the Rekor integrated time).
2. **DSSE signature** — the envelope signature verifies under the leaf certificate's key.
3. **Transparency log** — each Rekor entry is proven by its signed entry timestamp and/or
   its Merkle inclusion proof (recomputed per RFC 6962, against a signed checkpoint), and
   the entry is bound to this envelope by its payload hash.
4. **Identity policy** — the certificate's subject alternative name and OIDC issuer match
   what you require.

There is no "best effort" path: anything missing, unsupported, or invalid raises a
`SigstoreException`. A returned value always means all four checks held.

## Install

```bash
composer require k2gl/sigstore-verify
```

Requires PHP 8.1+, `ext-openssl`, and [`phpseclib/phpseclib`](https://phpseclib.com/)
(certificate parsing). Pulls in [`k2gl/in-toto-attestation`](https://github.com/k2gl/in-toto-attestation)
and [`k2gl/dsse`](https://github.com/k2gl/dsse).

## The trusted root

Verification runs against a Sigstore `trusted_root.json` that **you supply**. This package
deliberately does not bundle a trust snapshot or fetch one over TUF: a stale or substituted
trust root would silently undermine every verification, so keeping it current is the
caller's responsibility.

Obtain one with the Sigstore CLI:

```bash
# Public-good (default) instance:
cosign trusted-root create > trusted_root.json
```

or take the trusted root distributed via the Sigstore TUF root. Refresh it periodically.

## Usage

```php
use K2gl\Sigstore\Bundle;
use K2gl\Sigstore\TrustedRoot;
use K2gl\Sigstore\IdentityPolicy;
use K2gl\Sigstore\SigstoreVerifier;
use K2gl\Sigstore\Exception\SigstoreException;

$bundle      = Bundle::fromJson(file_get_contents('artifact.sigstore.json'));
$trustedRoot = TrustedRoot::fromJson(file_get_contents('trusted_root.json'));

$policy = new IdentityPolicy(
    san:    'https://github.com/acme/app/.github/workflows/release.yml@refs/heads/main',
    issuer: 'https://token.actions.githubusercontent.com',
);

try {
    // Returns the verified DSSE envelope (K2gl\Dsse\Envelope).
    $envelope = (new SigstoreVerifier())->verify($bundle, $trustedRoot, $policy);
} catch (SigstoreException $e) {
    // Not trustworthy — fail closed.
    throw $e;
}

// The payload is the authenticated in-toto Statement. Read it as you wish:
$statement = json_decode($envelope->payload, true);
$statement['predicateType']; // e.g. 'https://slsa.dev/provenance/v1'
$statement['subject'];       // the attested artifacts
```

Sigstore bundles carry in-toto Statement **v0.1** and **v1**; authentication does not depend
on the schema version, so the verifier hands back the envelope and leaves statement modelling
to you. For v1 statements you can parse with `K2gl\InToto\Statement::fromEnvelope($envelope)`,
and SLSA provenance with `K2gl\Slsa\Provenance::fromStatement(...)`.

## Scope

This release verifies **DSSE in-toto attestation bundles** signed by a keyless **Fulcio
ECDSA P-256** certificate, offline. The following are intentionally out of scope and are
rejected with `UnsupportedBundleException` rather than skipped:

- message-signature (artifact-signature / hashedrekord) bundles;
- public-key (non-certificate) bundles and non-P-256 keys;
- RFC 3161 timestamps and SCT / certificate-transparency verification;
- TUF-based trust-root fetching and auto-refresh.

These are the planned next steps — each a fail-closed addition in a later release.

## Exceptions

Everything thrown implements `K2gl\Sigstore\Exception\SigstoreException`:

- `VerificationFailedException` — a check failed; the bundle is not trustworthy.
- `UnsupportedBundleException` — a well-formed bundle using a feature this version does not verify.
- `InvalidBundleException` — the bundle is malformed.
- `TrustRootException` — the trusted root is malformed or unusable.

## License

MIT — see [LICENSE](LICENSE). Independent, clean-room implementation of the Sigstore
bundle-verification specifications (Apache-2.0).

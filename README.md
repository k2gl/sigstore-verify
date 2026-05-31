# k2gl/sigstore-verify

Offline, **fail-closed** PHP verifier for [Sigstore](https://www.sigstore.dev/) bundles.
Given a `.sigstore.json` bundle, a trusted root, and the identity you expect, it verifies
the whole chain of evidence and returns the authenticated content — or throws.

It handles both bundle shapes: **DSSE attestations** (`cosign attest`, npm provenance,
SLSA provenance) and **message signatures** (`cosign sign-blob` artifact signatures). It
answers *"is this genuine, and did the identity I trust produce it?"* in pure PHP, with no
network calls during verification.

## What it verifies

Every one of these must pass or verification throws:

1. **Certificate chain** — the Fulcio leaf certificate chains to a trusted CA from the
   supplied trusted root, and every certificate in the path is valid at the signing time.
2. **Signature** — the DSSE envelope signature, or the artifact's message signature,
   verifies under the leaf certificate's key.
3. **Transparency log** — each Rekor entry is proven by its signed entry timestamp and/or
   its Merkle inclusion proof (recomputed per RFC 6962, against a signed checkpoint), and
   the entry is bound to this bundle by its recorded hash.
4. **Timestamp** — when the bundle carries an RFC 3161 timestamp, the token must verify
   against a trusted Timestamp Authority from the trusted root (the token signature, its
   certificate chain valid at that time, and the imprint of the bundle signature), and its
   genTime becomes the signing time. With no timestamp, the Rekor integrated time stands in.
5. **Certificate transparency** — when the trusted root provides CT logs, the leaf
   certificate's embedded Signed Certificate Timestamp must verify (RFC 6962) under a trusted
   CT log whose operating window covers it, proving Fulcio publicly logged the certificate's
   issuance.
6. **Identity policy** — the certificate's subject alternative name and OIDC issuer match
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

If you already hold the bundle and trusted root as JSON strings, `verifyFromJson()` is the
one-line shorthand:

```php
$envelope = (new SigstoreVerifier())->verifyFromJson($bundleJson, $trustedRootJson, $policy);
```

Sigstore bundles carry in-toto Statement **v0.1** and **v1**; authentication does not depend
on the schema version, so the verifier hands back the envelope and leaves statement modelling
to you.

### Reading SLSA provenance (Statement v1)

```php
use K2gl\InToto\Statement;
use K2gl\Slsa\Provenance;

$statement  = Statement::fromEnvelope($envelope);   // throws unless it is a v1 Statement
$provenance = Provenance::fromStatement($statement);

$provenance->buildDefinition->buildType;            // how it was built
$provenance->runDetails->builder->id;               // who built it
```

For the still-common Statement v0.1, decode the payload directly
(`json_decode($envelope->payload, true)`) — the structure (`subject`, `predicateType`,
`predicate`) is identical, only `_type` differs.

### Verifying an artifact (message signature)

For a `cosign sign-blob`-style bundle, supply the artifact bytes; `verifyArtifact()`
checks the digest, the signature and the Rekor entry, and returns nothing (it throws
unless every step passes):

```php
use K2gl\Sigstore\Bundle;
use K2gl\Sigstore\TrustedRoot;
use K2gl\Sigstore\IdentityPolicy;
use K2gl\Sigstore\SigstoreVerifier;

(new SigstoreVerifier())->verifyArtifact(
    bundle: Bundle::fromJson($bundleJson),
    artifact: file_get_contents('artifact.bin'),
    trustedRoot: TrustedRoot::fromJson($trustedRootJson),
    identityPolicy: $policy,
);
// reached here => the artifact was signed by the expected identity
```

`verifyArtifactFromJson()` is the JSON-string shorthand. Use `Bundle::isDsse()` /
`Bundle::isMessageSignature()` to pick the right method for an unknown bundle.

## Scope

This release verifies, offline, both **DSSE in-toto attestation** bundles and
**message-signature** (artifact) bundles, signed by a keyless **Fulcio ECDSA P-256**
certificate. It verifies any **RFC 3161 timestamp** the bundle carries against a trusted
Timestamp Authority, and the certificate's embedded **SCT** against the trusted root's
**certificate-transparency** logs (when it provides them). The following are intentionally out
of scope and are rejected with `UnsupportedBundleException` rather than skipped:

- public-key (non-certificate) bundles and non-P-256 keys;
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

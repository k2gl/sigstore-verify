# k2gl/sigstore-verify

Offline, **fail-closed** PHP verifier for [Sigstore](https://www.sigstore.dev/) bundles.
Given a `.sigstore.json` bundle, a trusted root, and the identity you expect, it verifies
the whole chain of evidence and returns the authenticated content — or throws.

It handles both bundle shapes: **DSSE attestations** (`cosign attest`, npm provenance,
SLSA provenance) and **message signatures** (`cosign sign-blob` artifact signatures), with
either signing identity: a **keyless Fulcio certificate** or a **public key** you supply out
of band. The signing key may be ECDSA over NIST P-256/P-384/P-521, RSA, or — for DSSE —
Ed25519. It answers *"is this genuine, and did the identity I trust produce it?"* in pure
PHP, with no network calls during verification.

## What it verifies

Every one of these must pass or verification throws:

1. **Certificate chain** *(keyless bundles)* — the Fulcio leaf certificate chains to a
   trusted CA from the supplied trusted root, and every certificate in the path is valid at
   the signing time. For a public-key bundle there is no certificate; trust rests on the key
   you supply, and the optional key hint must match if you pass one.
2. **Signature** — the DSSE envelope signature, or the artifact's message signature,
   verifies under the signing key (the leaf certificate's key, or the public key you supply).
3. **Transparency log** — each Rekor entry is proven by its signed entry timestamp and/or
   its Merkle inclusion proof (recomputed per RFC 6962, against a signed checkpoint), and
   the entry is bound to this bundle by its recorded hash.
4. **Timestamp** — when the bundle carries an RFC 3161 timestamp, the token must verify
   against a trusted Timestamp Authority from the trusted root (the token signature, its
   certificate chain valid at that time, and the imprint of the bundle signature), and its
   genTime becomes the signing time. With no timestamp, the Rekor integrated time stands in.
5. **Certificate transparency** *(keyless bundles)* — when the trusted root provides CT
   logs, the leaf certificate's embedded Signed Certificate Timestamp must verify (RFC 6962)
   under a trusted CT log whose operating window covers it, proving Fulcio publicly logged
   the certificate's issuance.
6. **Identity policy** *(keyless bundles)* — the certificate's subject alternative name and
   OIDC issuer match what you require.

There is no "best effort" path: anything missing, unsupported, or invalid raises a
`SigstoreException`. A returned value always means every applicable check held.

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

### Verifying a public-key bundle

A bundle signed with your own key (`cosign sign-blob --key` / `cosign attest --key`, or a
self-managed-key Sigstore) carries a key *reference*, not a Fulcio certificate. There is no
chain to walk and no identity policy: trust rests on the key you pass in, so supply the
public key you already trust. The Rekor transparency-log proof is still verified.

```php
$bundle = Bundle::fromJson($bundleJson);

if ($bundle->isPublicKey()) {
    $publicKeyPem = file_get_contents('cosign.pub');

    // DSSE attestation — returns the verified envelope:
    $envelope = (new SigstoreVerifier())->verifyWithPublicKey($bundle, $publicKeyPem, $trustedRoot);

    // Message signature — supply the artifact; throws unless it verifies:
    (new SigstoreVerifier())->verifyArtifactWithPublicKey(
        bundle: $bundle,
        artifact: file_get_contents('artifact.bin'),
        publicKeyPem: $publicKeyPem,
        trustedRoot: $trustedRoot,
    );
}
```

Pass `expectedHint:` to additionally require the bundle's key hint to match a value you
expect. `verifyWithPublicKeyFromJson()` / `verifyArtifactWithPublicKeyFromJson()` are the
JSON-string shorthands. Use `Bundle::hasCertificate()` / `Bundle::isPublicKey()` to pick
between the keyless and public-key methods for an unknown bundle.

## Scope

This release verifies, offline, both **DSSE in-toto attestation** bundles and
**message-signature** (artifact) bundles, signed either by a **keyless Fulcio certificate**
or by a **public key** you supply. The signing key may be **ECDSA over NIST
P-256/P-384/P-521**, **RSA** (PKCS#1 v1.5), or — for DSSE — **Ed25519**. It verifies any
**RFC 3161 timestamp** the bundle carries against a trusted Timestamp Authority, and (for
keyless bundles) the certificate's embedded **SCT** against the trusted root's
**certificate-transparency** logs when it provides them. The following are intentionally out
of scope and are rejected with `UnsupportedBundleException` rather than skipped:

- Ed25519 **message** signatures (cosign signs the digest rather than the artifact, so the
  scheme is ambiguous), and RSASSA-PSS signatures;
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

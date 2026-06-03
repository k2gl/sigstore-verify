# k2gl/sigstore-verify

[![CI](https://img.shields.io/github/actions/workflow/status/k2gl/sigstore-verify/ci.yml?branch=main&label=CI&logo=github)](https://github.com/k2gl/sigstore-verify/actions/workflows/ci.yml)
[![Conformance](https://img.shields.io/github/actions/workflow/status/k2gl/sigstore-verify/conformance.yml?branch=main&label=conformance&logo=sigstore&logoColor=white)](https://github.com/k2gl/sigstore-verify/actions/workflows/conformance.yml)
[![Latest Stable Version](https://img.shields.io/packagist/v/k2gl/sigstore-verify?logo=packagist&logoColor=white)](https://packagist.org/packages/k2gl/sigstore-verify)
[![Total Downloads](https://img.shields.io/packagist/dt/k2gl/sigstore-verify?logo=packagist&logoColor=white)](https://packagist.org/packages/k2gl/sigstore-verify)
[![PHPStan Level](https://img.shields.io/badge/PHPStan-level%209-2a5ea7?logo=php&logoColor=white)](https://phpstan.org)
[![License](https://img.shields.io/packagist/l/k2gl/sigstore-verify?color=yellowgreen)](https://packagist.org/packages/k2gl/sigstore-verify)

Offline, **fail-closed** PHP verifier for [Sigstore](https://www.sigstore.dev/) bundles.
Given a `.sigstore.json` bundle, a trusted root, and the identity you expect, it verifies
the whole chain of evidence and returns the authenticated content — or throws. It is
validated against Sigstore's official
[conformance suite](https://github.com/sigstore/sigstore-conformance), which it **passes in
full** — every verification case, across Rekor v1 and v2 entries — so its behaviour matches
the reference clients.

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
(certificate parsing); `ext-sodium` is needed for Ed25519 — DSSE Ed25519 keys and Rekor v2
checkpoint notes. Pulls in [`k2gl/in-toto-attestation`](https://github.com/k2gl/in-toto-attestation)
and [`k2gl/dsse`](https://github.com/k2gl/dsse).

## The trusted root

Verification runs against a Sigstore `trusted_root.json`. You can supply it three ways.

**Supply it yourself** with `TrustedRoot::fromJson()`. Obtain the JSON with the Sigstore CLI
and keep it current — a stale or substituted trust root would silently undermine every
verification:

```bash
# Public-good (default) instance:
cosign trusted-root create > trusted_root.json
```

**Resolve it over TUF** with `TrustedRoot::fromTuf()`, given a `K2gl\Tuf\Updater` you build.
The TUF client refreshes the metadata and verifies the `trusted_root.json` target's length and
hashes before it is parsed, so the repository keeps the root current under its own rotation
rules. The verifier core stays offline — the network is reached only through the updater's
fetcher.

**For the public-good instance**, `TrustedRoot::fromSigstorePublicGood()` is the convenience
over `fromTuf()`: it points an updater at `tuf-repo-cdn.sigstore.dev`, using a bundled
`root.json` as the trust-on-first-use anchor that TUF rotates forward.

```php
use K2gl\Sigstore\TrustedRoot;

// Fetches and verifies the trusted root over TUF (opt-in network):
$trustedRoot = TrustedRoot::fromSigstorePublicGood();
```

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

When the artifact bytes are unavailable — too large to load, or already hashed —
verify from its digest instead. Sigstore's ECDSA and RSA schemes sign the artifact
digest, so the bytes are not needed:

```php
(new SigstoreVerifier())->verifyArtifactDigest(
    bundle: Bundle::fromJson($bundleJson),
    algorithm: 'sha256',
    hexDigest: hash_file('sha256', 'artifact.bin'),
    trustedRoot: TrustedRoot::fromJson($trustedRootJson),
    identityPolicy: $policy,
);
```

`$algorithm` (`sha256` / `sha384` / `sha512`) must match the one the bundle records.
`verifyArtifactDigestWithPublicKey()` is the public-key counterpart, and both have
`...FromJson()` shorthands.

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
**certificate-transparency** logs when it provides them. The **Rekor** transparency-log entry
is proven and bound to the bundle for both log generations — **v1** (hashedrekord / dsse /
intoto) and **v2** (hashedrekord 0.0.2, whose checkpoint is Ed25519-signed and whose time
comes from an RFC 3161 timestamp). The following are intentionally out of scope and are
rejected with `UnsupportedBundleException` rather than skipped:

- Ed25519 **message** signatures (cosign signs the digest rather than the artifact, so the
  scheme is ambiguous), and RSASSA-PSS signatures.

The trusted root can be resolved over TUF — supply it yourself with `TrustedRoot::fromJson()`,
or fetch and refresh it with `TrustedRoot::fromTuf()` / `TrustedRoot::fromSigstorePublicGood()`
(see [The trusted root](#the-trusted-root)).

## Conformance

The verifier is exercised against the official
[sigstore-conformance](https://github.com/sigstore/sigstore-conformance) suite on every push
(verification only) and **passes it in full** — every verification case, across Rekor v1 and
v2 transparency-log entries, keyless and public-key bundles, and artifact-bytes and bare-digest
inputs. See [Scope](#scope) for what is verified versus rejected as unsupported.

## Exceptions

Everything thrown implements `K2gl\Sigstore\Exception\SigstoreException`:

- `VerificationFailedException` — a check failed; the bundle is not trustworthy.
- `UnsupportedBundleException` — a well-formed bundle using a feature this version does not verify.
- `InvalidBundleException` — the bundle is malformed.
- `TrustRootException` — the trusted root is malformed or unusable.

## License

MIT — see [LICENSE](LICENSE). Independent, clean-room implementation of the Sigstore
bundle-verification specifications (Apache-2.0).

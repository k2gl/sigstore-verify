<?php

declare(strict_types=1);

namespace K2gl\Sigstore;

use K2gl\Dsse\Envelope;
use K2gl\Dsse\Exception\DsseException;
use K2gl\InToto\Statement;
use K2gl\Sigstore\Exception\UnsupportedBundleException;
use K2gl\Sigstore\Exception\VerificationFailedException;
use K2gl\Sigstore\Internal\Certificate;
use K2gl\Sigstore\Internal\CertificateChainVerifier;
use K2gl\Sigstore\Internal\RekorVerifier;
use K2gl\Sigstore\Internal\Rfc3161Verifier;
use K2gl\Sigstore\Internal\SctVerifier;
use K2gl\Sigstore\Internal\SignatureKey;

/**
 * Verifies a Sigstore bundle end to end, offline, against a caller-supplied
 * trusted root.
 *
 *  - {@see verify()} / {@see verifyArtifact()} handle keyless bundles, whose
 *    signing identity is a Fulcio certificate, against an {@see IdentityPolicy}.
 *  - {@see verifyWithPublicKey()} / {@see verifyArtifactWithPublicKey()} handle
 *    public-key bundles, whose signing key the caller supplies out of band.
 *
 * The signing key may be ECDSA over NIST P-256/P-384/P-521, RSA (PKCS#1 v1.5),
 * or — for DSSE — Ed25519; the scheme is resolved from the key ({@see SignatureKey}).
 *
 * The pipeline is fail-closed — every step must pass or it throws a
 * {@see Exception\SigstoreException}: the signing time is established (from a
 * trusted RFC 3161 timestamp when present, otherwise the Rekor integrated
 * time); for a keyless bundle the leaf certificate chains to a trusted Fulcio CA
 * valid at that time and its embedded SCT is checked; the signature verifies
 * under the signing key; each Rekor entry is proven (signed entry timestamp
 * and/or inclusion proof) and bound to the bundle content; and, for a keyless
 * bundle, the certificate identity matches the policy.
 *
 * For DSSE, the returned Envelope's payload is the authenticated in-toto
 * Statement. The caller decides how to read it — k2gl/in-toto-attestation's
 * Statement for v1, or its own parsing for the still-common Statement v0.1 —
 * because Sigstore bundles carry both schema versions and authentication does
 * not depend on it.
 */
final class SigstoreVerifier
{
    private readonly CertificateChainVerifier $chainVerifier;
    private readonly RekorVerifier $rekorVerifier;
    private readonly Rfc3161Verifier $rfc3161Verifier;
    private readonly SctVerifier $sctVerifier;

    public function __construct()
    {
        $this->chainVerifier = new CertificateChainVerifier();
        $this->rekorVerifier = new RekorVerifier();
        $this->rfc3161Verifier = new Rfc3161Verifier($this->chainVerifier);
        $this->sctVerifier = new SctVerifier();
    }

    /**
     * Convenience wrapper for the common case of having the bundle and trusted
     * root as JSON strings. Parsing errors surface as {@see Exception\InvalidBundleException}
     * / {@see Exception\TrustRootException}, exactly as {@see Bundle::fromJson()}
     * and {@see TrustedRoot::fromJson()} throw them.
     */
    public function verifyFromJson(
        string $bundleJson,
        string $trustedRootJson,
        IdentityPolicy $identityPolicy,
    ): Envelope {
        return $this->verify(
            bundle: Bundle::fromJson($bundleJson),
            trustedRoot: TrustedRoot::fromJson($trustedRootJson),
            identityPolicy: $identityPolicy,
        );
    }

    /** Verify a keyless DSSE in-toto attestation bundle and return the verified envelope. */
    public function verify(
        Bundle $bundle,
        TrustedRoot $trustedRoot,
        IdentityPolicy $identityPolicy,
    ): Envelope {
        $this->requireCertificateBundle($bundle);
        $envelope = $this->attestationEnvelope($bundle);

        $signingTime = $this->signingTime($bundle, $trustedRoot, $this->dsseSignature($envelope));
        $leaf = $this->verifyCertificate($bundle, $trustedRoot, $signingTime);

        $this->verifyDsseSignature($envelope, $leaf->signatureKey());
        $this->verifyTransparencyLog($bundle, $trustedRoot, hash('sha256', $envelope->payload));
        $identityPolicy->verify($leaf->subjectAlternativeNames(), $leaf->oidcIssuer());

        return $envelope;
    }

    /**
     * Convenience wrapper of {@see verifyArtifact()} for JSON-string inputs.
     */
    public function verifyArtifactFromJson(
        string $bundleJson,
        string $artifact,
        string $trustedRootJson,
        IdentityPolicy $identityPolicy,
    ): void {
        $this->verifyArtifact(
            Bundle::fromJson($bundleJson),
            $artifact,
            TrustedRoot::fromJson($trustedRootJson),
            $identityPolicy,
        );
    }

    /**
     * Verify a keyless message-signature bundle against the artifact it signs.
     * The artifact bytes must be supplied so the signature and the recorded
     * digest can be checked. Returns nothing: it throws unless every step passes.
     */
    public function verifyArtifact(
        Bundle $bundle,
        string $artifact,
        TrustedRoot $trustedRoot,
        IdentityPolicy $identityPolicy,
    ): void {
        $this->requireCertificateBundle($bundle);
        $signature = $this->messageSignature($bundle);

        $signingTime = $this->signingTime($bundle, $trustedRoot, $signature->signature);
        $leaf = $this->verifyCertificate($bundle, $trustedRoot, $signingTime);

        $this->verifyArtifactSignature($signature, $artifact, $leaf->signatureKey());
        $this->verifyTransparencyLog($bundle, $trustedRoot, bin2hex($signature->messageDigest));
        $identityPolicy->verify($leaf->subjectAlternativeNames(), $leaf->oidcIssuer());
    }

    /**
     * Convenience wrapper of {@see verifyWithPublicKey()} for JSON-string inputs.
     */
    public function verifyWithPublicKeyFromJson(
        string $bundleJson,
        string $publicKeyPem,
        string $trustedRootJson,
        ?string $expectedHint = null,
    ): Envelope {
        return $this->verifyWithPublicKey(
            Bundle::fromJson($bundleJson),
            $publicKeyPem,
            TrustedRoot::fromJson($trustedRootJson),
            $expectedHint,
        );
    }

    /**
     * Verify a public-key DSSE attestation bundle against the PEM-encoded key the
     * caller trusts out of band, and return the verified envelope. There is no
     * certificate to chain and no identity policy: trust rests on the supplied
     * key. When $expectedHint is given, the bundle's key hint must match it.
     */
    public function verifyWithPublicKey(
        Bundle $bundle,
        string $publicKeyPem,
        TrustedRoot $trustedRoot,
        ?string $expectedHint = null,
    ): Envelope {
        $this->requirePublicKeyBundle($bundle, $expectedHint);
        $envelope = $this->attestationEnvelope($bundle);

        $this->signingTime($bundle, $trustedRoot, $this->dsseSignature($envelope));
        $this->verifyDsseSignature($envelope, SignatureKey::fromPem($publicKeyPem));
        $this->verifyTransparencyLog($bundle, $trustedRoot, hash('sha256', $envelope->payload));

        return $envelope;
    }

    /**
     * Convenience wrapper of {@see verifyArtifactWithPublicKey()} for JSON-string inputs.
     */
    public function verifyArtifactWithPublicKeyFromJson(
        string $bundleJson,
        string $artifact,
        string $publicKeyPem,
        string $trustedRootJson,
        ?string $expectedHint = null,
    ): void {
        $this->verifyArtifactWithPublicKey(
            Bundle::fromJson($bundleJson),
            $artifact,
            $publicKeyPem,
            TrustedRoot::fromJson($trustedRootJson),
            $expectedHint,
        );
    }

    /**
     * Verify a public-key message-signature bundle against the artifact it signs
     * and the PEM-encoded key the caller trusts out of band. Returns nothing: it
     * throws unless every step passes. When $expectedHint is given, the bundle's
     * key hint must match it.
     */
    public function verifyArtifactWithPublicKey(
        Bundle $bundle,
        string $artifact,
        string $publicKeyPem,
        TrustedRoot $trustedRoot,
        ?string $expectedHint = null,
    ): void {
        $this->requirePublicKeyBundle($bundle, $expectedHint);
        $signature = $this->messageSignature($bundle);

        $this->signingTime($bundle, $trustedRoot, $signature->signature);
        $this->verifyArtifactSignature($signature, $artifact, SignatureKey::fromPem($publicKeyPem));
        $this->verifyTransparencyLog($bundle, $trustedRoot, bin2hex($signature->messageDigest));
    }

    /** The bundle's DSSE in-toto attestation envelope, or a rejection if it carries none. */
    private function attestationEnvelope(Bundle $bundle): Envelope
    {
        $envelope = $bundle->dsseEnvelope;

        if ($envelope === null) {
            throw new UnsupportedBundleException(
                'Bundle has no DSSE envelope; it is a message-signature bundle, so use an artifact verification method.'
            );
        }

        // Scope: this version verifies in-toto attestation envelopes.
        if ($envelope->payloadType !== Statement::PAYLOAD_TYPE) {
            throw new UnsupportedBundleException(sprintf(
                'This version verifies in-toto attestations ("%s") only; got payload type "%s".',
                Statement::PAYLOAD_TYPE,
                $envelope->payloadType,
            ));
        }

        return $envelope;
    }

    /** The bundle's message signature, or a rejection if it carries none. */
    private function messageSignature(Bundle $bundle): MessageSignature
    {
        return $bundle->messageSignature ?? throw new UnsupportedBundleException(
            'Bundle has no message signature; it is a DSSE attestation, so use a DSSE verification method.'
        );
    }

    private function requireCertificateBundle(Bundle $bundle): void
    {
        if (!$bundle->hasCertificate()) {
            throw new UnsupportedBundleException(
                'This is a public-key bundle; use verifyWithPublicKey() / verifyArtifactWithPublicKey() '
                . 'and supply the trusted key.'
            );
        }
    }

    private function requirePublicKeyBundle(Bundle $bundle, ?string $expectedHint): void
    {
        if ($bundle->hasCertificate()) {
            throw new UnsupportedBundleException(
                'This is a keyless (certificate) bundle; use verify() / verifyArtifact() with an identity policy.'
            );
        }

        if ($expectedHint !== null
            && ($bundle->publicKeyHint === null || !hash_equals($expectedHint, $bundle->publicKeyHint))
        ) {
            throw new VerificationFailedException('Bundle public-key hint does not match the expected hint.');
        }
    }

    /** The DSSE signature verifies under the signing key (over the envelope's PAE). */
    private function verifyDsseSignature(Envelope $envelope, SignatureKey $key): void
    {
        try {
            $envelope->verify($key);
        } catch (DsseException $e) {
            throw new VerificationFailedException(
                'DSSE signature does not verify against the signing public key.',
                previous: $e,
            );
        }
    }

    /** The artifact matches the recorded digest and the signature verifies under the signing key. */
    private function verifyArtifactSignature(
        MessageSignature $signature,
        string $artifact,
        SignatureKey $key,
    ): void {
        if ($key->isEd25519()) {
            throw new UnsupportedBundleException(
                'Ed25519 message signatures are not supported in this version; use a DSSE bundle for Ed25519.'
            );
        }

        $digest = match ($signature->hashAlgorithm) {
            'SHA2_256' => 'sha256',
            'SHA2_384' => 'sha384',
            'SHA2_512' => 'sha512',
            default => throw new UnsupportedBundleException(sprintf(
                'Unsupported message-digest algorithm "%s".',
                $signature->hashAlgorithm,
            )),
        };

        if (!hash_equals($signature->messageDigest, hash($digest, $artifact, true))) {
            throw new VerificationFailedException('Artifact does not match the bundle message digest.');
        }

        if (!$key->verify($artifact, $signature->signature)) {
            throw new VerificationFailedException(
                'Message signature does not verify against the signing public key.'
            );
        }
    }

    /** Parse the leaf certificate and verify it chains to a trusted Fulcio root at the signing time. */
    private function verifyCertificate(
        Bundle $bundle,
        TrustedRoot $trustedRoot,
        \DateTimeImmutable $signingTime,
    ): Certificate {
        $der = $bundle->leafCertificate ?? throw new UnsupportedBundleException('Bundle has no certificate.');
        $leaf = Certificate::fromDer($der);

        $chain = $this->chainVerifier->verify(
            leaf: $leaf,
            trustedRoot: $trustedRoot,
            signingTime: $signingTime,
        );

        // Certificate transparency: when the trusted root provides CT logs, the
        // leaf's embedded SCT must prove Fulcio logged the certificate's issuance.
        if ($trustedRoot->ctLogs !== []) {
            $issuer = $chain[1] ?? throw new VerificationFailedException(
                'Verified certificate chain has no issuer for SCT verification.'
            );
            $this->sctVerifier->verify($leaf, $issuer, $trustedRoot->ctLogs);
        }

        return $leaf;
    }

    /**
     * Establish the time at which the certificate must be valid. A trusted RFC
     * 3161 timestamp is preferred; when the bundle carries any, every one must
     * verify (fail-closed) and the first genTime is used. Otherwise the Rekor
     * integrated time stands in, as before.
     */
    private function signingTime(
        Bundle $bundle,
        TrustedRoot $trustedRoot,
        string $signature,
    ): \DateTimeImmutable {
        $genTime = null;

        foreach ($bundle->rfc3161Timestamps as $timestamp) {
            $verified = $this->rfc3161Verifier->verify(
                timestamp: $timestamp,
                signature: $signature,
                timestampAuthorities: $trustedRoot->timestampAuthorities,
            );
            $genTime ??= $verified;
        }

        if ($genTime !== null) {
            return $genTime;
        }
        $entry = $bundle->tlogEntries[0] ?? null;

        if ($entry === null) {
            throw new VerificationFailedException('Bundle has no trusted time source.');
        }

        return (new \DateTimeImmutable())->setTimestamp($entry->integratedTime);
    }

    /** The DSSE signature bytes an RFC 3161 timestamp would cover. */
    private function dsseSignature(Envelope $envelope): string
    {
        $signature = $envelope->signatures[0] ?? null;

        if ($signature === null) {
            throw new VerificationFailedException('DSSE envelope carries no signature.');
        }

        return $signature->sig;
    }

    private function verifyTransparencyLog(
        Bundle $bundle,
        TrustedRoot $trustedRoot,
        string $expectedHashHex,
    ): void {
        foreach ($bundle->tlogEntries as $entry) {
            $this->rekorVerifier->verify(
                entry: $entry,
                trustedRoot: $trustedRoot,
                expectedHashHex: $expectedHashHex,
            );
        }
    }
}

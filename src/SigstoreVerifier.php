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
use K2gl\Sigstore\Internal\CertificateKeyVerifier;
use K2gl\Sigstore\Internal\Ecdsa;
use K2gl\Sigstore\Internal\RekorVerifier;
use K2gl\Sigstore\Internal\Rfc3161Verifier;
use K2gl\Sigstore\Internal\SctVerifier;

/**
 * Verifies a Sigstore bundle end to end, offline, against a caller-supplied
 * trusted root and identity policy.
 *
 *  - {@see verify()} handles DSSE-attestation bundles and returns the verified
 *    in-toto {@see Envelope}.
 *  - {@see verifyArtifact()} handles message-signature bundles, verifying the
 *    signature against the artifact you supply.
 *
 * The pipeline is fail-closed — every step must pass or it throws a
 * {@see Exception\SigstoreException}: the signing time is established (from a
 * trusted RFC 3161 timestamp when present, otherwise the Rekor integrated
 * time); the leaf certificate chains to a trusted Fulcio CA valid at that time;
 * the signature verifies under the certificate's key; each Rekor entry is
 * proven (signed entry timestamp and/or inclusion proof) and bound to the
 * bundle content; and the certificate identity matches the policy.
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

    /** Verify a DSSE in-toto attestation bundle and return the verified envelope. */
    public function verify(
        Bundle $bundle,
        TrustedRoot $trustedRoot,
        IdentityPolicy $identityPolicy,
    ): Envelope {
        $envelope = $bundle->dsseEnvelope;

        if ($envelope === null) {
            throw new UnsupportedBundleException(
                'Bundle has no DSSE envelope; use verifyArtifact() for message-signature bundles.'
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

        $signingTime = $this->signingTime($bundle, $trustedRoot, $this->dsseSignature($envelope));
        $leaf = $this->verifyCertificate($bundle, $trustedRoot, $signingTime);

        // DSSE signature verifies under the certificate key.
        try {
            $envelope->verify(new CertificateKeyVerifier($leaf->publicKeyPem()));
        } catch (DsseException $e) {
            throw new VerificationFailedException(
                'DSSE signature does not verify against the certificate public key.',
                previous: $e,
            );
        }

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
     * Verify a message-signature bundle against the artifact it signs. The
     * artifact bytes must be supplied so the signature and the recorded digest
     * can be checked. Returns nothing: it throws unless every step passes.
     */
    public function verifyArtifact(
        Bundle $bundle,
        string $artifact,
        TrustedRoot $trustedRoot,
        IdentityPolicy $identityPolicy,
    ): void {
        $signature = $bundle->messageSignature;

        if ($signature === null) {
            throw new UnsupportedBundleException(
                'Bundle has no message signature; use verify() for DSSE attestations.'
            );
        }

        if ($signature->hashAlgorithm !== 'SHA2_256') {
            throw new UnsupportedBundleException(sprintf(
                'Only SHA2_256 message digests are supported; got "%s".',
                $signature->hashAlgorithm,
            ));
        }

        if (!hash_equals($signature->messageDigest, hash('sha256', $artifact, true))) {
            throw new VerificationFailedException('Artifact does not match the bundle message digest.');
        }

        $signingTime = $this->signingTime($bundle, $trustedRoot, $signature->signature);
        $leaf = $this->verifyCertificate($bundle, $trustedRoot, $signingTime);

        // The signature is ECDSA-over-SHA-256 of the artifact, in DER.
        $valid = Ecdsa::verifyDer(
            message: $artifact,
            derSignature: $signature->signature,
            publicKeyPem: $leaf->publicKeyPem(),
        );

        if (!$valid) {
            throw new VerificationFailedException(
                'Message signature does not verify against the certificate public key.'
            );
        }

        $this->verifyTransparencyLog($bundle, $trustedRoot, bin2hex($signature->messageDigest));
        $identityPolicy->verify($leaf->subjectAlternativeNames(), $leaf->oidcIssuer());
    }

    /** Parse the leaf certificate and verify it chains to a trusted Fulcio root at the signing time. */
    private function verifyCertificate(
        Bundle $bundle,
        TrustedRoot $trustedRoot,
        \DateTimeImmutable $signingTime,
    ): Certificate {
        $leaf = Certificate::fromDer($bundle->leafCertificate);

        if (!$leaf->isEcdsaP256()) {
            throw new UnsupportedBundleException('Only ECDSA P-256 Fulcio certificates are supported in this version.');
        }
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

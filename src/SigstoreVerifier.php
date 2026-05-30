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
use K2gl\Sigstore\Internal\RekorVerifier;

/**
 * Verifies a Sigstore DSSE-attestation bundle end to end, offline, against a
 * caller-supplied trusted root and identity policy, and returns the verified
 * DSSE {@see Envelope}.
 *
 * The pipeline is fail-closed — every step must pass or it throws a
 * {@see Exception\SigstoreException}:
 *
 *   1. the envelope carries an in-toto payload (this version's scope);
 *   2. the leaf certificate chains to a trusted Fulcio CA, valid at the Rekor
 *      integrated time;
 *   3. the DSSE signature verifies under the leaf certificate's key;
 *   4. each Rekor entry is proven (signed entry timestamp and/or inclusion
 *      proof) and bound to the envelope payload;
 *   5. the certificate identity matches the policy.
 *
 * The returned Envelope's payload is the authenticated in-toto Statement. The
 * caller decides how to read it — k2gl/in-toto-attestation's Statement for v1,
 * or its own parsing for the still-common Statement v0.1 — because Sigstore
 * bundles carry both schema versions and authentication does not depend on it.
 */
final class SigstoreVerifier
{
    private readonly CertificateChainVerifier $chainVerifier;
    private readonly RekorVerifier $rekorVerifier;

    public function __construct()
    {
        $this->chainVerifier = new CertificateChainVerifier();
        $this->rekorVerifier = new RekorVerifier();
    }

    /**
     * Convenience wrapper for the common case of having the bundle and trusted
     * root as JSON strings. Parsing errors surface as {@see Exception\InvalidBundleException}
     * / {@see Exception\TrustRootException}, exactly as {@see Bundle::fromJson()}
     * and {@see TrustedRoot::fromJson()} throw them.
     */
    public function verifyFromJson(string $bundleJson, string $trustedRootJson, IdentityPolicy $identityPolicy): Envelope
    {
        return $this->verify(
            Bundle::fromJson($bundleJson),
            TrustedRoot::fromJson($trustedRootJson),
            $identityPolicy,
        );
    }

    public function verify(Bundle $bundle, TrustedRoot $trustedRoot, IdentityPolicy $identityPolicy): Envelope
    {
        // 1. Scope: this version verifies in-toto attestation envelopes.
        if ($bundle->dsseEnvelope->payloadType !== Statement::PAYLOAD_TYPE) {
            throw new UnsupportedBundleException(sprintf(
                'This version verifies in-toto attestations ("%s") only; got payload type "%s".',
                Statement::PAYLOAD_TYPE,
                $bundle->dsseEnvelope->payloadType,
            ));
        }

        $leaf = Certificate::fromDer($bundle->leafCertificate);
        if (!$leaf->isEcdsaP256()) {
            throw new UnsupportedBundleException('Only ECDSA P-256 Fulcio certificates are supported in this version.');
        }

        $signingTime = (new \DateTimeImmutable())->setTimestamp($bundle->tlogEntries[0]->integratedTime);

        // 2. Certificate chains to a trusted Fulcio root at the signing time.
        $this->chainVerifier->verify($leaf, $trustedRoot, $signingTime);

        // 3. DSSE signature verifies under the certificate key.
        $keyVerifier = new CertificateKeyVerifier($leaf->publicKeyPem());
        try {
            $bundle->dsseEnvelope->verify($keyVerifier);
        } catch (DsseException $e) {
            throw new VerificationFailedException(
                'DSSE signature does not verify against the certificate public key.',
                previous: $e,
            );
        }

        // 4. Every transparency-log entry is proven and bound to this envelope.
        foreach ($bundle->tlogEntries as $entry) {
            $this->rekorVerifier->verify($entry, $trustedRoot, $bundle->dsseEnvelope->payload);
        }

        // 5. The certificate identity matches the policy.
        $identityPolicy->verify($leaf->subjectAlternativeNames(), $leaf->oidcIssuer());

        // Authenticated: the envelope payload is the verified in-toto Statement.
        return $bundle->dsseEnvelope;
    }
}

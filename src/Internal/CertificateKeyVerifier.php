<?php

declare(strict_types=1);

namespace K2gl\Sigstore\Internal;

use K2gl\Dsse\Verifier;
use K2gl\Sigstore\Exception\VerificationFailedException;

/**
 * A {@see Verifier} backed by a certificate's public key. Sigstore DSSE
 * signatures are ASN.1 DER ECDSA (not the raw r||s encoding that
 * k2gl/dsse's own EcdsaP256Verifier expects), so this passes the signature
 * straight to ext-openssl. It lets us reuse k2gl/dsse's Envelope/PAE handling
 * while verifying against the Fulcio leaf certificate.
 *
 * @internal
 */
final class CertificateKeyVerifier implements Verifier
{
    private \OpenSSLAsymmetricKey $key;

    public function __construct(string $publicKeyPem)
    {
        $key = openssl_pkey_get_public($publicKeyPem);
        if ($key === false) {
            throw new VerificationFailedException('Unable to load the certificate public key.');
        }
        $this->key = $key;
    }

    public function verify(string $message, string $signature): bool
    {
        return openssl_verify($message, $signature, $this->key, OPENSSL_ALGO_SHA256) === 1;
    }
}

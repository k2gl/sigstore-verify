<?php

declare(strict_types=1);

namespace K2gl\Sigstore\Internal;

use K2gl\Dsse\Verifier;
use K2gl\Sigstore\Exception\VerificationFailedException;

/**
 * A {@see Verifier} backed by ext-openssl, for the schemes openssl_verify
 * handles directly: ECDSA (ASN.1 DER signatures, the form OpenSSL and Sigstore
 * emit) over SHA-256/384/512, and RSA PKCS#1 v1.5 over SHA-256. The signature is
 * passed through verbatim; the digest is fixed at construction from the key's
 * curve or algorithm. It lets us reuse k2gl/dsse's Envelope/PAE handling while
 * verifying against a Sigstore signing key.
 *
 * @internal
 */
final class OpensslVerifier implements Verifier
{
    private \OpenSSLAsymmetricKey $key;

    public function __construct(string $publicKeyPem, private readonly int $algorithm)
    {
        $key = openssl_pkey_get_public($publicKeyPem);

        if ($key === false) {
            throw new VerificationFailedException('Unable to load the signing public key.');
        }
        $this->key = $key;
    }

    public function verify(string $message, string $signature): bool
    {
        return openssl_verify($message, $signature, $this->key, $this->algorithm) === 1;
    }
}

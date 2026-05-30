<?php

declare(strict_types=1);

namespace K2gl\Sigstore\Internal;

/**
 * Verifies ECDSA-over-SHA-256 signatures in ASN.1 DER encoding against a PEM
 * public key, using ext-openssl. Sigstore's Rekor signed entry timestamps and
 * checkpoint note signatures are both DER, so they are passed through verbatim.
 *
 * @internal
 */
final class Ecdsa
{
    public static function verifyDer(string $message, string $derSignature, string $publicKeyPem): bool
    {
        $key = openssl_pkey_get_public($publicKeyPem);
        if ($key === false) {
            return false;
        }
        return openssl_verify($message, $derSignature, $key, OPENSSL_ALGO_SHA256) === 1;
    }
}

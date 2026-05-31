<?php

declare(strict_types=1);

namespace K2gl\Sigstore\Internal;

/**
 * Verifies ECDSA signatures in ASN.1 DER encoding (and RSA PKCS#1 v1.5
 * signatures) against a PEM public key, using ext-openssl. Sigstore's Rekor
 * signed entry timestamps and checkpoint note signatures are DER, so they are
 * passed through verbatim. The digest defaults to SHA-256; RFC 3161 timestamp
 * tokens may use SHA-384/512, so the algorithm is selectable.
 *
 * @internal
 */
final class Ecdsa
{
    public static function verifyDer(
        string $message,
        string $derSignature,
        string $publicKeyPem,
        int $algorithm = OPENSSL_ALGO_SHA256,
    ): bool {
        $key = openssl_pkey_get_public($publicKeyPem);

        if ($key === false) {
            return false;
        }

        return openssl_verify($message, $derSignature, $key, $algorithm) === 1;
    }
}

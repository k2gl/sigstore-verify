<?php

declare(strict_types=1);

namespace K2gl\Sigstore\Internal;

use K2gl\Sigstore\Exception\UnsupportedBundleException;

/**
 * Verifies an RSA PKCS#1 v1.5 signature against an already-computed digest.
 * OpenSSL recovers the signed {@code DigestInfo} from the signature
 * ({@see openssl_public_decrypt} with PKCS#1 padding); this rebuilds the
 * expected {@code DigestInfo} from the supplied digest and compares the two in
 * constant time, so no message bytes are needed.
 *
 * Sigstore RSA message signatures are PKCS#1 v1.5 over SHA-256, but the
 * DigestInfo prefix is selected from the digest algorithm for completeness.
 *
 * @internal
 */
final class RsaPrehashed implements DigestVerifier
{
    /** ASN.1 DER DigestInfo prefixes (everything up to the bare digest), per RFC 8017. */
    private const DIGEST_INFO_PREFIX = [
        'sha256' => '3031300d060960864801650304020105000420',
        'sha384' => '3041300d060960864801650304020205000430',
        'sha512' => '3051300d060960864801650304020305000440',
    ];

    public function __construct(
        private readonly string $publicKeyPem,
        private readonly string $digestAlgorithm,
    ) {}

    public function verifyDigest(string $digest, string $signature): bool
    {
        $prefix = self::DIGEST_INFO_PREFIX[$this->digestAlgorithm] ?? throw new UnsupportedBundleException(sprintf(
            'Unsupported RSA digest algorithm "%s".',
            $this->digestAlgorithm,
        ));

        $key = openssl_pkey_get_public($this->publicKeyPem);

        if ($key === false) {
            return false;
        }
        $recovered = '';

        if (openssl_public_decrypt($signature, $recovered, $key, OPENSSL_PKCS1_PADDING) === false) {
            return false;
        }

        $expected = (string) hex2bin($prefix) . $digest;

        return hash_equals($expected, $recovered);
    }
}

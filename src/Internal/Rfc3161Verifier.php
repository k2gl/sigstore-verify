<?php

declare(strict_types=1);

namespace K2gl\Sigstore\Internal;

use K2gl\Sigstore\CertificateAuthority;
use K2gl\Sigstore\Exception\UnsupportedBundleException;
use K2gl\Sigstore\Exception\VerificationFailedException;
use K2gl\Sigstore\Rfc3161Timestamp;
use DateTimeImmutable;

/**
 * Verifies an RFC 3161 time-stamp token, offline, against the trusted timestamp
 * authorities, and returns the asserted signing time (the TSTInfo genTime):
 *
 *  - the token wraps a TSTInfo and its message-digest signed attribute matches
 *    the TSTInfo, so the token is internally consistent;
 *  - the message imprint is the hash of the signature bytes the caller supplies,
 *    binding the timestamp to this bundle's signature;
 *  - the token signature verifies under a trusted TSA certificate that chains to
 *    its root and is valid at genTime.
 *
 * Every failure throws; a token that cannot be bound or proven is never
 * accepted, and its genTime is never trusted.
 *
 * @internal
 */
final class Rfc3161Verifier
{
    /** id-ct-TSTInfo: the content type a time-stamp token must carry. */
    private const OID_TST_INFO = '1.2.840.113549.1.9.16.1.4';

    private readonly CertificateChainVerifier $chainVerifier;

    public function __construct(?CertificateChainVerifier $chainVerifier = null)
    {
        $this->chainVerifier = $chainVerifier ?? new CertificateChainVerifier;
    }

    /**
     * @param  list<CertificateAuthority> $timestampAuthorities
     * @throws VerificationFailedException|UnsupportedBundleException
     */
    public function verify(
        Rfc3161Timestamp $timestamp,
        string $signature,
        array $timestampAuthorities,
    ): DateTimeImmutable {
        $token = Cms::parse($timestamp->signedTimestamp);

        if ($token->contentTypeOid !== self::OID_TST_INFO) {
            throw new VerificationFailedException('Time-stamp token does not attest to a TSTInfo.');
        }

        // The signed message-digest attribute must match the TSTInfo it covers.
        $tstInfoHash = hash(self::hashAlgorithm($token->digestAlgorithmOid), $token->tstInfoDer, true);

        if ($token->messageDigest === null || ! hash_equals($tstInfoHash, $token->messageDigest)) {
            throw new VerificationFailedException('Time-stamp token message-digest attribute does not match its content.');
        }

        // The message imprint binds the timestamp to the signature it covers.
        $signatureHash = hash(self::hashAlgorithm($token->messageImprintHashOid), $signature, true);

        if (! hash_equals($signatureHash, $token->messageImprintHash)) {
            throw new VerificationFailedException('Time-stamp token does not cover the bundle signature.');
        }

        $this->verifySignature($token, $timestampAuthorities);

        return $token->genTime;
    }

    /**
     * @param  list<CertificateAuthority> $timestampAuthorities
     * @throws VerificationFailedException|UnsupportedBundleException
     */
    private function verifySignature(TimeStampToken $token, array $timestampAuthorities): void
    {
        $algorithm = self::signatureAlgorithm($token->signatureAlgorithmOid);

        foreach ($timestampAuthorities as $authority) {
            $chain = $authority->certificates();

            if ($chain === [] || ! $authority->isValidAt($token->genTime)) {
                continue;
            }

            if (! $this->chainVerifier->isValidChain($chain, $token->genTime)) {
                continue;
            }

            $valid = Ecdsa::verifyDer(
                message: $token->signedAttributes,
                derSignature: $token->signature,
                publicKeyPem: $chain[0]->publicKeyPem(),
                algorithm: $algorithm,
            );

            if ($valid) {
                return;
            }
        }

        throw new VerificationFailedException(
            'Time-stamp token is not signed by a trusted timestamp authority valid at the time of signing.'
        );
    }

    /** Map a digest OID to a hash() algorithm name. */
    private static function hashAlgorithm(string $oid): string
    {
        return match ($oid) {
            '2.16.840.1.101.3.4.2.1' => 'sha256',
            '2.16.840.1.101.3.4.2.2' => 'sha384',
            '2.16.840.1.101.3.4.2.3' => 'sha512',
            default => throw new UnsupportedBundleException(
                sprintf('Unsupported time-stamp digest algorithm "%s".', $oid),
            ),
        };
    }

    /** Map a signature OID (ECDSA or RSA PKCS#1 v1.5 over SHA-2) to an OpenSSL algorithm. */
    private static function signatureAlgorithm(string $oid): int
    {
        return match ($oid) {
            '1.2.840.10045.4.3.2', '1.2.840.113549.1.1.11' => OPENSSL_ALGO_SHA256,
            '1.2.840.10045.4.3.3', '1.2.840.113549.1.1.12' => OPENSSL_ALGO_SHA384,
            '1.2.840.10045.4.3.4', '1.2.840.113549.1.1.13' => OPENSSL_ALGO_SHA512,
            default => throw new UnsupportedBundleException(
                sprintf('Unsupported time-stamp signature algorithm "%s".', $oid),
            ),
        };
    }
}

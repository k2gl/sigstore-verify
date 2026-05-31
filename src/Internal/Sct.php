<?php

declare(strict_types=1);

namespace K2gl\Sigstore\Internal;

use K2gl\Sigstore\Exception\VerificationFailedException;

/**
 * One Signed Certificate Timestamp, parsed from a leaf certificate's embedded
 * SCT list (RFC 6962 §3.2). The fields are the TLS-encoded structure: the log
 * id (SHA-256 of the log key), the timestamp in milliseconds, any SCT
 * extensions, and the {@see https://www.rfc-editor.org/rfc/rfc6962#section-3.2 digitally-signed}
 * algorithm pair and signature.
 *
 * @internal
 */
final class Sct
{
    public const HASH_SHA256 = 4;
    public const SIGNATURE_ECDSA = 3;

    public function __construct(
        public readonly string $logId,
        public readonly int $timestamp,
        public readonly string $extensions,
        public readonly int $hashAlgorithm,
        public readonly int $signatureAlgorithm,
        public readonly string $signature,
    ) {
    }

    /** The SCT timestamp (milliseconds since the epoch) as a point in time. */
    public function time(): \DateTimeImmutable
    {
        return (new \DateTimeImmutable())->setTimestamp(intdiv($this->timestamp, 1000));
    }

    /**
     * Parse a TLS-encoded SignedCertificateTimestampList: a uint16 total length
     * followed by uint16-length-prefixed SCTs.
     *
     * @return list<self>
     */
    public static function parseList(string $bytes): array
    {
        $offset = 0;
        $total = self::uint16($bytes, $offset);
        $end = $offset + $total;

        if ($end > strlen($bytes)) {
            throw new VerificationFailedException('SCT list runs past its declared length.');
        }
        $scts = [];

        while ($offset < $end) {
            $length = self::uint16($bytes, $offset);
            $scts[] = self::parse(self::slice($bytes, $offset, $length));
            $offset += $length;
        }

        return $scts;
    }

    private static function parse(string $sct): self
    {
        $offset = 0;
        self::byte($sct, $offset); // sct_version (v1)
        $logId = self::slice($sct, $offset, 32);
        $offset += 32;
        $timestamp = self::uint64($sct, $offset);

        $extensionsLength = self::uint16($sct, $offset);
        $extensions = self::slice($sct, $offset, $extensionsLength);
        $offset += $extensionsLength;

        $hashAlgorithm = self::byte($sct, $offset);
        $signatureAlgorithm = self::byte($sct, $offset);

        $signatureLength = self::uint16($sct, $offset);
        $signature = self::slice($sct, $offset, $signatureLength);
        $offset += $signatureLength;

        if ($offset !== strlen($sct)) {
            throw new VerificationFailedException('Signed Certificate Timestamp has trailing bytes.');
        }

        return new self(
            logId: $logId,
            timestamp: $timestamp,
            extensions: $extensions,
            hashAlgorithm: $hashAlgorithm,
            signatureAlgorithm: $signatureAlgorithm,
            signature: $signature,
        );
    }

    private static function byte(string $bytes, int &$offset): int
    {
        if ($offset + 1 > strlen($bytes)) {
            throw new VerificationFailedException('Truncated Signed Certificate Timestamp.');
        }

        return ord($bytes[$offset++]);
    }

    private static function uint16(string $bytes, int &$offset): int
    {
        $value = (self::byte($bytes, $offset) << 8) | self::byte($bytes, $offset);

        return $value;
    }

    private static function uint64(string $bytes, int &$offset): int
    {
        $value = 0;

        for ($i = 0; $i < 8; $i++) {
            $value = ($value << 8) | self::byte($bytes, $offset);
        }

        return $value;
    }

    private static function slice(string $bytes, int $offset, int $length): string
    {
        if ($offset + $length > strlen($bytes)) {
            throw new VerificationFailedException('Truncated Signed Certificate Timestamp.');
        }

        return substr($bytes, $offset, $length);
    }
}

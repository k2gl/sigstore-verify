<?php

declare(strict_types=1);

namespace K2gl\Sigstore\Internal;

use DateTimeImmutable;

/**
 * The fields {@see Rfc3161Verifier} needs from a parsed RFC 3161 time-stamp
 * token (a CMS SignedData wrapping a TSTInfo), produced by {@see Cms::parse()}.
 *
 * @internal
 */
final class TimeStampToken
{
    public function __construct(
        /** The signed attributes re-encoded as a DER SET, i.e. the exact bytes the TSA signed. */
        public readonly string $signedAttributes,
        /** The signer's signature over {@see $signedAttributes}, as carried in the token. */
        public readonly string $signature,
        /** OID of the algorithm the signer used (e.g. ecdsa-with-SHA256). */
        public readonly string $signatureAlgorithmOid,
        /** OID of the SignerInfo digest algorithm (hashes the eContent for the message-digest attribute). */
        public readonly string $digestAlgorithmOid,
        /** The eContent: the DER-encoded TSTInfo the token attests to. */
        public readonly string $tstInfoDer,
        /** Value of the signed content-type attribute (an OID), or null when absent. */
        public readonly ?string $contentTypeOid,
        /** Value of the signed message-digest attribute (raw bytes), or null when absent. */
        public readonly ?string $messageDigest,
        /** OID of the messageImprint hash algorithm inside TSTInfo. */
        public readonly string $messageImprintHashOid,
        /** The messageImprint hashed-message bytes: the digest the TSA timestamped. */
        public readonly string $messageImprintHash,
        /** The TSTInfo genTime: the asserted signing time. */
        public readonly DateTimeImmutable $genTime,
    ) {}
}

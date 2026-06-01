<?php

declare(strict_types=1);

namespace K2gl\Sigstore;

use K2gl\Sigstore\Internal\Json;

/**
 * An RFC 3161 timestamp from a bundle's verificationMaterial: a signed
 * time-stamp token (a CMS SignedData over a TSTInfo) from a Timestamp
 * Authority, asserting the time at which the signature existed.
 *
 * @see https://github.com/sigstore/protobuf-specs/blob/main/protos/sigstore_common.proto
 */
final class Rfc3161Timestamp
{
    /** @param string $signedTimestamp the DER-encoded time-stamp token */
    public function __construct(
        public readonly string $signedTimestamp,
    ) {}

    /** @param array<string, mixed> $data */
    public static function fromArray(array $data): self
    {
        return new self(Json::base64($data, 'signedTimestamp'));
    }
}

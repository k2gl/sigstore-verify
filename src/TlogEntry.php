<?php

declare(strict_types=1);

namespace K2gl\Sigstore;

use K2gl\Sigstore\Internal\Json;

/**
 * One Rekor transparency-log entry from a bundle's verification material: which
 * log it is in (log id), when it was integrated, the canonicalized entry body,
 * and the evidence of inclusion — an inclusion promise (signed entry timestamp)
 * and/or a Merkle inclusion proof.
 */
final class TlogEntry
{
    public function __construct(
        public readonly int $logIndex,
        public readonly string $logId,
        public readonly string $kind,
        public readonly int $integratedTime,
        public readonly ?string $signedEntryTimestamp,
        public readonly ?InclusionProof $inclusionProof,
        public readonly string $canonicalizedBody,
    ) {
    }

    /** @param array<string, mixed> $data */
    public static function fromArray(array $data): self
    {
        $logId = Json::base64(Json::object($data, 'logId'), 'keyId');
        $kindVersion = Json::object($data, 'kindVersion');

        $signedEntryTimestamp = null;
        $promise = $data['inclusionPromise'] ?? null;
        if (is_array($promise) && isset($promise['signedEntryTimestamp'])) {
            $signedEntryTimestamp = Json::base64($promise, 'signedEntryTimestamp');
        }

        $inclusionProof = null;
        $proof = $data['inclusionProof'] ?? null;
        if (is_array($proof) && isset($proof['logIndex'], $proof['rootHash'], $proof['checkpoint'])) {
            /** @var array<string, mixed> $proof */
            $inclusionProof = InclusionProof::fromArray($proof);
        }

        return new self(
            Json::int($data, 'logIndex'),
            $logId,
            Json::string($kindVersion, 'kind'),
            Json::int($data, 'integratedTime'),
            $signedEntryTimestamp,
            $inclusionProof,
            Json::base64($data, 'canonicalizedBody'),
        );
    }
}

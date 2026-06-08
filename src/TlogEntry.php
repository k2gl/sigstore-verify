<?php

declare(strict_types=1);

namespace K2gl\Sigstore;

use K2gl\Sigstore\Internal\Json;
use JsonException;

/**
 * One Rekor transparency-log entry from a bundle's verification material: which
 * log it is in (log id), when it was integrated, the canonicalized entry body,
 * and the evidence of inclusion — an inclusion promise (signed entry timestamp)
 * and/or a Merkle inclusion proof. The integrated time is absent for Rekor v2
 * entries, whose signing time comes from an RFC 3161 timestamp instead.
 */
final class TlogEntry
{
    public function __construct(
        public readonly int $logIndex,
        public readonly string $logId,
        public readonly string $kind,
        public readonly ?int $integratedTime,
        public readonly ?string $signedEntryTimestamp,
        public readonly ?InclusionProof $inclusionProof,
        public readonly string $canonicalizedBody,
    ) {}

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
            logIndex: Json::int($data, 'logIndex'),
            logId: $logId,
            kind: Json::string($kindVersion, 'kind'),
            integratedTime: isset($data['integratedTime']) ? Json::int($data, 'integratedTime') : null,
            signedEntryTimestamp: $signedEntryTimestamp,
            inclusionProof: $inclusionProof,
            canonicalizedBody: Json::base64($data, 'canonicalizedBody'),
        );
    }

    /**
     * Whether this is a Rekor v2 hashedrekord (0.0.2) entry, detected from the
     * Merkle-proven canonicalized body — not the unauthenticated kind/version.
     */
    public function isHashedRekordV2(): bool
    {
        try {
            $body = json_decode($this->canonicalizedBody, true, 512, JSON_THROW_ON_ERROR);
        } catch (JsonException) {
            return false;
        }

        return is_array($body)
            && isset($body['spec'])
            && is_array($body['spec'])
            && isset($body['spec']['hashedRekordV002'])
            && is_array($body['spec']['hashedRekordV002']);
    }
}

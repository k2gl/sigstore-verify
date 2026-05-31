<?php

declare(strict_types=1);

namespace K2gl\Sigstore;

use K2gl\Sigstore\Internal\Pem;
use K2gl\Sigstore\Internal\TrustRootJson;

/**
 * A transparency log (Rekor) instance from the trusted root: its log id (the
 * SHA-256 of the public key) and the public key used to verify signed entry
 * timestamps and checkpoint notes.
 */
final class TransparencyLogInstance
{
    public function __construct(
        public readonly string $logId,
        public readonly string $publicKeyPem,
        public readonly ?\DateTimeImmutable $validForStart = null,
        public readonly ?\DateTimeImmutable $validForEnd = null,
    ) {
    }

    /** @param array<string, mixed> $data */
    public static function fromArray(array $data): self
    {
        $publicKey = TrustRootJson::object($data, 'publicKey', 'public_key');
        $der = TrustRootJson::base64($publicKey, 'rawBytes', 'raw_bytes');

        $logId = TrustRootJson::object($data, 'logId', 'log_id');

        $validFor = is_array($publicKey['validFor'] ?? $publicKey['valid_for'] ?? null)
            ? TrustRootJson::object($publicKey, 'validFor', 'valid_for')
            : [];

        return new self(
            logId: TrustRootJson::base64($logId, 'keyId', 'key_id'),
            publicKeyPem: Pem::fromDer($der, 'PUBLIC KEY'),
            validForStart: TrustRootJson::dateOrNull($validFor, 'start'),
            validForEnd: TrustRootJson::dateOrNull($validFor, 'end'),
        );
    }

    /**
     * True if the given moment falls inside this log's operating window. An
     * absent bound is treated as open, so a log without a validFor is always
     * considered valid.
     */
    public function isValidAt(\DateTimeImmutable $moment): bool
    {
        if ($this->validForStart !== null && $moment < $this->validForStart) {
            return false;
        }

        if ($this->validForEnd !== null && $moment > $this->validForEnd) {
            return false;
        }

        return true;
    }
}

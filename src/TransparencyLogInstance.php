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
    ) {
    }

    /** @param array<string, mixed> $data */
    public static function fromArray(array $data): self
    {
        $publicKey = TrustRootJson::object($data, 'publicKey', 'public_key');
        $der = TrustRootJson::base64($publicKey, 'rawBytes', 'raw_bytes');

        $logId = TrustRootJson::object($data, 'logId', 'log_id');

        return new self(
            TrustRootJson::base64($logId, 'keyId', 'key_id'),
            Pem::fromDer($der, 'PUBLIC KEY'),
        );
    }
}

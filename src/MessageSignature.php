<?php

declare(strict_types=1);

namespace K2gl\Sigstore;

use K2gl\Sigstore\Internal\Json;

/**
 * The message-signature content of a bundle: a signature over an artifact,
 * alongside the artifact's digest. Produced by `cosign sign-blob` and friends.
 * Unlike a DSSE attestation, it carries no payload — verification proves that a
 * given artifact was signed, so the caller must supply the artifact bytes.
 *
 * @see https://github.com/sigstore/protobuf-specs/blob/main/protos/sigstore_common.proto
 */
final class MessageSignature
{
    public function __construct(
        public readonly string $hashAlgorithm,
        public readonly string $messageDigest,
        public readonly string $signature,
    ) {
    }

    /** @param array<string, mixed> $data */
    public static function fromArray(array $data): self
    {
        $digest = Json::object($data, 'messageDigest');

        return new self(
            hashAlgorithm: Json::string($digest, 'algorithm'),
            messageDigest: Json::base64($digest, 'digest'),
            signature: Json::base64($data, 'signature'),
        );
    }
}

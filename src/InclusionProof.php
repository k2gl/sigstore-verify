<?php

declare(strict_types=1);

namespace K2gl\Sigstore;

use K2gl\Sigstore\Internal\Json;

/**
 * A Rekor Merkle inclusion proof: the leaf index and tree size, the sibling
 * hashes along the path to the root, the claimed root hash, and the signed
 * checkpoint that commits the log to that root.
 */
final class InclusionProof
{
    /** @param list<string> $hashes raw sibling hashes, bottom to top */
    public function __construct(
        public readonly int $logIndex,
        public readonly int $treeSize,
        public readonly string $rootHash,
        public readonly array $hashes,
        public readonly Checkpoint $checkpoint,
    ) {}

    /** @param array<string, mixed> $data */
    public static function fromArray(array $data): self
    {
        $hashes = [];

        foreach (Json::list($data, 'hashes') as $hash) {
            if (! is_string($hash)) {
                throw new Exception\InvalidBundleException('Inclusion proof hash must be a string.');
            }
            $decoded = base64_decode($hash, true);

            if ($decoded === false) {
                throw new Exception\InvalidBundleException('Inclusion proof hash is not valid base64.');
            }
            $hashes[] = $decoded;
        }

        $checkpoint = Json::object($data, 'checkpoint');

        return new self(
            logIndex: Json::int($data, 'logIndex'),
            treeSize: Json::int($data, 'treeSize'),
            rootHash: Json::base64($data, 'rootHash'),
            hashes: $hashes,
            checkpoint: new Checkpoint(Json::string($checkpoint, 'envelope')),
        );
    }
}

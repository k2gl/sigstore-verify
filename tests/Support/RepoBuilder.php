<?php

declare(strict_types=1);

namespace K2gl\Sigstore\Tests\Support;

/**
 * Builds a small, self-consistent synthetic TUF repository for the four
 * top-level roles, signed with freshly generated Ed25519 keys, that publishes a
 * single `trusted_root.json` target. It lets the TUF resolution path be tested
 * end to end against a repository this test owns, independent of any vendored
 * Sigstore snapshot. Consistent-snapshot naming is used, matching production.
 */
final class RepoBuilder
{
    public SigningKey $rootKey;
    public SigningKey $timestampKey;
    public SigningKey $snapshotKey;
    public SigningKey $targetsKey;

    public int $version = 1;
    public string $expires = '2099-01-01T00:00:00Z';

    public function __construct()
    {
        $this->rootKey = SigningKey::generate();
        $this->timestampKey = SigningKey::generate();
        $this->snapshotKey = SigningKey::generate();
        $this->targetsKey = SigningKey::generate();
    }

    /** The root document, used as the trust-on-first-use anchor for the updater. */
    public function rootDoc(): string
    {
        $signed = [
            '_type' => 'root',
            'spec_version' => '1.0.0',
            'consistent_snapshot' => true,
            'version' => $this->version,
            'expires' => $this->expires,
            'keys' => [
                $this->rootKey->keyid => $this->rootKey->keyObject(),
                $this->timestampKey->keyid => $this->timestampKey->keyObject(),
                $this->snapshotKey->keyid => $this->snapshotKey->keyObject(),
                $this->targetsKey->keyid => $this->targetsKey->keyObject(),
            ],
            'roles' => [
                'root' => ['keyids' => [$this->rootKey->keyid], 'threshold' => 1],
                'timestamp' => ['keyids' => [$this->timestampKey->keyid], 'threshold' => 1],
                'snapshot' => ['keyids' => [$this->snapshotKey->keyid], 'threshold' => 1],
                'targets' => ['keyids' => [$this->targetsKey->keyid], 'threshold' => 1],
            ],
        ];

        return Meta::document($signed, $this->rootKey);
    }

    /**
     * Serve every metadata document and the single target into the fetcher,
     * keyed by the URLs the updater will request, and return the target's
     * consistent-snapshot hash prefix for assertions if needed.
     */
    public function installInto(
        LocalFetcher $fetcher,
        string $metadataBaseUrl,
        string $targetBaseUrl,
        string $targetBytes,
    ): string {
        $hash = Meta::sha256($targetBytes);

        $targets = $this->targetsDoc($targetBytes, $hash);
        $snapshot = $this->snapshotDoc($targets);
        $timestamp = $this->timestampDoc($snapshot);

        $fetcher->put($metadataBaseUrl . '/timestamp.json', $timestamp);
        $fetcher->put($metadataBaseUrl . '/' . $this->version . '.snapshot.json', $snapshot);
        $fetcher->put($metadataBaseUrl . '/' . $this->version . '.targets.json', $targets);
        $fetcher->put($targetBaseUrl . '/' . $hash . '.trusted_root.json', $targetBytes);

        return $hash;
    }

    private function targetsDoc(string $targetBytes, string $hash): string
    {
        $signed = [
            '_type' => 'targets',
            'spec_version' => '1.0.0',
            'version' => $this->version,
            'expires' => $this->expires,
            'targets' => [
                'trusted_root.json' => [
                    'length' => \strlen($targetBytes),
                    'hashes' => ['sha256' => $hash],
                ],
            ],
        ];

        return Meta::document($signed, $this->targetsKey);
    }

    private function snapshotDoc(string $targets): string
    {
        $signed = [
            '_type' => 'snapshot',
            'spec_version' => '1.0.0',
            'version' => $this->version,
            'expires' => $this->expires,
            'meta' => [
                'targets.json' => [
                    'version' => $this->version,
                    'length' => \strlen($targets),
                    'hashes' => ['sha256' => Meta::sha256($targets)],
                ],
            ],
        ];

        return Meta::document($signed, $this->snapshotKey);
    }

    private function timestampDoc(string $snapshot): string
    {
        $signed = [
            '_type' => 'timestamp',
            'spec_version' => '1.0.0',
            'version' => $this->version,
            'expires' => $this->expires,
            'meta' => [
                'snapshot.json' => [
                    'version' => $this->version,
                    'length' => \strlen($snapshot),
                    'hashes' => ['sha256' => Meta::sha256($snapshot)],
                ],
            ],
        ];

        return Meta::document($signed, $this->timestampKey);
    }
}

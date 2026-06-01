<?php

declare(strict_types=1);

namespace K2gl\Sigstore\Tests\Support;

use K2gl\Tuf\Exception\DownloadException;
use K2gl\Tuf\Fetcher;

/**
 * An in-memory {@see Fetcher} over a fixed url => bytes map, so the TUF client
 * workflow can be driven entirely offline in tests. A missing URL throws,
 * exactly as a "not found" response would.
 */
final class LocalFetcher implements Fetcher
{
    /** @param array<string, string> $files url => bytes */
    public function __construct(private array $files = []) {}

    public function put(string $url, string $bytes): void
    {
        $this->files[$url] = $bytes;
    }

    public function fetch(string $url, int $maxLength): string
    {
        $bytes = $this->files[$url] ?? throw new DownloadException(\sprintf('Not found: %s', $url));

        if (\strlen($bytes) > $maxLength) {
            throw new DownloadException(\sprintf('Response for "%s" exceeds %d bytes.', $url, $maxLength));
        }

        return $bytes;
    }
}

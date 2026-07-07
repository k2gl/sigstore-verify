<?php

declare(strict_types=1);

namespace K2gl\Sigstore\Tests;

use K2gl\Sigstore\CertificateAuthority;
use K2gl\Sigstore\Exception\TrustRootException;
use K2gl\Sigstore\Internal\TrustRootJson;
use K2gl\Sigstore\Tests\Support\LocalFetcher;
use K2gl\Sigstore\Tests\Support\RepoBuilder;
use K2gl\Sigstore\TransparencyLogInstance;
use K2gl\Sigstore\TrustedRoot;
use K2gl\Tuf\Exception\LengthOrHashMismatchException;
use K2gl\Tuf\Updater;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use DateTimeImmutable;

use function K2gl\PHPUnitFluentAssertions\fact;

/**
 * Drives the TUF resolution path entirely offline: against a vendored real
 * Sigstore public-good snapshot and against a synthetic repository this test
 * signs itself, plus the fail-closed negatives.
 */
#[CoversClass(TrustedRoot::class)]
#[CoversClass(TrustRootJson::class)]
#[CoversClass(CertificateAuthority::class)]
#[CoversClass(TransparencyLogInstance::class)]
#[CoversClass(TrustRootException::class)]
final class TrustedRootFromTufTest extends TestCase
{
    private const SIGSTORE_METADATA_URL = 'https://tuf-repo-cdn.sigstore.dev';
    private const SIGSTORE_TARGETS_URL = 'https://tuf-repo-cdn.sigstore.dev/targets';
    private const SIGSTORE_TARGET_HASH = '6494e21ea73fa7ee769f85f57d5a3e6a08725eae1e38c755fc3517c9e6bc0b66';

    /** A fixed instant inside the validity window of the vendored snapshot. */
    private function referenceTime(): DateTimeImmutable
    {
        return new DateTimeImmutable('2026-06-01T00:00:00Z');
    }

    private function read(string $path): string
    {
        $bytes = file_get_contents($path);
        fact($bytes)->isString();

        return $bytes;
    }

    private function bundledRoot(): string
    {
        return $this->read(__DIR__ . '/../resources/sigstore-tuf-root.json');
    }

    private function snapshotFetcher(): LocalFetcher
    {
        $dir = __DIR__ . '/fixtures/sigstore-tuf';

        return new LocalFetcher([
            self::SIGSTORE_METADATA_URL . '/timestamp.json' => $this->read($dir . '/timestamp.json'),
            self::SIGSTORE_METADATA_URL . '/165.snapshot.json' => $this->read($dir . '/165.snapshot.json'),
            self::SIGSTORE_METADATA_URL . '/14.targets.json' => $this->read($dir . '/14.targets.json'),
            self::SIGSTORE_TARGETS_URL . '/' . self::SIGSTORE_TARGET_HASH . '.trusted_root.json'
                => $this->read($dir . '/targets/' . self::SIGSTORE_TARGET_HASH . '.trusted_root.json'),
        ]);
    }

    private function snapshotUpdater(LocalFetcher $fetcher): Updater
    {
        return new Updater(
            trustedRoot: $this->bundledRoot(),
            metadataBaseUrl: self::SIGSTORE_METADATA_URL,
            targetBaseUrl: self::SIGSTORE_TARGETS_URL,
            fetcher: $fetcher,
            referenceTime: $this->referenceTime(),
        );
    }

    public function testFromTufResolvesVendoredSigstoreSnapshot(): void
    {
        $root = TrustedRoot::fromTuf($this->snapshotUpdater($this->snapshotFetcher()));

        fact(count($root->certificateAuthorities))->is(2);
        fact(count($root->transparencyLogs))->is(2);
        fact(count($root->ctLogs))->is(2);
        fact(count($root->timestampAuthorities))->is(1);
    }

    public function testFromSigstorePublicGoodUsesInjectedFetcher(): void
    {
        $root = TrustedRoot::fromSigstorePublicGood($this->snapshotFetcher(), $this->referenceTime());

        fact(count($root->certificateAuthorities))->is(2);
        fact(count($root->transparencyLogs))->is(2);
    }

    public function testMissingTargetThrows(): void
    {
        // act + assert
        fact(fn () => TrustedRoot::fromTuf($this->snapshotUpdater($this->snapshotFetcher()), 'no-such-target.json'))
            ->throws(TrustRootException::class);
    }

    public function testTamperedTargetThrows(): void
    {
        // arrange
        $fetcher = $this->snapshotFetcher();
        $fetcher->put(
            self::SIGSTORE_TARGETS_URL . '/' . self::SIGSTORE_TARGET_HASH . '.trusted_root.json',
            '{"tampered": true}',
        );

        // act + assert
        fact(fn () => TrustedRoot::fromTuf($this->snapshotUpdater($fetcher)))->throws(LengthOrHashMismatchException::class);
    }

    public function testFromTufResolvesSyntheticRepository(): void
    {
        $repo = new RepoBuilder;
        $fetcher = new LocalFetcher;
        $target = $this->read(__DIR__ . '/fixtures/trusted-root-public-good.json');
        $repo->installInto($fetcher, 'https://repo.test', 'https://repo.test/targets', $target);

        $updater = new Updater(
            trustedRoot: $repo->rootDoc(),
            metadataBaseUrl: 'https://repo.test',
            targetBaseUrl: 'https://repo.test/targets',
            fetcher: $fetcher,
        );
        $root = TrustedRoot::fromTuf($updater);

        fact(count($root->certificateAuthorities))->is(2);
        fact(count($root->transparencyLogs))->is(1);
    }
}

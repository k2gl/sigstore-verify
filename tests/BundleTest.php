<?php

declare(strict_types=1);

namespace K2gl\Sigstore\Tests;

use function K2gl\PHPUnitFluentAssertions\fact;

use K2gl\Sigstore\Bundle;
use K2gl\Sigstore\Exception\InvalidBundleException;
use K2gl\Sigstore\Exception\UnsupportedBundleException;
use K2gl\Sigstore\Internal\Json;
use K2gl\Sigstore\TlogEntry;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;

#[CoversClass(Bundle::class)]
#[CoversClass(TlogEntry::class)]
#[CoversClass(Json::class)]
#[CoversClass(InvalidBundleException::class)]
#[CoversClass(UnsupportedBundleException::class)]
final class BundleTest extends TestCase
{
    /** @return array<string, mixed> */
    private function minimalDsseEnvelope(): array
    {
        return [
            'payload' => base64_encode('{}'),
            'payloadType' => 'application/vnd.in-toto+json',
            'signatures' => [['sig' => base64_encode('signature-bytes')]],
        ];
    }

    public function testParsesRealProvenanceBundle(): void
    {
        $raw = file_get_contents(__DIR__ . '/fixtures/bundle-provenance.json');
        self::assertIsString($raw);

        $bundle = Bundle::fromJson($raw);
        fact($bundle->dsseEnvelope->payloadType)->is('application/vnd.in-toto+json');
        fact(count($bundle->tlogEntries))->is(1);
        fact($bundle->tlogEntries[0]->kind)->is('intoto');
        fact($bundle->leafCertificate === '')->false();
    }

    public function testRejectsNonObjectJson(): void
    {
        $this->expectException(InvalidBundleException::class);
        Bundle::fromJson('[]');
    }

    public function testRejectsUnknownMediaType(): void
    {
        $this->expectException(UnsupportedBundleException::class);
        Bundle::fromArray(['mediaType' => 'application/json', 'dsseEnvelope' => $this->minimalDsseEnvelope()]);
    }

    public function testRejectsMessageSignatureContent(): void
    {
        $this->expectException(UnsupportedBundleException::class);
        Bundle::fromArray([
            'mediaType' => 'application/vnd.dev.sigstore.bundle.v0.3+json',
            'messageSignature' => ['messageDigest' => ['algorithm' => 'SHA2_256', 'digest' => base64_encode('x')]],
        ]);
    }

    public function testRejectsPublicKeyMaterial(): void
    {
        $this->expectException(UnsupportedBundleException::class);
        Bundle::fromArray([
            'mediaType' => 'application/vnd.dev.sigstore.bundle.v0.3+json',
            'verificationMaterial' => [
                'publicKey' => ['hint' => 'abc'],
                'tlogEntries' => [],
            ],
            'dsseEnvelope' => $this->minimalDsseEnvelope(),
        ]);
    }

    public function testRejectsMissingContent(): void
    {
        $this->expectException(InvalidBundleException::class);
        Bundle::fromArray(['mediaType' => 'application/vnd.dev.sigstore.bundle.v0.3+json']);
    }
}

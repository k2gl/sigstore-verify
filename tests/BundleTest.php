<?php

declare(strict_types=1);

namespace K2gl\Sigstore\Tests;

use function K2gl\PHPUnitFluentAssertions\fact;

use K2gl\Sigstore\Bundle;
use K2gl\Sigstore\Exception\InvalidBundleException;
use K2gl\Sigstore\Exception\UnsupportedBundleException;
use K2gl\Sigstore\Internal\Json;
use K2gl\Sigstore\MessageSignature;
use K2gl\Sigstore\TlogEntry;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;

#[CoversClass(Bundle::class)]
#[CoversClass(MessageSignature::class)]
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

    /** @return array<string, mixed> */
    private function minimalTlogEntry(): array
    {
        return [
            'logIndex' => '1',
            'logId' => ['keyId' => base64_encode('key-id')],
            'kindVersion' => ['kind' => 'hashedrekord', 'version' => '0.0.1'],
            'integratedTime' => '1700000000',
            'inclusionPromise' => ['signedEntryTimestamp' => base64_encode('set')],
            'canonicalizedBody' => base64_encode('{}'),
        ];
    }

    public function testParsesRealProvenanceBundle(): void
    {
        $raw = file_get_contents(__DIR__ . '/fixtures/bundle-provenance.json');
        self::assertIsString($raw);

        $bundle = Bundle::fromJson($raw);

        fact($bundle->isDsse())->true();
        fact($bundle->dsseEnvelope?->payloadType)->is('application/vnd.in-toto+json');
        fact(count($bundle->tlogEntries))->is(1);
        fact($bundle->tlogEntries[0]->kind)->is('intoto');
        fact($bundle->leafCertificate === '')->false();
    }

    public function testParsesMessageSignatureBundle(): void
    {
        $bundle = Bundle::fromArray([
            'mediaType' => 'application/vnd.dev.sigstore.bundle.v0.3+json',
            'verificationMaterial' => [
                'certificate' => ['rawBytes' => base64_encode('der')],
                'tlogEntries' => [$this->minimalTlogEntry()],
            ],
            'messageSignature' => [
                'messageDigest' => ['algorithm' => 'SHA2_256', 'digest' => base64_encode('digest')],
                'signature' => base64_encode('sig'),
            ],
        ]);

        fact($bundle->isMessageSignature())->true();
        fact($bundle->isDsse())->false();
        fact($bundle->messageSignature?->hashAlgorithm)->is('SHA2_256');
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

    public function testRejectsPublicKeyMaterial(): void
    {
        $this->expectException(UnsupportedBundleException::class);
        Bundle::fromArray([
            'mediaType' => 'application/vnd.dev.sigstore.bundle.v0.3+json',
            'verificationMaterial' => [
                'publicKey' => ['hint' => 'abc'],
                'tlogEntries' => [$this->minimalTlogEntry()],
            ],
            'dsseEnvelope' => $this->minimalDsseEnvelope(),
        ]);
    }

    public function testRejectsMissingContent(): void
    {
        $this->expectException(InvalidBundleException::class);
        Bundle::fromArray([
            'mediaType' => 'application/vnd.dev.sigstore.bundle.v0.3+json',
            'verificationMaterial' => [
                'certificate' => ['rawBytes' => base64_encode('der')],
                'tlogEntries' => [$this->minimalTlogEntry()],
            ],
        ]);
    }

    public function testRejectsEmptyTlogEntries(): void
    {
        $this->expectException(InvalidBundleException::class);
        Bundle::fromArray([
            'mediaType' => 'application/vnd.dev.sigstore.bundle.v0.3+json',
            'verificationMaterial' => [
                'certificate' => ['rawBytes' => base64_encode('der')],
                'tlogEntries' => [],
            ],
            'dsseEnvelope' => $this->minimalDsseEnvelope(),
        ]);
    }
}

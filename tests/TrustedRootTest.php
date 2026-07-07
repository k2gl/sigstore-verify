<?php

declare(strict_types=1);

namespace K2gl\Sigstore\Tests;

use K2gl\Sigstore\CertificateAuthority;
use K2gl\Sigstore\Exception\TrustRootException;
use K2gl\Sigstore\Internal\TrustRootJson;
use K2gl\Sigstore\TransparencyLogInstance;
use K2gl\Sigstore\TrustedRoot;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use DateTimeImmutable;

use function K2gl\PHPUnitFluentAssertions\fact;

#[CoversClass(TrustedRoot::class)]
#[CoversClass(TrustRootJson::class)]
#[CoversClass(CertificateAuthority::class)]
#[CoversClass(TransparencyLogInstance::class)]
#[CoversClass(TrustRootException::class)]
final class TrustedRootTest extends TestCase
{
    private function publicGood(): TrustedRoot
    {
        $raw = file_get_contents(__DIR__ . '/fixtures/trusted-root-public-good.json');
        fact($raw)->isString();

        return TrustedRoot::fromJson($raw);
    }

    public function testParsesPublicGoodRoot(): void
    {
        $root = $this->publicGood();
        fact(count($root->certificateAuthorities))->is(2);
        fact(count($root->transparencyLogs))->is(1);
    }

    public function testFindsTransparencyLogByLogId(): void
    {
        $logId = base64_decode('wNI9atQGlz+VWfO6LRygH4QUfY/8W4RFwiT5i5WRgB0=', true);
        fact($logId)->isString();

        fact($this->publicGood()->findTransparencyLog($logId) !== null)->true();
    }

    public function testReturnsNullForUnknownLogId(): void
    {
        fact($this->publicGood()->findTransparencyLog(str_repeat("\x01", 32)))->null();
    }

    public function testValidForWindowIsHonored(): void
    {
        // CA[0] in the public-good root expired at the end of 2022.
        $ca = $this->publicGood()->certificateAuthorities[0];
        fact($ca->isValidAt(new DateTimeImmutable('2022-01-01T00:00:00Z')))->true();
        fact($ca->isValidAt(new DateTimeImmutable('2024-01-01T00:00:00Z')))->false();
    }

    public function testRejectsNonObjectJson(): void
    {
        // act + assert
        fact(static fn () => TrustedRoot::fromJson('"a string"'))->throws(TrustRootException::class);
    }

    public function testRejectsRootWithoutTransparencyLogs(): void
    {
        // act + assert
        fact(static fn () => TrustedRoot::fromJson('{"certificateAuthorities":[]}'))->throws(TrustRootException::class);
    }
}

<?php

declare(strict_types=1);

namespace K2gl\Sigstore\Tests;

use K2gl\Sigstore\Exception\VerificationFailedException;
use K2gl\Sigstore\IdentityPolicy;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;

#[CoversClass(IdentityPolicy::class)]
#[CoversClass(VerificationFailedException::class)]
final class IdentityPolicyTest extends TestCase
{
    private const SAN = 'https://github.com/acme/app/.github/workflows/release.yml@refs/heads/main';
    private const ISSUER = 'https://token.actions.githubusercontent.com';

    public function testAcceptsMatchingIdentity(): void
    {
        $policy = new IdentityPolicy(self::SAN, self::ISSUER);
        $policy->verify(['https://other', self::SAN], self::ISSUER);
        $this->addToAssertionCount(1);
    }

    public function testRejectsWrongIssuer(): void
    {
        $this->expectException(VerificationFailedException::class);
        (new IdentityPolicy(self::SAN, self::ISSUER))->verify([self::SAN], 'https://accounts.google.com');
    }

    public function testRejectsMissingIssuer(): void
    {
        $this->expectException(VerificationFailedException::class);
        (new IdentityPolicy(self::SAN, self::ISSUER))->verify([self::SAN], null);
    }

    public function testRejectsSanNotPresent(): void
    {
        $this->expectException(VerificationFailedException::class);
        (new IdentityPolicy(self::SAN, self::ISSUER))->verify(['https://someone-else'], self::ISSUER);
    }

    public function testConstructorRejectsEmptyValues(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        new IdentityPolicy('', self::ISSUER);
    }
}

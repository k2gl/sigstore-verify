<?php

declare(strict_types=1);

namespace K2gl\Sigstore\Tests;

use K2gl\Sigstore\Exception\VerificationFailedException;
use K2gl\Sigstore\IdentityPolicy;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use InvalidArgumentException;

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
        $this->expectException(InvalidArgumentException::class);
        new IdentityPolicy('', self::ISSUER);
    }

    public function testSanRegexAcceptsMatching(): void
    {
        $policy = IdentityPolicy::sanRegex('#^https://github\.com/acme/app/.+@refs/tags/.+$#', self::ISSUER);
        $policy->verify(['https://github.com/acme/app/.github/workflows/release.yml@refs/tags/v1.2.3'], self::ISSUER);
        $this->addToAssertionCount(1);
    }

    public function testSanRegexRejectsNonMatching(): void
    {
        $policy = IdentityPolicy::sanRegex('#^https://github\.com/acme/app/.+@refs/tags/.+$#', self::ISSUER);
        $this->expectException(VerificationFailedException::class);
        $policy->verify(['https://github.com/acme/app/.github/workflows/release.yml@refs/heads/main'], self::ISSUER);
    }

    public function testSanRegexRejectsInvalidPattern(): void
    {
        $this->expectException(InvalidArgumentException::class);
        IdentityPolicy::sanRegex('not a valid (regex', self::ISSUER);
    }

    public function testGithubActionsExactMatch(): void
    {
        $policy = IdentityPolicy::githubActions('acme/app', 'release.yml', 'refs/heads/main');
        $policy->verify([self::SAN], self::ISSUER);
        $this->addToAssertionCount(1);
    }

    public function testGithubActionsMatchesAnyWorkflowAndRef(): void
    {
        $policy = IdentityPolicy::githubActions('acme/app');
        $policy->verify(['https://github.com/acme/app/.github/workflows/build.yml@refs/tags/v2'], self::ISSUER);
        $this->addToAssertionCount(1);
    }

    public function testGithubActionsRejectsAnotherRepository(): void
    {
        $policy = IdentityPolicy::githubActions('acme/app');
        $this->expectException(VerificationFailedException::class);
        $policy->verify(['https://github.com/evil/app/.github/workflows/build.yml@refs/heads/main'], self::ISSUER);
    }

    public function testGitlabCiMatchesAnyRef(): void
    {
        $policy = IdentityPolicy::gitlabCi('my-group/my-project');
        $policy->verify(['https://gitlab.com/my-group/my-project//.gitlab-ci.yml@refs/heads/main'], 'https://gitlab.com');
        $this->addToAssertionCount(1);
    }

    public function testGitlabCiExactMatch(): void
    {
        $policy = IdentityPolicy::gitlabCi('my-group/my-project', '.gitlab-ci.yml', 'refs/heads/main');
        $policy->verify(['https://gitlab.com/my-group/my-project//.gitlab-ci.yml@refs/heads/main'], 'https://gitlab.com');
        $this->addToAssertionCount(1);
    }
}

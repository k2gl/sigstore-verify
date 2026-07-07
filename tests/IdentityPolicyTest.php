<?php

declare(strict_types=1);

namespace K2gl\Sigstore\Tests;

use K2gl\Sigstore\Exception\VerificationFailedException;
use K2gl\Sigstore\IdentityPolicy;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use InvalidArgumentException;

use function K2gl\PHPUnitFluentAssertions\fact;

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
        // act + assert
        fact(static fn () => (new IdentityPolicy(self::SAN, self::ISSUER))->verify([self::SAN], 'https://accounts.google.com'))
            ->throws(VerificationFailedException::class);
    }

    public function testRejectsMissingIssuer(): void
    {
        // act + assert
        fact(static fn () => (new IdentityPolicy(self::SAN, self::ISSUER))->verify([self::SAN], null))
            ->throws(VerificationFailedException::class);
    }

    public function testRejectsSanNotPresent(): void
    {
        // act + assert
        fact(static fn () => (new IdentityPolicy(self::SAN, self::ISSUER))->verify(['https://someone-else'], self::ISSUER))
            ->throws(VerificationFailedException::class);
    }

    public function testConstructorRejectsEmptyValues(): void
    {
        // act + assert
        fact(static fn () => new IdentityPolicy('', self::ISSUER))->throws(InvalidArgumentException::class);
    }

    public function testSanRegexAcceptsMatching(): void
    {
        $policy = IdentityPolicy::sanRegex('#^https://github\.com/acme/app/.+@refs/tags/.+$#', self::ISSUER);
        $policy->verify(['https://github.com/acme/app/.github/workflows/release.yml@refs/tags/v1.2.3'], self::ISSUER);
        $this->addToAssertionCount(1);
    }

    public function testSanRegexRejectsNonMatching(): void
    {
        // arrange
        $policy = IdentityPolicy::sanRegex('#^https://github\.com/acme/app/.+@refs/tags/.+$#', self::ISSUER);

        // act + assert
        fact(static fn () => $policy->verify(['https://github.com/acme/app/.github/workflows/release.yml@refs/heads/main'], self::ISSUER))
            ->throws(VerificationFailedException::class);
    }

    public function testSanRegexRejectsInvalidPattern(): void
    {
        // act + assert
        fact(static fn () => IdentityPolicy::sanRegex('not a valid (regex', self::ISSUER))->throws(InvalidArgumentException::class);
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
        // arrange
        $policy = IdentityPolicy::githubActions('acme/app');

        // act + assert
        fact(static fn () => $policy->verify(['https://github.com/evil/app/.github/workflows/build.yml@refs/heads/main'], self::ISSUER))
            ->throws(VerificationFailedException::class);
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

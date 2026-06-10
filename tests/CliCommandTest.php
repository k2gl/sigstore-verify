<?php

declare(strict_types=1);

namespace K2gl\Sigstore\Tests;

use K2gl\Sigstore\Cli\Command;
use K2gl\Sigstore\Cli\Options;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;

use function K2gl\PHPUnitFluentAssertions\fact;

/**
 * The CLI is exercised fully offline: conformance fixtures provide a real
 * message-signature bundle, its artifact and the public-good trusted root.
 */
#[CoversClass(Command::class)]
#[CoversClass(Options::class)]
final class CliCommandTest extends TestCase
{
    private const BEACON_SAN = 'https://github.com/sigstore-conformance/extremely-dangerous-public-oidc-beacon/.github/workflows/extremely-dangerous-oidc-beacon.yml@refs/heads/main';
    private const ISSUER = 'https://token.actions.githubusercontent.com';

    /** @var resource */
    private $stdout;

    /** @var resource */
    private $stderr;

    protected function setUp(): void
    {
        $stdout = fopen('php://memory', 'w+');
        $stderr = fopen('php://memory', 'w+');
        fact(is_resource($stdout))->true();
        fact(is_resource($stderr))->true();

        assert(is_resource($stdout) && is_resource($stderr));
        $this->stdout = $stdout;
        $this->stderr = $stderr;
    }

    private function runCli(string ...$arguments): int
    {
        $command = new Command($this->stdout, $this->stderr);

        return $command->run(['sigstore-verify', ...$arguments]);
    }

    private function cliOutput(): string
    {
        rewind($this->stdout);

        return (string) stream_get_contents($this->stdout);
    }

    private function cliErrors(): string
    {
        rewind($this->stderr);

        return (string) stream_get_contents($this->stderr);
    }

    private static function fixture(string $name): string
    {
        return __DIR__ . '/fixtures/' . $name;
    }

    public function testHelpPrintsUsageAndExitsZero(): void
    {
        $exit = $this->runCli('--help');

        fact($exit)->is(0);
        fact(str_contains($this->cliOutput(), 'Usage: sigstore-verify'))->true();
    }

    public function testMissingIdentityIsAUsageError(): void
    {
        $exit = $this->runCli(
            self::fixture('conformance-artifact.txt'),
            self::fixture('conformance-msgsig-v0.3.json'),
        );

        fact($exit)->is(2);
        fact(str_contains($this->cliErrors(), 'Expected an identity'))->true();
    }

    public function testUnknownOptionIsAUsageError(): void
    {
        $exit = $this->runCli('a', 'b', '--nope', 'x');

        fact($exit)->is(2);
        fact(str_contains($this->cliErrors(), 'Unknown option "--nope"'))->true();
    }

    public function testVerifiesMessageSignatureArtifactWithExactIdentity(): void
    {
        $exit = $this->runCli(
            self::fixture('conformance-artifact.txt'),
            self::fixture('conformance-msgsig-v0.3.json'),
            '--san',
            self::BEACON_SAN,
            '--issuer',
            self::ISSUER,
            '--trusted-root',
            self::fixture('trusted-root-public-good.json'),
        );

        fact($this->cliErrors())->is('');
        fact($exit)->is(0);
        fact(str_contains($this->cliOutput(), 'VERIFIED'))->true();
    }

    public function testVerifiesWithGithubActionsIdentityFactory(): void
    {
        $exit = $this->runCli(
            self::fixture('conformance-artifact.txt'),
            self::fixture('conformance-msgsig-v0.3.json'),
            '--repository',
            'sigstore-conformance/extremely-dangerous-public-oidc-beacon',
            '--workflow',
            'extremely-dangerous-oidc-beacon.yml',
            '--ref',
            'refs/heads/main',
            '--trusted-root',
            self::fixture('trusted-root-public-good.json'),
        );

        fact($this->cliErrors())->is('');
        fact($exit)->is(0);
        fact(str_contains($this->cliOutput(), 'VERIFIED'))->true();
    }

    public function testRejectsWrongSignerIdentity(): void
    {
        $exit = $this->runCli(
            self::fixture('conformance-artifact.txt'),
            self::fixture('conformance-msgsig-v0.3.json'),
            '--repository',
            'evil/repository',
            '--trusted-root',
            self::fixture('trusted-root-public-good.json'),
        );

        fact($exit)->is(1);
        fact(str_contains($this->cliErrors(), 'FAILED: no bundle verifies the artifact'))->true();
        fact(str_contains($this->cliErrors(), 'identity'))->true();
    }

    public function testRejectsDsseAttestationWhoseSubjectDoesNotMatchTheArtifact(): void
    {
        $exit = $this->runCli(
            self::fixture('conformance-artifact.txt'),
            self::fixture('bundle-provenance.json'),
            '--san',
            self::BEACON_SAN,
            '--issuer',
            self::ISSUER,
            '--trusted-root',
            self::fixture('trusted-root-public-good.json'),
        );

        fact($exit)->is(1);
        fact(str_contains($this->cliErrors(), 'FAILED'))->true();
    }

    public function testJsonLinesVerifiesWhenAnyBundleMatches(): void
    {
        $provenance = file_get_contents(self::fixture('bundle-provenance.json'));
        $messageSignature = file_get_contents(self::fixture('conformance-msgsig-v0.3.json'));
        fact(is_string($provenance))->true();
        fact(is_string($messageSignature))->true();

        $jsonl = tempnam(sys_get_temp_dir(), 'bundles');
        fact(is_string($jsonl))->true();
        assert(is_string($jsonl) && is_string($provenance) && is_string($messageSignature));
        file_put_contents($jsonl, json_encode(json_decode($provenance)) . "\n" . json_encode(json_decode($messageSignature)) . "\n");

        try {
            $exit = $this->runCli(
                self::fixture('conformance-artifact.txt'),
                $jsonl,
                '--san',
                self::BEACON_SAN,
                '--issuer',
                self::ISSUER,
                '--trusted-root',
                self::fixture('trusted-root-public-good.json'),
            );
        } finally {
            unlink($jsonl);
        }

        fact($exit)->is(0);
        fact(str_contains($this->cliOutput(), 'VERIFIED'))->true();
    }

    public function testMissingArtifactFileIsAnError(): void
    {
        $exit = $this->runCli(
            '/nonexistent/artifact',
            self::fixture('conformance-msgsig-v0.3.json'),
            '--repository',
            'any/repo',
        );

        fact($exit)->is(2);
        fact(str_contains($this->cliErrors(), 'does not exist'))->true();
    }
}

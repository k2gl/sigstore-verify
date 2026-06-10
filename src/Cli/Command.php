<?php

declare(strict_types=1);

namespace K2gl\Sigstore\Cli;

use InvalidArgumentException;
use K2gl\Sigstore\Bundle;
use K2gl\Sigstore\Exception\SigstoreException;
use K2gl\Sigstore\IdentityPolicy;
use K2gl\Sigstore\SigstoreVerifier;
use K2gl\Sigstore\SubjectPolicy;
use K2gl\Sigstore\TrustedRoot;
use RuntimeException;

/**
 * Implementation behind the `sigstore-verify` binary: verifies an artifact
 * against one or more Sigstore bundles (plain JSON or JSON Lines, as written
 * by `gh attestation download`). Fail-closed: the command succeeds only when
 * at least one bundle fully verifies against the expected signer identity
 * and the artifact bytes on disk.
 */
final class Command
{
    private const USAGE = <<<'TXT'
Usage: sigstore-verify <artifact> <bundle.json[l]> (--repository <owner/repo> | --san <SAN> --issuer <issuer>) [options]

Verifies that the artifact is covered by a valid Sigstore attestation whose
signer matches the expected identity. Fail-closed: any problem exits non-zero.

Identity (pick one form):
  --repository <owner/repo>     GitHub Actions identity, with optional filters:
    --workflow <file.yml>         workflow file name, e.g. attest.yml
    --ref <ref>                   git ref, e.g. refs/tags/1.2.3
  --san <value> --issuer <iss>  exact certificate SAN and OIDC issuer

Options:
  --trusted-root <path>         trusted root JSON (offline); default: fetch the
                                Sigstore public-good root via TUF (network)
  --digest-alg <alg>            subject digest algorithm for DSSE attestations
                                (sha256 or sha512, default sha256)
  -h, --help                    show this help
TXT;

    /** @var resource */
    private $stdout;

    /** @var resource */
    private $stderr;

    /**
     * @param resource|null $stdout
     * @param resource|null $stderr
     */
    public function __construct($stdout = null, $stderr = null)
    {
        $this->stdout = $stdout ?? STDOUT;
        $this->stderr = $stderr ?? STDERR;
    }

    /**
     * @param list<string> $argv full argv including the script name
     */
    public function run(array $argv): int
    {
        try {
            $options = Options::parse(array_slice($argv, 1));
        } catch (InvalidArgumentException $e) {
            fwrite($this->stderr, 'error: ' . $e->getMessage() . "\n\n" . self::USAGE . "\n");

            return 2;
        }

        if ($options->help) {
            fwrite($this->stdout, self::USAGE . "\n");

            return 0;
        }

        try {
            return $this->verify($options);
        } catch (RuntimeException $e) {
            fwrite($this->stderr, 'error: ' . $e->getMessage() . "\n");

            return 2;
        }
    }

    private function verify(Options $options): int
    {
        $artifactBytes = $this->readFile($options->artifact);
        $bundles = $this->readBundles($options->bundle);
        $identityPolicy = $this->identityPolicy($options);
        $trustedRoot = $options->trustedRoot !== null
            ? TrustedRoot::fromJson($this->readFile($options->trustedRoot))
            : TrustedRoot::fromSigstorePublicGood();

        $verifier = new SigstoreVerifier;
        $failures = [];

        foreach ($bundles as $index => $bundle) {
            try {
                $this->verifyBundle(
                    verifier: $verifier,
                    bundle: $bundle,
                    artifactPath: $options->artifact,
                    artifactBytes: $artifactBytes,
                    trustedRoot: $trustedRoot,
                    identityPolicy: $identityPolicy,
                    digestAlgorithm: $options->digestAlgorithm,
                );

                return 0;
            } catch (SigstoreException $e) {
                $failures[] = sprintf('bundle #%d: %s', $index + 1, $e->getMessage());
            }
        }

        fwrite($this->stderr, "FAILED: no bundle verifies the artifact\n");

        foreach ($failures as $failure) {
            fwrite($this->stderr, '  ' . $failure . "\n");
        }

        return 1;
    }

    private function verifyBundle(
        SigstoreVerifier $verifier,
        Bundle $bundle,
        string $artifactPath,
        string $artifactBytes,
        TrustedRoot $trustedRoot,
        IdentityPolicy $identityPolicy,
        string $digestAlgorithm,
    ): void {
        if ($bundle->isDsse()) {
            $digest = hash($digestAlgorithm, $artifactBytes);

            $envelope = $verifier->verify(
                bundle: $bundle,
                trustedRoot: $trustedRoot,
                identityPolicy: $identityPolicy,
                subjectPolicy: new SubjectPolicy($digestAlgorithm, $digest),
            );

            /** @var array{predicateType?: string, subject?: list<array{name?: string}>} $statement */
            $statement = (array) json_decode($envelope->payload, true);

            fwrite($this->stdout, "VERIFIED\n");
            fwrite($this->stdout, sprintf("subject:   %s (%s:%s)\n", $statement['subject'][0]['name'] ?? basename($artifactPath), $digestAlgorithm, $digest));
            fwrite($this->stdout, sprintf("predicate: %s\n", $statement['predicateType'] ?? 'unknown'));

            return;
        }

        $verifier->verifyArtifact(
            bundle: $bundle,
            artifact: $artifactBytes,
            trustedRoot: $trustedRoot,
            identityPolicy: $identityPolicy,
        );

        fwrite($this->stdout, "VERIFIED\n");
        fwrite($this->stdout, sprintf("artifact:  %s (sha256:%s)\n", basename($artifactPath), hash('sha256', $artifactBytes)));
    }

    private function identityPolicy(Options $options): IdentityPolicy
    {
        if ($options->repository !== null) {
            return IdentityPolicy::githubActions(
                repository: $options->repository,
                workflow: $options->workflow,
                ref: $options->ref,
            );
        }

        return new IdentityPolicy((string) $options->san, (string) $options->issuer);
    }

    /**
     * A bundle file is either a single JSON document or JSON Lines with one
     * bundle per line (the format `gh attestation download` writes).
     *
     * @return list<Bundle>
     */
    private function readBundles(string $path): array
    {
        $raw = trim($this->readFile($path));

        if ($raw === '') {
            throw new RuntimeException(sprintf('Bundle file "%s" is empty.', $path));
        }

        if (json_decode($raw) !== null) {
            return [Bundle::fromJson($raw)];
        }

        $bundles = [];
        $lines = preg_split('/\R/', $raw) ?: [];

        foreach ($lines as $number => $line) {
            $line = trim($line);

            if ($line === '') {
                continue;
            }

            if (json_decode($line) === null) {
                throw new RuntimeException(sprintf('Bundle file "%s" line %d is not valid JSON.', $path, $number + 1));
            }

            $bundles[] = Bundle::fromJson($line);
        }

        if ($bundles === []) {
            throw new RuntimeException(sprintf('Bundle file "%s" contains no bundles.', $path));
        }

        return $bundles;
    }

    private function readFile(string $path): string
    {
        if (! is_file($path)) {
            throw new RuntimeException(sprintf('File "%s" does not exist.', $path));
        }

        $contents = file_get_contents($path);

        if ($contents === false) {
            throw new RuntimeException(sprintf('File "%s" is not readable.', $path));
        }

        return $contents;
    }
}

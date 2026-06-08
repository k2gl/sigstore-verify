<?php

declare(strict_types=1);

namespace K2gl\Sigstore;

use K2gl\Sigstore\Exception\VerificationFailedException;
use InvalidArgumentException;

/**
 * The identity a caller requires of the signer: the expected subject
 * alternative name (the Fulcio signing identity, e.g. a workflow URI or an
 * email) and the expected OIDC issuer.
 *
 * Pinning identity is mandatory: a certificate that chains to Fulcio only
 * proves "some Sigstore identity signed this", never "the identity you trust
 * signed this". The verifier always enforces a policy.
 *
 * The SAN is matched exactly by default. Use {@see sanRegex()} for a pattern
 * (a CI signing identity embeds the ref or workflow, which varies between
 * runs), or the {@see githubActions()} / {@see gitlabCi()} factories, which
 * build the issuer and the SAN pattern for those providers.
 */
final class IdentityPolicy
{
    private const GITHUB_ISSUER = 'https://token.actions.githubusercontent.com';

    public function __construct(
        public readonly string $san,
        public readonly string $issuer,
        private readonly bool $sanIsRegex = false,
    ) {
        if ($san === '' || $issuer === '') {
            throw new InvalidArgumentException('Identity policy requires a non-empty SAN and issuer.');
        }

        if ($sanIsRegex && @preg_match($san, '') === false) {
            throw new InvalidArgumentException(
                sprintf('Identity policy SAN pattern is not a valid regular expression: "%s".', $san),
            );
        }
    }

    /**
     * Match the signer's SAN against a PCRE pattern (with delimiters) instead
     * of by exact string — useful when the ref or workflow in the SAN varies.
     */
    public static function sanRegex(string $pattern, string $issuer): self
    {
        return new self(
            san: $pattern,
            issuer: $issuer,
            sanIsRegex: true,
        );
    }

    /**
     * A policy for a GitHub Actions keyless identity: the issuer is GitHub's
     * Actions OIDC provider and the SAN is the workflow identity
     * "https://github.com/{repository}/.github/workflows/{workflow}@{ref}".
     * Leave $workflow or $ref null to match any workflow / any ref in the repo.
     */
    public static function githubActions(string $repository, ?string $workflow = null, ?string $ref = null): self
    {
        if ($repository === '') {
            throw new InvalidArgumentException('GitHub Actions identity requires a repository ("owner/repo").');
        }

        $prefix = 'https://github.com/' . $repository . '/.github/workflows/';

        if ($workflow !== null && $ref !== null) {
            return new self($prefix . $workflow . '@' . $ref, self::GITHUB_ISSUER);
        }

        $pattern = '#^' . preg_quote($prefix, '#')
            . ($workflow !== null ? preg_quote($workflow, '#') : '[^/@]+')
            . '@' . ($ref !== null ? preg_quote($ref, '#') : '.+')
            . '$#';

        return new self(
            san: $pattern,
            issuer: self::GITHUB_ISSUER,
            sanIsRegex: true,
        );
    }

    /**
     * A policy for a GitLab CI keyless identity: the issuer is the GitLab
     * instance ("https://{host}") and the SAN is the CI config identity
     * "https://{host}/{projectPath}//{ciConfigPath}@{ref}". Leave $ciConfigPath
     * or $ref null to match any config / any ref in the project.
     */
    public static function gitlabCi(
        string $projectPath,
        ?string $ciConfigPath = null,
        ?string $ref = null,
        string $host = 'gitlab.com',
    ): self {
        if ($projectPath === '' || $host === '') {
            throw new InvalidArgumentException('GitLab CI identity requires a project path and a host.');
        }

        $issuer = 'https://' . $host;
        $prefix = $issuer . '/' . $projectPath . '//';

        if ($ciConfigPath !== null && $ref !== null) {
            return new self($prefix . $ciConfigPath . '@' . $ref, $issuer);
        }

        $pattern = '#^' . preg_quote($prefix, '#')
            . ($ciConfigPath !== null ? preg_quote($ciConfigPath, '#') : '[^@]+')
            . '@' . ($ref !== null ? preg_quote($ref, '#') : '.+')
            . '$#';

        return new self(
            san: $pattern,
            issuer: $issuer,
            sanIsRegex: true,
        );
    }

    /**
     * @param  list<string> $subjectAlternativeNames
     * @throws VerificationFailedException
     */
    public function verify(array $subjectAlternativeNames, ?string $issuer): void
    {
        if ($issuer !== $this->issuer) {
            throw new VerificationFailedException(sprintf(
                'Certificate OIDC issuer "%s" does not match the expected "%s".',
                $issuer ?? '(none)',
                $this->issuer,
            ));
        }

        if (! $this->sanMatches($subjectAlternativeNames)) {
            throw new VerificationFailedException(sprintf(
                $this->sanIsRegex
                    ? 'Certificate identity does not match the expected SAN pattern "%s".'
                    : 'Certificate identity does not include the expected SAN "%s".',
                $this->san,
            ));
        }
    }

    /** @param list<string> $subjectAlternativeNames */
    private function sanMatches(array $subjectAlternativeNames): bool
    {
        if (! $this->sanIsRegex) {
            return in_array($this->san, $subjectAlternativeNames, true);
        }

        foreach ($subjectAlternativeNames as $name) {
            if (preg_match($this->san, $name) === 1) {
                return true;
            }
        }

        return false;
    }
}

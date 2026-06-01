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
 */
final class IdentityPolicy
{
    public function __construct(
        public readonly string $san,
        public readonly string $issuer,
    ) {
        if ($san === '' || $issuer === '') {
            throw new InvalidArgumentException('Identity policy requires a non-empty SAN and issuer.');
        }
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

        if (! in_array($this->san, $subjectAlternativeNames, true)) {
            throw new VerificationFailedException(sprintf(
                'Certificate identity does not include the expected SAN "%s".',
                $this->san,
            ));
        }
    }
}

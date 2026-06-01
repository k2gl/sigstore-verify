<?php

declare(strict_types=1);

namespace K2gl\Sigstore\Internal;

use K2gl\Sigstore\Exception\VerificationFailedException;
use K2gl\Sigstore\TrustedRoot;
use DateTimeImmutable;

/**
 * Verifies that a leaf certificate chains to a trusted CA at the signing time.
 * For each trusted CA it builds the explicit path leaf -> intermediate(s) ->
 * root, checks every signature link and every validity window against the
 * signing time, and requires the anchor to be self-signed. The bundle's own
 * intermediate certificates are deliberately ignored: only certificates from
 * the supplied trusted root are trusted.
 *
 * The same chain check serves both Fulcio certificate authorities and timestamp
 * authorities, whose trusted root entries share the same shape.
 *
 * @internal
 */
final class CertificateChainVerifier
{
    /**
     * Returns the matched chain (leaf first, then the trusted authority's
     * certificates), so the caller can read the leaf's issuer.
     *
     * @return list<Certificate>
     * @throws VerificationFailedException
     */
    public function verify(
        Certificate $leaf,
        TrustedRoot $trustedRoot,
        DateTimeImmutable $signingTime,
    ): array {
        foreach ($trustedRoot->certificateAuthorities as $authority) {
            $chain = array_merge([$leaf], $authority->certificates());

            if ($authority->isValidAt($signingTime) && $this->isValidChain($chain, $signingTime)) {
                return $chain;
            }
        }
        throw new VerificationFailedException(
            'Certificate does not chain to any trusted Fulcio CA valid at the signing time.'
        );
    }

    /**
     * True if the ordered chain (leaf-most first, self-signed anchor last) holds
     * at the given time: each certificate is valid then and signed by the next,
     * and the anchor is self-signed.
     *
     * @param list<Certificate> $chain
     */
    public function isValidChain(array $chain, DateTimeImmutable $signingTime): bool
    {
        $last = count($chain) - 1;

        if ($last < 1) {
            return false;
        }

        for ($i = 0; $i < $last; $i++) {
            if (! $chain[$i]->isValidAt($signingTime)) {
                return false;
            }

            if (! $chain[$i]->isSignedBy($chain[$i + 1])) {
                return false;
            }
        }

        $anchor = $chain[$last];

        return $anchor->isValidAt($signingTime) && $anchor->isSignedBy($anchor);
    }
}

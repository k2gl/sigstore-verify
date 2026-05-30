<?php

declare(strict_types=1);

namespace K2gl\Sigstore\Internal;

use K2gl\Sigstore\CertificateAuthority;
use K2gl\Sigstore\Exception\VerificationFailedException;
use K2gl\Sigstore\TrustedRoot;

/**
 * Verifies that a leaf certificate chains to a trusted Fulcio CA at the signing
 * time. For each trusted CA it builds the explicit path leaf -> intermediate(s)
 * -> root, checks every signature link and every validity window against the
 * signing time, and requires the anchor to be self-signed. The bundle's own
 * intermediate certificates are deliberately ignored: only certificates from
 * the supplied trusted root are trusted.
 *
 * @internal
 */
final class CertificateChainVerifier
{
    /** @throws VerificationFailedException */
    public function verify(Certificate $leaf, TrustedRoot $trustedRoot, \DateTimeImmutable $signingTime): void
    {
        foreach ($trustedRoot->certificateAuthorities as $authority) {
            if ($this->chains($leaf, $authority, $signingTime)) {
                return;
            }
        }
        throw new VerificationFailedException(
            'Certificate does not chain to any trusted Fulcio CA valid at the signing time.'
        );
    }

    private function chains(Certificate $leaf, CertificateAuthority $authority, \DateTimeImmutable $signingTime): bool
    {
        if (!$authority->isValidAt($signingTime)) {
            return false;
        }

        $path = array_merge([$leaf], $authority->certificates());
        $last = count($path) - 1;
        if ($last < 1) {
            return false;
        }

        for ($i = 0; $i < $last; $i++) {
            if (!$path[$i]->isValidAt($signingTime)) {
                return false;
            }
            if (!$path[$i]->isSignedBy($path[$i + 1])) {
                return false;
            }
        }

        $anchor = $path[$last];

        return $anchor->isValidAt($signingTime) && $anchor->isSignedBy($anchor);
    }
}

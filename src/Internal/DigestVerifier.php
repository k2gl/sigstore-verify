<?php

declare(strict_types=1);

namespace K2gl\Sigstore\Internal;

/**
 * Verifies a signature against an already-computed message digest, without the
 * original message bytes (a "prehashed" verification).
 *
 * Sigstore's ECDSA and RSA message-signature schemes sign the digest of the
 * artifact, so a bundle can be verified from a bare artifact digest — the form
 * the sigstore-conformance suite exercises and a common need when the artifact
 * is large or unavailable. ext-openssl's {@see OpensslVerifier} always recomputes
 * the digest from the message, so this is the complementary primitive.
 *
 * @internal
 */
interface DigestVerifier
{
    /**
     * Whether $signature is a valid signature over the raw digest bytes
     * $digest under the resolved public key. Never throws: malformed input is
     * a failed verification, returned as false.
     */
    public function verifyDigest(string $digest, string $signature): bool;
}

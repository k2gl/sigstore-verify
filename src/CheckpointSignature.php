<?php

declare(strict_types=1);

namespace K2gl\Sigstore;

/**
 * One signature line of a checkpoint note: the four-byte key hint that names the
 * signing key, and the raw signature bytes (for Rekor, an ASN.1 DER ECDSA
 * signature). The key hint lets a verifier reject a checkpoint signed by a key
 * other than the transparency log that produced the entry.
 */
final class CheckpointSignature
{
    public function __construct(
        public readonly string $keyHint,
        public readonly string $signature,
    ) {}
}

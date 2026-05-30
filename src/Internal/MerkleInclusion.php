<?php

declare(strict_types=1);

namespace K2gl\Sigstore\Internal;

use K2gl\Sigstore\Exception\VerificationFailedException;

/**
 * RFC 6962 Merkle tree inclusion-proof arithmetic. Given a leaf hash, its index
 * and the tree size, it recomputes the tree root from the proof hashes so the
 * caller can compare it against a signed log root.
 *
 * The algorithm mirrors transparency-dev/merkle's RootFromInclusionProof and
 * uses SHA-256 with the RFC 6962 domain-separation prefixes (0x00 for leaves,
 * 0x01 for interior nodes).
 *
 * @internal
 */
final class MerkleInclusion
{
    public static function leafHash(string $entry): string
    {
        return hash('sha256', "\x00" . $entry, true);
    }

    /**
     * @param  list<string> $proof raw sibling hashes, bottom to top
     * @throws VerificationFailedException
     */
    public static function computeRoot(int $leafIndex, int $treeSize, string $leafHash, array $proof): string
    {
        if ($leafIndex < 0 || $treeSize <= 0 || $leafIndex >= $treeSize) {
            throw new VerificationFailedException('Inclusion proof leaf index is out of range for the tree size.');
        }

        $inner = self::bitLength($leafIndex ^ ($treeSize - 1));
        $border = self::onesCount($leafIndex >> $inner);
        if (count($proof) !== $inner + $border) {
            throw new VerificationFailedException('Inclusion proof has an unexpected number of hashes.');
        }

        $seed = $leafHash;
        for ($i = 0; $i < $inner; $i++) {
            $sibling = $proof[$i];
            if ((($leafIndex >> $i) & 1) === 0) {
                $seed = self::hashChildren($seed, $sibling);
            } else {
                $seed = self::hashChildren($sibling, $seed);
            }
        }
        for ($i = $inner, $n = count($proof); $i < $n; $i++) {
            $seed = self::hashChildren($proof[$i], $seed);
        }

        return $seed;
    }

    private static function hashChildren(string $left, string $right): string
    {
        return hash('sha256', "\x01" . $left . $right, true);
    }

    private static function bitLength(int $value): int
    {
        $bits = 0;
        while ($value > 0) {
            $bits++;
            $value >>= 1;
        }
        return $bits;
    }

    private static function onesCount(int $value): int
    {
        $count = 0;
        while ($value > 0) {
            $count += $value & 1;
            $value >>= 1;
        }
        return $count;
    }
}

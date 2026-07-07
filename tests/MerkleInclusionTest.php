<?php

declare(strict_types=1);

namespace K2gl\Sigstore\Tests;

use K2gl\Sigstore\Exception\VerificationFailedException;
use K2gl\Sigstore\Internal\MerkleInclusion;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;

use function K2gl\PHPUnitFluentAssertions\fact;

/**
 * RFC 6962 inclusion-proof arithmetic, checked against a real Rekor proof (the
 * staging bundle ships an 11-hash inclusion proof) and on its boundaries.
 */
#[CoversClass(MerkleInclusion::class)]
#[CoversClass(VerificationFailedException::class)]
final class MerkleInclusionTest extends TestCase
{
    /** @return array{index:int,size:int,leafHash:string,proof:list<string>,root:string} */
    private function realProof(): array
    {
        $raw = file_get_contents(__DIR__ . '/fixtures/bundle_v3.txt.sigstore');
        fact($raw)->isString();
        $bundle = json_decode($raw, true);
        fact($bundle)->isArray();
        $entry = $bundle['verificationMaterial']['tlogEntries'][0];
        $proof = $entry['inclusionProof'];

        $hashes = [];

        foreach ($proof['hashes'] as $hash) {
            $hashes[] = self::b64($hash);
        }

        return [
            'index' => (int) $proof['logIndex'],
            'size' => (int) $proof['treeSize'],
            'leafHash' => MerkleInclusion::leafHash(self::b64($entry['canonicalizedBody'])),
            'proof' => $hashes,
            'root' => self::b64($proof['rootHash']),
        ];
    }

    private static function b64(string $value): string
    {
        $decoded = base64_decode($value, true);
        fact($decoded)->isString();

        return $decoded;
    }

    public function testRecomputesRealRekorRoot(): void
    {
        $p = $this->realProof();
        $root = MerkleInclusion::computeRoot(
            leafIndex: $p['index'],
            treeSize: $p['size'],
            leafHash: $p['leafHash'],
            proof: $p['proof'],
        );
        fact($root === $p['root'])->true();
    }

    public function testSingleLeafTreeRootIsLeafHash(): void
    {
        $leaf = MerkleInclusion::leafHash('only-entry');
        $root = MerkleInclusion::computeRoot(
            leafIndex: 0,
            treeSize: 1,
            leafHash: $leaf,
            proof: [],
        );
        fact($root === $leaf)->true();
    }

    public function testRejectsIndexOutOfRange(): void
    {
        // act + assert
        fact(static fn () => MerkleInclusion::computeRoot(
            leafIndex: 5,
            treeSize: 5,
            leafHash: str_repeat("\x00", 32),
            proof: [],
        ))->throws(VerificationFailedException::class);
    }

    public function testRejectsWrongProofLength(): void
    {
        // arrange
        $p = $this->realProof();

        // act + assert
        fact(static fn () => MerkleInclusion::computeRoot(
            leafIndex: $p['index'],
            treeSize: $p['size'],
            leafHash: $p['leafHash'],
            proof: array_slice($p['proof'], 1),
        ))->throws(VerificationFailedException::class);
    }
}

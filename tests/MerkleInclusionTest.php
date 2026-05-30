<?php

declare(strict_types=1);

namespace K2gl\Sigstore\Tests;

use function K2gl\PHPUnitFluentAssertions\fact;

use K2gl\Sigstore\Exception\VerificationFailedException;
use K2gl\Sigstore\Internal\MerkleInclusion;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;

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
        self::assertIsString($raw);
        $bundle = json_decode($raw, true);
        self::assertIsArray($bundle);
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
        self::assertIsString($decoded);
        return $decoded;
    }

    public function testRecomputesRealRekorRoot(): void
    {
        $p = $this->realProof();
        $root = MerkleInclusion::computeRoot($p['index'], $p['size'], $p['leafHash'], $p['proof']);
        fact($root === $p['root'])->true();
    }

    public function testSingleLeafTreeRootIsLeafHash(): void
    {
        $leaf = MerkleInclusion::leafHash('only-entry');
        fact(MerkleInclusion::computeRoot(0, 1, $leaf, []) === $leaf)->true();
    }

    public function testRejectsIndexOutOfRange(): void
    {
        $this->expectException(VerificationFailedException::class);
        MerkleInclusion::computeRoot(5, 5, str_repeat("\x00", 32), []);
    }

    public function testRejectsWrongProofLength(): void
    {
        $p = $this->realProof();
        $this->expectException(VerificationFailedException::class);
        MerkleInclusion::computeRoot($p['index'], $p['size'], $p['leafHash'], array_slice($p['proof'], 1));
    }
}

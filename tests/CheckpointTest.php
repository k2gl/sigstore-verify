<?php

declare(strict_types=1);

namespace K2gl\Sigstore\Tests;

use function K2gl\PHPUnitFluentAssertions\fact;

use K2gl\Sigstore\Checkpoint;
use K2gl\Sigstore\Exception\InvalidBundleException;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;

/**
 * Signed-note (checkpoint) parsing, checked against a real Rekor checkpoint and
 * on malformed input.
 */
#[CoversClass(Checkpoint::class)]
#[CoversClass(InvalidBundleException::class)]
final class CheckpointTest extends TestCase
{
    private function realCheckpoint(): Checkpoint
    {
        $raw = file_get_contents(__DIR__ . '/fixtures/bundle_v3.txt.sigstore');
        fact($raw)->isString();
        $bundle = json_decode($raw, true);
        fact($bundle)->isArray();
        $envelope = $bundle['verificationMaterial']['tlogEntries'][0]['inclusionProof']['checkpoint']['envelope'];
        fact($envelope)->isString();

        return new Checkpoint($envelope);
    }

    public function testParsesRealCheckpoint(): void
    {
        $checkpoint = $this->realCheckpoint();

        fact($checkpoint->treeSize())->is(25901138);
        fact(base64_encode($checkpoint->rootHash()))->is('iGAoHccJIyFemFxmEftti2YC8hvPqixBi5y1EyvfF4c=');
        fact(count($checkpoint->signatures()))->is(1);
        // The signed body is the note header up to (and including) the newline
        // before the blank separator line.
        fact(str_ends_with($checkpoint->signedBody(), "\n"))->true();
        fact(str_contains($checkpoint->signedBody(), "\n\n"))->false();
    }

    public function testRejectsNoteWithoutSeparator(): void
    {
        $this->expectException(InvalidBundleException::class);
        new Checkpoint("origin\n1\nrootHashLine\n");
    }

    public function testRejectsNoteWithShortBody(): void
    {
        $this->expectException(InvalidBundleException::class);
        new Checkpoint("origin\n1\n\n— origin AAAAAA==\n");
    }

    public function testRejectsNoteWithNonIntegerTreeSize(): void
    {
        $this->expectException(InvalidBundleException::class);
        new Checkpoint("origin\nnotanumber\n" . base64_encode('root') . "\n\n— origin " . base64_encode('xxxxsig') . "\n");
    }

    public function testRejectsNoteWithoutSignature(): void
    {
        $this->expectException(InvalidBundleException::class);
        new Checkpoint("origin\n1\n" . base64_encode('root') . "\n\n\n");
    }
}

<?php

declare(strict_types=1);

namespace K2gl\Sigstore\Tests;

use K2gl\Sigstore\Checkpoint;
use K2gl\Sigstore\Exception\InvalidBundleException;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;

use function K2gl\PHPUnitFluentAssertions\fact;

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
        fact($checkpoint->signatures())->count(1);
        // The signed body is the note header up to (and including) the newline
        // before the blank separator line.
        fact($checkpoint->signedBody())->endsWith("\n");
        fact($checkpoint->signedBody())->notContainsString("\n\n");
    }

    public function testRejectsNoteWithoutSeparator(): void
    {
        // act + assert
        fact(static fn () => new Checkpoint("origin\n1\nrootHashLine\n"))->throws(InvalidBundleException::class);
    }

    public function testRejectsNoteWithShortBody(): void
    {
        // act + assert
        fact(static fn () => new Checkpoint("origin\n1\n\n— origin AAAAAA==\n"))->throws(InvalidBundleException::class);
    }

    public function testRejectsNoteWithNonIntegerTreeSize(): void
    {
        // act + assert
        fact(static fn () => new Checkpoint(
            "origin\nnotanumber\n" . base64_encode('root') . "\n\n— origin " . base64_encode('xxxxsig') . "\n",
        ))->throws(InvalidBundleException::class);
    }

    public function testRejectsNoteWithoutSignature(): void
    {
        // act + assert
        fact(static fn () => new Checkpoint("origin\n1\n" . base64_encode('root') . "\n\n\n"))->throws(InvalidBundleException::class);
    }

    public function testRejectsASignatureLineWithoutTheEmDash(): void
    {
        // arrange
        $envelope = "origin\n1\n" . base64_encode('root') . "\n\norigin " . base64_encode('hintsig') . "\n";

        // act + assert
        fact(static fn () => new Checkpoint($envelope))->throws(InvalidBundleException::class);
    }

    public function testRejectsAMalformedSignatureLineEvenBesideAGoodOne(): void
    {
        // arrange: a note whose first signature line is well-formed and whose
        // second is not. Skipping the bad line would mean accepting a note we
        // could not fully read.
        $envelope = "origin\n1\n" . base64_encode('root') . "\n"
            . "\n\u{2014} origin " . base64_encode('hintsig') . "\n"
            . "\u{2014} origin not-base64!\n";

        // act + assert
        fact(static fn () => new Checkpoint($envelope))->throws(InvalidBundleException::class);
    }
}

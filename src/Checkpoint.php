<?php

declare(strict_types=1);

namespace K2gl\Sigstore;

use K2gl\SignedNote\Checkpoint as SignedCheckpoint;
use K2gl\SignedNote\Exception\SignedNoteException;
use K2gl\SignedNote\NoteSignature;
use K2gl\Sigstore\Exception\InvalidBundleException;

/**
 * A Rekor checkpoint: a signed note (the format used by transparency logs and
 * Go's sumdb) that commits the log to a tree size and root hash. The note body
 * is three or more newline-terminated lines — origin, tree size, base64 root
 * hash — followed by a blank line and one or more signature lines.
 *
 * Reading it is {@see \K2gl\SignedNote\Checkpoint}'s job; this class presents
 * the result the way the verifier consumes it and turns a malformed note into
 * a bundle error.
 *
 * @see https://github.com/transparency-dev/formats/blob/main/log/README.md
 */
final class Checkpoint
{
    private readonly SignedCheckpoint $checkpoint;

    public function __construct(public readonly string $envelope)
    {
        try {
            $this->checkpoint = SignedCheckpoint::parse($envelope);
        } catch (SignedNoteException $e) {
            throw new InvalidBundleException('Checkpoint note is malformed: ' . $e->getMessage(), previous: $e);
        }
    }

    /** The exact bytes the log signed. */
    public function signedBody(): string
    {
        return $this->checkpoint->note->signedText();
    }

    public function treeSize(): int
    {
        return $this->checkpoint->treeSize;
    }

    public function rootHash(): string
    {
        return $this->checkpoint->rootHash;
    }

    /**
     * The checkpoint's signature lines, each with its 4-byte key hint and raw
     * signature bytes. For Rekor the signatures are ASN.1 DER ECDSA signatures.
     *
     * @return list<CheckpointSignature>
     */
    public function signatures(): array
    {
        return array_map(
            static fn (NoteSignature $signature): CheckpointSignature => new CheckpointSignature(
                keyHint: $signature->keyHash,
                signature: $signature->signature,
            ),
            $this->checkpoint->note->signatures(),
        );
    }
}

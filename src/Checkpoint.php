<?php

declare(strict_types=1);

namespace K2gl\Sigstore;

use K2gl\Sigstore\Exception\InvalidBundleException;
use K2gl\SignedNote\Exception\SignedNoteException;
use K2gl\SignedNote\Note;
use K2gl\SignedNote\NoteSignature;

/**
 * A Rekor checkpoint: a signed note (the format used by transparency logs and
 * Go's sumdb) that commits the log to a tree size and root hash. The note body
 * is three or more newline-terminated lines — origin, tree size, base64 root
 * hash — followed by a blank line and one or more signature lines.
 *
 * The note itself is read by {@see \K2gl\SignedNote\Note}; what stays here is
 * what makes a note a *checkpoint* — the meaning of those first three lines.
 *
 * @see https://github.com/transparency-dev/formats/blob/main/log/README.md
 */
final class Checkpoint
{
    private string $signedBody;
    private int $treeSize;
    private string $rootHash;

    /** @var list<CheckpointSignature> */
    private array $signatures;

    public function __construct(public readonly string $envelope)
    {
        try {
            $note = Note::parse($envelope);
        } catch (SignedNoteException $e) {
            throw new InvalidBundleException('Checkpoint note is malformed: ' . $e->getMessage(), previous: $e);
        }
        $this->signedBody = $note->signedText();

        // signedText() is the body with the separator's newline appended; drop it
        // again to get the lines as the log wrote them.
        $lines = explode("\n", substr($this->signedBody, 0, -1));

        if (count($lines) < 3) {
            throw new InvalidBundleException('Checkpoint note body must have at least three lines.');
        }

        if (preg_match('/^\d+$/', $lines[1]) !== 1) {
            throw new InvalidBundleException('Checkpoint note tree size is not an integer.');
        }
        $this->treeSize = (int) $lines[1];

        $rootHash = base64_decode($lines[2], true);

        if ($rootHash === false) {
            throw new InvalidBundleException('Checkpoint note root hash is not valid base64.');
        }
        $this->rootHash = $rootHash;

        $this->signatures = array_map(
            static fn (NoteSignature $signature): CheckpointSignature => new CheckpointSignature(
                keyHint: $signature->keyHash,
                signature: $signature->signature,
            ),
            $note->signatures(),
        );
    }

    /** The exact bytes the log signed. */
    public function signedBody(): string
    {
        return $this->signedBody;
    }

    public function treeSize(): int
    {
        return $this->treeSize;
    }

    public function rootHash(): string
    {
        return $this->rootHash;
    }

    /**
     * The checkpoint's signature lines, each with its 4-byte key hint and raw
     * signature bytes. For Rekor the signatures are ASN.1 DER ECDSA signatures.
     *
     * @return list<CheckpointSignature>
     */
    public function signatures(): array
    {
        return $this->signatures;
    }
}

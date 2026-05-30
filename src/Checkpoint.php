<?php

declare(strict_types=1);

namespace K2gl\Sigstore;

use K2gl\Sigstore\Exception\InvalidBundleException;

/**
 * A Rekor checkpoint: a signed note (the format used by transparency logs and
 * Go's sumdb) that commits the log to a tree size and root hash. The note body
 * is three or more newline-terminated lines — origin, tree size, base64 root
 * hash — followed by a blank line and one or more signature lines.
 *
 * The signed bytes are the note body up to (and including) the newline before
 * the blank separator. Each signature line is "<U+2014> <name> <base64>", where
 * the base64 decodes to a 4-byte key hint followed by the raw signature.
 *
 * @see https://github.com/transparency-dev/formats/blob/main/log/README.md
 */
final class Checkpoint
{
    private string $signedBody;
    private int $treeSize;
    private string $rootHash;

    /** @var list<string> raw signature bytes (key hint stripped) */
    private array $signatures;

    public function __construct(public readonly string $envelope)
    {
        $separator = strpos($envelope, "\n\n");
        if ($separator === false) {
            throw new InvalidBundleException('Checkpoint note has no blank line separating body and signatures.');
        }

        $body = substr($envelope, 0, $separator);
        $this->signedBody = $body . "\n";

        $lines = explode("\n", $body);
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

        $this->signatures = self::parseSignatures(substr($envelope, $separator + 2));
        if ($this->signatures === []) {
            throw new InvalidBundleException('Checkpoint note has no parseable signature.');
        }
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
     * Raw signature bytes (the 4-byte key hint removed), one per signature line.
     * For Rekor these are ASN.1 DER ECDSA signatures.
     *
     * @return list<string>
     */
    public function signatures(): array
    {
        return $this->signatures;
    }

    /** @return list<string> */
    private static function parseSignatures(string $block): array
    {
        $signatures = [];
        foreach (explode("\n", $block) as $line) {
            if ($line === '') {
                continue;
            }
            $space = strrpos($line, ' ');
            if ($space === false) {
                continue;
            }
            $decoded = base64_decode(substr($line, $space + 1), true);
            if ($decoded === false || strlen($decoded) <= 4) {
                continue;
            }
            $signatures[] = substr($decoded, 4);
        }
        return $signatures;
    }
}

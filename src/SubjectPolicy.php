<?php

declare(strict_types=1);

namespace K2gl\Sigstore;

use K2gl\InToto\Statement;
use K2gl\Sigstore\Exception\VerificationFailedException;
use InvalidArgumentException;

/**
 * The artifact a caller requires the attestation to be about: a digest that
 * must appear in the verified Statement's subject.
 *
 * Binding the subject closes the gap between "a trusted identity signed some
 * attestation" and "the attestation is about the artifact in front of me" —
 * without it, a genuine attestation for a different artifact, signed by the
 * same trusted identity, would pass.
 */
final class SubjectPolicy
{
    private const ALGORITHMS = ['sha256', 'sha384', 'sha512'];

    public function __construct(
        public readonly string $algorithm,
        public readonly string $hexDigest,
    ) {
        if (! in_array($this->algorithm, self::ALGORITHMS, true)) {
            throw new InvalidArgumentException(
                sprintf('Unsupported subject digest algorithm "%s".', $this->algorithm),
            );
        }

        if ($hexDigest === '' || ! ctype_xdigit($hexDigest)) {
            throw new InvalidArgumentException('Subject digest must be a non-empty hexadecimal string.');
        }
    }

    /**
     * @throws VerificationFailedException when no subject in the statement
     *                                     records the expected digest
     */
    public function verify(Statement $statement): void
    {
        $expected = strtolower($this->hexDigest);

        foreach ($statement->subject as $descriptor) {
            $value = $descriptor->digest[$this->algorithm] ?? null;

            if (is_string($value) && hash_equals($expected, strtolower($value))) {
                return;
            }
        }

        throw new VerificationFailedException(sprintf(
            'Attestation subject does not include the expected %s digest "%s".',
            $this->algorithm,
            $this->hexDigest,
        ));
    }
}

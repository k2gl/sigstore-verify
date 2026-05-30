<?php

declare(strict_types=1);

namespace K2gl\Sigstore\Internal;

use K2gl\Sigstore\Exception\UnsupportedBundleException;
use K2gl\Sigstore\Exception\VerificationFailedException;
use K2gl\Sigstore\InclusionProof;
use K2gl\Sigstore\TlogEntry;
use K2gl\Sigstore\TransparencyLogInstance;
use K2gl\Sigstore\TrustedRoot;

/**
 * Verifies a Rekor transparency-log entry, offline, against the trusted root:
 *
 *  - the signed entry timestamp (inclusion promise), if present, is a valid
 *    Rekor signature over the canonical entry;
 *  - the Merkle inclusion proof, if present, recomputes the signed checkpoint
 *    root, and the checkpoint note signature is valid;
 *  - at least one of the two forms of proof is present and valid; and
 *  - the entry body is bound to the bundle by matching the hash it records
 *    (the DSSE payload hash, or the signed artifact's digest) against the
 *    expected hex digest the caller computed from the bundle content.
 *
 * Every failure throws; an entry that cannot be bound or proven is never
 * accepted.
 *
 * @internal
 */
final class RekorVerifier
{
    /** @throws VerificationFailedException|UnsupportedBundleException */
    public function verify(
        TlogEntry $entry,
        TrustedRoot $trustedRoot,
        string $expectedHashHex,
    ): void {
        $log = $trustedRoot->findTransparencyLog($entry->logId);

        if ($log === null) {
            throw new VerificationFailedException('No trusted transparency log matches the entry log id.');
        }

        $proven = false;

        if ($entry->signedEntryTimestamp !== null) {
            $this->verifySignedEntryTimestamp($entry, $log);
            $proven = true;
        }

        if ($entry->inclusionProof !== null) {
            $this->verifyInclusionProof($entry, $entry->inclusionProof, $log);
            $proven = true;
        }

        if (!$proven) {
            throw new VerificationFailedException(
                'Transparency log entry has neither an inclusion promise nor an inclusion proof.'
            );
        }

        $this->verifyPayloadBinding($entry, $expectedHashHex);
    }

    private function verifySignedEntryTimestamp(TlogEntry $entry, TransparencyLogInstance $log): void
    {
        // Rekor signs the canonical JSON of the log entry. Keys must be in
        // lexical order: body, integratedTime, logID, logIndex.
        $canonical = json_encode([
            'body' => base64_encode($entry->canonicalizedBody),
            'integratedTime' => $entry->integratedTime,
            'logID' => bin2hex($entry->logId),
            'logIndex' => $entry->logIndex,
        ], JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR);

        $valid = $entry->signedEntryTimestamp !== null && Ecdsa::verifyDer(
            message: $canonical,
            derSignature: $entry->signedEntryTimestamp,
            publicKeyPem: $log->publicKeyPem,
        );

        if (!$valid) {
            throw new VerificationFailedException('Rekor signed entry timestamp is invalid.');
        }
    }

    private function verifyInclusionProof(
        TlogEntry $entry,
        InclusionProof $proof,
        TransparencyLogInstance $log,
    ): void {
        $computedRoot = MerkleInclusion::computeRoot(
            leafIndex: $proof->logIndex,
            treeSize: $proof->treeSize,
            leafHash: MerkleInclusion::leafHash($entry->canonicalizedBody),
            proof: $proof->hashes,
        );

        if (!hash_equals($proof->rootHash, $computedRoot)) {
            throw new VerificationFailedException('Merkle inclusion proof does not reproduce the log root.');
        }

        $checkpoint = $proof->checkpoint;

        if (!hash_equals($proof->rootHash, $checkpoint->rootHash()) || $checkpoint->treeSize() !== $proof->treeSize) {
            throw new VerificationFailedException('Checkpoint does not match the inclusion proof.');
        }

        foreach ($checkpoint->signatures() as $signature) {
            $valid = Ecdsa::verifyDer(
                message: $checkpoint->signedBody(),
                derSignature: $signature,
                publicKeyPem: $log->publicKeyPem,
            );

            if ($valid) {
                return;
            }
        }
        throw new VerificationFailedException('Checkpoint note signature is invalid.');
    }

    /**
     * Bind the log entry to this bundle: the hash recorded in the Rekor entry
     * body must equal the expected hex digest the caller derived from the
     * bundle content (the DSSE payload, or the signed artifact).
     */
    private function verifyPayloadBinding(TlogEntry $entry, string $expectedHashHex): void
    {
        $recorded = $this->bodyHash($entry);

        if (!hash_equals(strtolower($expectedHashHex), strtolower($recorded))) {
            throw new VerificationFailedException(
                'Transparency log entry hash does not match the bundle content.'
            );
        }
    }

    private function bodyHash(TlogEntry $entry): string
    {
        try {
            /** @var mixed $body */
            $body = json_decode($entry->canonicalizedBody, true, 512, JSON_THROW_ON_ERROR);
        } catch (\JsonException $e) {
            throw new VerificationFailedException('Rekor entry body is not valid JSON.', previous: $e);
        }

        if (!is_array($body)) {
            throw new VerificationFailedException('Rekor entry body is not a JSON object.');
        }

        $hash = match ($entry->kind) {
            'intoto' => self::dig($body, 'spec', 'content', 'payloadHash', 'value'),
            'dsse' => self::dig($body, 'spec', 'payloadHash', 'value'),
            'hashedrekord' => self::dig($body, 'spec', 'data', 'hash', 'value'),
            default => throw new UnsupportedBundleException(
                sprintf('Unsupported Rekor entry kind "%s"; cannot bind it to the bundle.', $entry->kind),
            ),
        };

        if (!is_string($hash) || $hash === '') {
            throw new VerificationFailedException('Rekor entry body has no hash to bind.');
        }

        return $hash;
    }

    /** Walk a decoded JSON tree by successive object keys, returning null on any miss. */
    private static function dig(mixed $value, string ...$keys): mixed
    {
        foreach ($keys as $key) {
            if (!is_array($value) || !array_key_exists($key, $value)) {
                return null;
            }
            $value = $value[$key];
        }

        return $value;
    }
}

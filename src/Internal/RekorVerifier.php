<?php

declare(strict_types=1);

namespace K2gl\Sigstore\Internal;

use K2gl\Sigstore\Exception\UnsupportedBundleException;
use K2gl\Sigstore\Exception\VerificationFailedException;
use K2gl\Sigstore\InclusionProof;
use K2gl\Sigstore\TlogEntry;
use K2gl\Sigstore\TransparencyLogInstance;
use K2gl\Sigstore\TrustedRoot;
use JsonException;

/**
 * Verifies a Rekor transparency-log entry, offline, against the trusted root:
 *
 *  - a Merkle inclusion proof is present (an inclusion promise alone is not
 *    enough), recomputes the signed checkpoint root, and the checkpoint note
 *    signature is valid;
 *  - the signed entry timestamp (inclusion promise), if present, is a valid
 *    Rekor signature over the canonical entry; and
 *  - the entry body is bound to the bundle: the hash it records (the DSSE
 *    payload hash, or the signed artifact's digest) matches the expected digest
 *    the caller computed from the bundle content, and the signature (and, for a
 *    keyless bundle, the certificate) the entry was logged with are the ones the
 *    bundle carries.
 *
 * Every failure throws; an entry that cannot be bound or proven is never
 * accepted.
 *
 * @internal
 */
final class RekorVerifier
{
    /**
     * @param  string  $expectedSignature      the signing signature the bundle carries (DSSE or message signature), raw bytes
     * @param  ?string $signingCertificateDer  the bundle's leaf certificate (DER), or null for a public-key bundle
     * @param  bool    $requireInclusionProof  whether a Merkle inclusion proof is mandatory (true for bundle media type v0.2+)
     * @throws VerificationFailedException|UnsupportedBundleException
     */
    public function verify(
        TlogEntry $entry,
        TrustedRoot $trustedRoot,
        string $expectedHashHex,
        string $expectedSignature,
        ?string $signingCertificateDer,
        bool $requireInclusionProof,
    ): void {
        $log = $trustedRoot->findTransparencyLog($entry->logId);

        if ($log === null) {
            throw new VerificationFailedException('No trusted transparency log matches the entry log id.');
        }

        if ($entry->signedEntryTimestamp !== null) {
            $this->verifySignedEntryTimestamp($entry, $log);
        }

        if ($entry->inclusionProof !== null) {
            $this->verifyInclusionProof($entry, $entry->inclusionProof, $log);
        } elseif ($requireInclusionProof) {
            throw new VerificationFailedException('Transparency log entry has no Merkle inclusion proof.');
        } elseif ($entry->signedEntryTimestamp === null) {
            throw new VerificationFailedException(
                'Transparency log entry has neither an inclusion promise nor an inclusion proof.'
            );
        }

        $this->verifyPayloadBinding($entry, $expectedHashHex);
        $this->verifyBodyBinding($entry, $expectedSignature, $signingCertificateDer);
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

        if (! $valid) {
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

        if (! hash_equals($proof->rootHash, $computedRoot)) {
            throw new VerificationFailedException('Merkle inclusion proof does not reproduce the log root.');
        }

        $checkpoint = $proof->checkpoint;

        if (! hash_equals($proof->rootHash, $checkpoint->rootHash()) || $checkpoint->treeSize() !== $proof->treeSize) {
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

        if (! hash_equals(strtolower($expectedHashHex), strtolower($recorded))) {
            throw new VerificationFailedException(
                'Transparency log entry hash does not match the bundle content.'
            );
        }
    }

    /**
     * Bind the log entry to the bundle's signing material: the entry was logged
     * with the same signature the bundle carries, and — for a keyless bundle —
     * the same certificate. This rejects a bundle whose content is genuine but
     * whose transparency-log entry was made with a different (also valid)
     * signature or a different certificate.
     */
    private function verifyBodyBinding(
        TlogEntry $entry,
        string $expectedSignature,
        ?string $signingCertificateDer,
    ): void {
        [$bodySignature, $bodyCertificateDer] = $this->bodySigningMaterial($entry);

        if (! hash_equals($expectedSignature, $bodySignature)) {
            throw new VerificationFailedException(
                'Transparency log entry signature does not match the bundle signature.'
            );
        }

        if ($signingCertificateDer !== null
            && $bodyCertificateDer !== null
            && ! hash_equals($signingCertificateDer, $bodyCertificateDer)
        ) {
            throw new VerificationFailedException(
                'Transparency log entry certificate does not match the bundle certificate.'
            );
        }
    }

    /**
     * The signature (raw bytes) and certificate (DER, or null) the Rekor entry
     * body records, located by entry kind. The in-toto v0.0.2 type wraps the DSSE
     * envelope, whose signature value is itself base64, so its signature is stored
     * base64-encoded twice; it carries no separate certificate to bind.
     *
     * @return array{0: string, 1: ?string}
     */
    private function bodySigningMaterial(TlogEntry $entry): array
    {
        $body = $this->decodeBody($entry);

        [$signature, $certificateDer] = match ($entry->kind) {
            'hashedrekord' => [
                self::base64(self::dig($body, 'spec', 'signature', 'content')),
                self::certificate(self::dig($body, 'spec', 'signature', 'publicKey', 'content')),
            ],
            'dsse' => [
                self::base64(self::dig($body, 'spec', 'signatures', '0', 'signature')),
                self::certificate(self::dig($body, 'spec', 'signatures', '0', 'verifier')),
            ],
            'intoto' => [
                self::base64(self::base64(self::dig($body, 'spec', 'content', 'envelope', 'signatures', '0', 'sig'))),
                null,
            ],
            default => throw new UnsupportedBundleException(
                sprintf('Unsupported Rekor entry kind "%s"; cannot bind it to the bundle.', $entry->kind),
            ),
        };

        if ($signature === null) {
            throw new VerificationFailedException('Rekor entry body has no signature to bind.');
        }

        return [$signature, $certificateDer];
    }

    /** Base64-decode a value the entry body stores as a string, or null when absent or invalid. */
    private static function base64(mixed $value): ?string
    {
        if (! is_string($value) || ($decoded = base64_decode($value, true)) === false) {
            return null;
        }

        return $decoded;
    }

    /** Decode a PEM certificate the entry body stores as base64, to DER, or null when absent. */
    private static function certificate(mixed $value): ?string
    {
        $pem = self::base64($value);

        return $pem === null ? null : Pem::toDer($pem);
    }

    /** @return array<string, mixed> */
    private function decodeBody(TlogEntry $entry): array
    {
        try {
            /** @var mixed $body */
            $body = json_decode($entry->canonicalizedBody, true, 512, JSON_THROW_ON_ERROR);
        } catch (JsonException $e) {
            throw new VerificationFailedException('Rekor entry body is not valid JSON.', previous: $e);
        }

        if (! is_array($body)) {
            throw new VerificationFailedException('Rekor entry body is not a JSON object.');
        }

        /** @var array<string, mixed> $body */
        return $body;
    }

    private function bodyHash(TlogEntry $entry): string
    {
        $body = $this->decodeBody($entry);

        $hash = match ($entry->kind) {
            'intoto' => self::dig($body, 'spec', 'content', 'payloadHash', 'value'),
            'dsse' => self::dig($body, 'spec', 'payloadHash', 'value'),
            'hashedrekord' => self::dig($body, 'spec', 'data', 'hash', 'value'),
            default => throw new UnsupportedBundleException(
                sprintf('Unsupported Rekor entry kind "%s"; cannot bind it to the bundle.', $entry->kind),
            ),
        };

        if (! is_string($hash) || $hash === '') {
            throw new VerificationFailedException('Rekor entry body has no hash to bind.');
        }

        return $hash;
    }

    /** Walk a decoded JSON tree by successive object keys, returning null on any miss. */
    private static function dig(mixed $value, string ...$keys): mixed
    {
        foreach ($keys as $key) {
            if (! is_array($value) || ! array_key_exists($key, $value)) {
                return null;
            }
            $value = $value[$key];
        }

        return $value;
    }
}

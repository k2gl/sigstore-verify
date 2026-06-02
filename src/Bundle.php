<?php

declare(strict_types=1);

namespace K2gl\Sigstore;

use K2gl\Dsse\Envelope;
use K2gl\Dsse\Exception\DsseException;
use K2gl\Sigstore\Exception\InvalidBundleException;
use K2gl\Sigstore\Exception\UnsupportedBundleException;
use K2gl\Sigstore\Internal\Json;

/**
 * A parsed Sigstore bundle (the .sigstore.json produced by cosign, gitsign, npm
 * provenance, etc.): one or more Rekor transparency-log entries, exactly one
 * content — a DSSE envelope (an attestation) or a message signature (an artifact
 * signature) — and a signing identity that is either a Fulcio leaf certificate
 * (keyless) or a public-key reference (a {@see $publicKeyHint} naming a key the
 * caller supplies out of band).
 *
 * @see https://github.com/sigstore/protobuf-specs/blob/main/protos/sigstore_bundle.proto
 */
final class Bundle
{
    private const MEDIA_TYPE_PREFIX = 'application/vnd.dev.sigstore.bundle';

    /**
     * @param ?string                $leafCertificate   DER Fulcio leaf certificate, or null for a public-key bundle
     * @param list<TlogEntry>        $tlogEntries
     * @param list<Rfc3161Timestamp> $rfc3161Timestamps
     * @param ?string                $publicKeyHint     key hint of a public-key bundle, or null for a certificate bundle
     */
    public function __construct(
        public readonly string $mediaType,
        public readonly ?string $leafCertificate,
        public readonly array $tlogEntries,
        public readonly ?Envelope $dsseEnvelope = null,
        public readonly ?MessageSignature $messageSignature = null,
        public readonly array $rfc3161Timestamps = [],
        public readonly ?string $publicKeyHint = null,
    ) {}

    public function isDsse(): bool
    {
        return $this->dsseEnvelope !== null;
    }

    public function isMessageSignature(): bool
    {
        return $this->messageSignature !== null;
    }

    /** True if the signing identity is a Fulcio leaf certificate (keyless). */
    public function hasCertificate(): bool
    {
        return $this->leafCertificate !== null;
    }

    /** True if the signing identity is a public-key reference (caller supplies the key). */
    public function isPublicKey(): bool
    {
        return $this->leafCertificate === null;
    }

    /**
     * Whether a Merkle inclusion proof is mandatory: from bundle media type
     * v0.2 onward an inclusion promise alone is not enough, while the earliest
     * (v0.1) bundles predate that requirement.
     */
    public function requiresInclusionProof(): bool
    {
        return version_compare($this->mediaTypeVersion(), '0.2', '>=');
    }

    /** The bundle media type version, e.g. "0.1", "0.2", "0.3". */
    private function mediaTypeVersion(): string
    {
        if (preg_match('/[.;]v(?:ersion=)?(\d+\.\d+)/', $this->mediaType, $matches) === 1) {
            return $matches[1];
        }

        return '0.1';
    }

    public static function fromJson(string $json): self
    {
        return self::fromArray(Json::decodeObject($json));
    }

    /** @param array<string, mixed> $data */
    public static function fromArray(array $data): self
    {
        $mediaType = Json::string($data, 'mediaType');

        if (! str_starts_with($mediaType, self::MEDIA_TYPE_PREFIX)) {
            throw new UnsupportedBundleException(sprintf('Unsupported bundle media type "%s".', $mediaType));
        }

        $material = Json::object($data, 'verificationMaterial');
        [$leaf, $hint] = self::signingMaterial($material);
        $tlogEntries = self::tlogEntries($material);
        $timestamps = self::rfc3161Timestamps($material);

        if (isset($data['dsseEnvelope'])) {
            return new self(
                mediaType: $mediaType,
                leafCertificate: $leaf,
                tlogEntries: $tlogEntries,
                dsseEnvelope: self::dsseEnvelope(Json::object($data, 'dsseEnvelope')),
                rfc3161Timestamps: $timestamps,
                publicKeyHint: $hint,
            );
        }

        if (isset($data['messageSignature'])) {
            return new self(
                mediaType: $mediaType,
                leafCertificate: $leaf,
                tlogEntries: $tlogEntries,
                messageSignature: MessageSignature::fromArray(Json::object($data, 'messageSignature')),
                rfc3161Timestamps: $timestamps,
                publicKeyHint: $hint,
            );
        }

        throw new InvalidBundleException('Bundle has neither dsseEnvelope nor messageSignature content.');
    }

    /**
     * Resolve the signing identity: a Fulcio leaf certificate (keyless) or a
     * public-key reference. Exactly one is returned non-null.
     *
     * @param  array<string, mixed>  $material
     * @return array{0: ?string, 1: ?string} the leaf certificate DER, and the public-key hint
     */
    private static function signingMaterial(array $material): array
    {
        if (isset($material['certificate'])) {
            return [Json::base64(Json::object($material, 'certificate'), 'rawBytes'), null];
        }

        if (isset($material['x509CertificateChain'])) {
            $chain = Json::list(Json::object($material, 'x509CertificateChain'), 'certificates');
            $leaf = $chain[0] ?? null;

            if (! is_array($leaf)) {
                throw new InvalidBundleException('x509CertificateChain.certificates is empty.');
            }

            return [Json::base64($leaf, 'rawBytes'), null];
        }

        if (isset($material['publicKey'])) {
            return [null, self::publicKeyHint(Json::object($material, 'publicKey'))];
        }

        throw new InvalidBundleException('Bundle verification material has no certificate or public key.');
    }

    /**
     * The hint of a public-key bundle, or null when absent. The hint only names
     * which key the caller must supply; the bundle never carries the key bytes.
     *
     * @param array<string, mixed> $publicKey
     */
    private static function publicKeyHint(array $publicKey): ?string
    {
        $hint = $publicKey['hint'] ?? null;

        return is_string($hint) && $hint !== '' ? $hint : null;
    }

    /**
     * @param  array<string, mixed> $material
     * @return list<TlogEntry>
     */
    private static function tlogEntries(array $material): array
    {
        $entries = [];

        foreach (Json::list($material, 'tlogEntries') as $raw) {
            if (! is_array($raw)) {
                throw new InvalidBundleException('Each tlog entry must be a JSON object.');
            }
            /** @var array<string, mixed> $raw */
            $entries[] = TlogEntry::fromArray($raw);
        }

        if ($entries === []) {
            throw new InvalidBundleException('Bundle has no transparency-log entries.');
        }

        return $entries;
    }

    /**
     * @param  array<string, mixed>  $material
     * @return list<Rfc3161Timestamp>
     */
    private static function rfc3161Timestamps(array $material): array
    {
        $data = $material['timestampVerificationData'] ?? null;

        if (! is_array($data)) {
            return [];
        }
        $raw = $data['rfc3161Timestamps'] ?? null;

        if (! is_array($raw) || ! array_is_list($raw)) {
            return [];
        }
        $timestamps = [];

        foreach ($raw as $entry) {
            if (! is_array($entry)) {
                throw new InvalidBundleException('Each RFC 3161 timestamp must be a JSON object.');
            }
            /** @var array<string, mixed> $entry */
            $timestamps[] = Rfc3161Timestamp::fromArray($entry);
        }

        return $timestamps;
    }

    /** @param array<string, mixed> $dsse */
    private static function dsseEnvelope(array $dsse): Envelope
    {
        try {
            return Envelope::fromArray($dsse);
        } catch (DsseException $e) {
            throw new InvalidBundleException('Bundle dsseEnvelope is invalid: ' . $e->getMessage(), previous: $e);
        }
    }
}

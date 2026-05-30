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
 * provenance, etc.). This version models the DSSE-attestation shape only: a
 * Fulcio leaf certificate, one or more Rekor transparency-log entries, and a
 * DSSE envelope.
 *
 * Anything outside that shape — a message-signature artifact bundle or a
 * public-key (keyless-without-certificate) bundle — is rejected at parse time
 * with {@see UnsupportedBundleException}, so it can never be mistaken for a
 * verifiable attestation.
 *
 * @see https://github.com/sigstore/protobuf-specs/blob/main/protos/sigstore_bundle.proto
 */
final class Bundle
{
    private const MEDIA_TYPE_PREFIX = 'application/vnd.dev.sigstore.bundle';

    /** @param list<TlogEntry> $tlogEntries */
    public function __construct(
        public readonly string $mediaType,
        public readonly string $leafCertificate,
        public readonly array $tlogEntries,
        public readonly Envelope $dsseEnvelope,
    ) {
    }

    public static function fromJson(string $json): self
    {
        return self::fromArray(Json::decodeObject($json));
    }

    /** @param array<string, mixed> $data */
    public static function fromArray(array $data): self
    {
        $mediaType = Json::string($data, 'mediaType');
        if (!str_starts_with($mediaType, self::MEDIA_TYPE_PREFIX)) {
            throw new UnsupportedBundleException(sprintf('Unsupported bundle media type "%s".', $mediaType));
        }

        if (!isset($data['dsseEnvelope'])) {
            if (isset($data['messageSignature'])) {
                throw new UnsupportedBundleException(
                    'This version verifies DSSE-attestation bundles only; message-signature bundles are not supported.'
                );
            }
            throw new InvalidBundleException('Bundle has no dsseEnvelope content.');
        }

        $material = Json::object($data, 'verificationMaterial');

        return new self(
            $mediaType,
            self::leafCertificate($material),
            self::tlogEntries($material),
            self::dsseEnvelope(Json::object($data, 'dsseEnvelope')),
        );
    }

    /** @param array<string, mixed> $material */
    private static function leafCertificate(array $material): string
    {
        if (isset($material['certificate'])) {
            return Json::base64(Json::object($material, 'certificate'), 'rawBytes');
        }
        if (isset($material['x509CertificateChain'])) {
            $chain = Json::list(Json::object($material, 'x509CertificateChain'), 'certificates');
            $leaf = $chain[0] ?? null;
            if (!is_array($leaf)) {
                throw new InvalidBundleException('x509CertificateChain.certificates is empty.');
            }
            return Json::base64($leaf, 'rawBytes');
        }
        if (isset($material['publicKey'])) {
            throw new UnsupportedBundleException(
                'This version verifies certificate-based bundles only; public-key bundles are not supported.'
            );
        }
        throw new InvalidBundleException('Bundle verification material has no certificate.');
    }

    /**
     * @param  array<string, mixed> $material
     * @return list<TlogEntry>
     */
    private static function tlogEntries(array $material): array
    {
        $entries = [];
        foreach (Json::list($material, 'tlogEntries') as $raw) {
            if (!is_array($raw)) {
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

<?php

declare(strict_types=1);

namespace K2gl\Sigstore;

use K2gl\Sigstore\Exception\TrustRootException;
use K2gl\Sigstore\Internal\TrustRootJson;

/**
 * The set of trust anchors a verification runs against, parsed from a Sigstore
 * trusted_root.json: the Fulcio certificate authorities, the Rekor transparency
 * logs, and any RFC 3161 timestamp authorities.
 *
 * This package does not fetch or update trust material. The caller supplies a
 * trusted_root.json — obtained from the Sigstore TUF root or via
 * `cosign trusted-root create` — and is responsible for keeping it current.
 *
 * @see https://github.com/sigstore/protobuf-specs/blob/main/protos/sigstore_trustroot.proto
 */
final class TrustedRoot
{
    /**
     * @param list<CertificateAuthority>     $certificateAuthorities
     * @param list<TransparencyLogInstance>  $transparencyLogs
     * @param list<CertificateAuthority>     $timestampAuthorities    RFC 3161 timestamp authorities, if any
     * @param list<TransparencyLogInstance>  $ctLogs                  Certificate Transparency logs, if any
     */
    public function __construct(
        public readonly array $certificateAuthorities,
        public readonly array $transparencyLogs,
        public readonly array $timestampAuthorities = [],
        public readonly array $ctLogs = [],
    ) {
        if ($certificateAuthorities === []) {
            throw new TrustRootException('Trusted root has no certificate authorities.');
        }

        if ($transparencyLogs === []) {
            throw new TrustRootException('Trusted root has no transparency logs.');
        }
    }

    public static function fromJson(string $json): self
    {
        $data = TrustRootJson::decodeObject($json);

        $authorities = [];

        foreach (TrustRootJson::list($data, 'certificateAuthorities', 'certificate_authorities') as $entry) {
            if (!is_array($entry)) {
                throw new TrustRootException('Certificate authority entry must be an object.');
            }
            /** @var array<string, mixed> $entry */
            $authorities[] = CertificateAuthority::fromArray($entry);
        }

        $logs = [];

        foreach (TrustRootJson::list($data, 'tlogs') as $entry) {
            if (!is_array($entry)) {
                throw new TrustRootException('Transparency log entry must be an object.');
            }
            /** @var array<string, mixed> $entry */
            $logs[] = TransparencyLogInstance::fromArray($entry);
        }

        return new self($authorities, $logs, self::timestampAuthorities($data), self::ctLogs($data));
    }

    /**
     * Certificate Transparency logs are optional: a trusted root without them
     * simply cannot anchor a certificate's embedded SCTs.
     *
     * @param  array<string, mixed>         $data
     * @return list<TransparencyLogInstance>
     */
    private static function ctLogs(array $data): array
    {
        $raw = $data['ctlogs'] ?? $data['ctLogs'] ?? $data['ct_logs'] ?? null;

        if (!is_array($raw) || !array_is_list($raw)) {
            return [];
        }
        $logs = [];

        foreach ($raw as $entry) {
            if (!is_array($entry)) {
                throw new TrustRootException('Certificate transparency log entry must be an object.');
            }
            /** @var array<string, mixed> $entry */
            $logs[] = TransparencyLogInstance::fromArray($entry);
        }

        return $logs;
    }

    /**
     * Timestamp authorities are optional: a trusted root without them simply
     * cannot anchor RFC 3161 timestamps.
     *
     * @param  array<string, mixed>      $data
     * @return list<CertificateAuthority>
     */
    private static function timestampAuthorities(array $data): array
    {
        $raw = $data['timestampAuthorities'] ?? $data['timestamp_authorities'] ?? null;

        if (!is_array($raw) || !array_is_list($raw)) {
            return [];
        }
        $authorities = [];

        foreach ($raw as $entry) {
            if (!is_array($entry)) {
                throw new TrustRootException('Timestamp authority entry must be an object.');
            }
            /** @var array<string, mixed> $entry */
            $authorities[] = CertificateAuthority::fromArray($entry);
        }

        return $authorities;
    }

    /** Find the transparency log whose log id matches the given raw bytes. */
    public function findTransparencyLog(string $logId): ?TransparencyLogInstance
    {
        foreach ($this->transparencyLogs as $log) {
            if (hash_equals($log->logId, $logId)) {
                return $log;
            }
        }

        return null;
    }

    /** Find the Certificate Transparency log whose log id matches the given raw bytes. */
    public function findCtLog(string $logId): ?TransparencyLogInstance
    {
        foreach ($this->ctLogs as $log) {
            if (hash_equals($log->logId, $logId)) {
                return $log;
            }
        }

        return null;
    }
}

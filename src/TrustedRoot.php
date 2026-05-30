<?php

declare(strict_types=1);

namespace K2gl\Sigstore;

use K2gl\Sigstore\Exception\TrustRootException;
use K2gl\Sigstore\Internal\TrustRootJson;

/**
 * The set of trust anchors a verification runs against, parsed from a Sigstore
 * trusted_root.json: the Fulcio certificate authorities and the Rekor
 * transparency logs.
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
     */
    public function __construct(
        public readonly array $certificateAuthorities,
        public readonly array $transparencyLogs,
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

        return new self($authorities, $logs);
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
}

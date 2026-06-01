<?php

declare(strict_types=1);

namespace K2gl\Sigstore;

use K2gl\Sigstore\Exception\TrustRootException;
use K2gl\Sigstore\Internal\TrustRootJson;
use K2gl\Tuf\Fetcher;
use K2gl\Tuf\HttpFetcher;
use K2gl\Tuf\Updater;
use DateTimeImmutable;

/**
 * The set of trust anchors a verification runs against, parsed from a Sigstore
 * trusted_root.json: the Fulcio certificate authorities, the Rekor transparency
 * logs, and any RFC 3161 timestamp authorities.
 *
 * The verifier's core stays offline: it never reaches the network on its own.
 * Trust material can be supplied three ways. {@see fromJson()} takes a
 * caller-managed trusted_root.json (e.g. from `cosign trusted-root create`).
 * {@see fromTuf()} resolves it through a caller-built {@see Updater}, so the
 * Sigstore TUF repository keeps the root current with its own rotation rules.
 * {@see fromSigstorePublicGood()} is the convenience over that for the public
 * Sigstore instance. The TUF paths are the only ones that touch the network,
 * and only through the injected fetcher.
 *
 * @see https://github.com/sigstore/protobuf-specs/blob/main/protos/sigstore_trustroot.proto
 */
final class TrustedRoot
{
    /** Metadata base URL of the public-good Sigstore TUF repository. */
    private const SIGSTORE_TUF_METADATA_URL = 'https://tuf-repo-cdn.sigstore.dev';

    /** Target base URL of the public-good Sigstore TUF repository. */
    private const SIGSTORE_TUF_TARGETS_URL = 'https://tuf-repo-cdn.sigstore.dev/targets';

    /** The target path the Sigstore TUF repository publishes the trusted root under. */
    private const TRUSTED_ROOT_TARGET = 'trusted_root.json';
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
            if (! is_array($entry)) {
                throw new TrustRootException('Certificate authority entry must be an object.');
            }
            /** @var array<string, mixed> $entry */
            $authorities[] = CertificateAuthority::fromArray($entry);
        }

        $logs = [];

        foreach (TrustRootJson::list($data, 'tlogs') as $entry) {
            if (! is_array($entry)) {
                throw new TrustRootException('Transparency log entry must be an object.');
            }
            /** @var array<string, mixed> $entry */
            $logs[] = TransparencyLogInstance::fromArray($entry);
        }

        return new self($authorities, $logs, self::timestampAuthorities($data), self::ctLogs($data));
    }

    /**
     * Resolve the trusted root from a Sigstore TUF repository through a
     * caller-built {@see Updater}. The updater refreshes the top-level metadata,
     * the named target's length and hashes are verified by the TUF client, and
     * the resulting bytes are parsed by {@see fromJson()}.
     *
     * Fail-closed: a TUF verification failure (rollback, expiry, threshold,
     * length or hash mismatch) throws a {@see \K2gl\Tuf\Exception\TufException},
     * and a repository that does not publish the target throws here.
     */
    public static function fromTuf(Updater $updater, string $targetPath = self::TRUSTED_ROOT_TARGET): self
    {
        $updater->refresh();
        $target = $updater->getTargetInfo($targetPath);

        if ($target === null) {
            throw new TrustRootException(\sprintf('Sigstore TUF repository has no target "%s".', $targetPath));
        }

        return self::fromJson($updater->downloadTarget($target));
    }

    /**
     * Resolve the trusted root from the public-good Sigstore TUF repository,
     * using a bundled root.json as the trust-on-first-use anchor (TUF rotates it
     * forward from there). The verifier core stays offline — the network is
     * reached only through the fetcher, which defaults to {@see HttpFetcher}.
     * Pass a $referenceTime to evaluate metadata expiry at a fixed instant.
     */
    public static function fromSigstorePublicGood(
        ?Fetcher $fetcher = null,
        ?DateTimeImmutable $referenceTime = null,
    ): self {
        $root = file_get_contents(__DIR__ . '/../resources/sigstore-tuf-root.json');

        if ($root === false) {
            throw new TrustRootException('Bundled Sigstore TUF root could not be read.');
        }
        $updater = new Updater(
            trustedRoot: $root,
            metadataBaseUrl: self::SIGSTORE_TUF_METADATA_URL,
            targetBaseUrl: self::SIGSTORE_TUF_TARGETS_URL,
            fetcher: $fetcher ?? new HttpFetcher,
            referenceTime: $referenceTime,
        );

        return self::fromTuf($updater);
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

        if (! is_array($raw) || ! array_is_list($raw)) {
            return [];
        }
        $logs = [];

        foreach ($raw as $entry) {
            if (! is_array($entry)) {
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

        if (! is_array($raw) || ! array_is_list($raw)) {
            return [];
        }
        $authorities = [];

        foreach ($raw as $entry) {
            if (! is_array($entry)) {
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

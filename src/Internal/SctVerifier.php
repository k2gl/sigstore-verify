<?php

declare(strict_types=1);

namespace K2gl\Sigstore\Internal;

use K2gl\Sigstore\Exception\VerificationFailedException;
use K2gl\Sigstore\TransparencyLogInstance;

/**
 * Verifies a Fulcio leaf certificate's embedded Signed Certificate Timestamps
 * against the trusted root's Certificate Transparency logs (RFC 6962). An
 * embedded SCT is a CT log's promise, made when Fulcio submitted the
 * pre-certificate, that the certificate's issuance is publicly logged.
 *
 * For each SCT the log reconstructs and signs a {@see https://www.rfc-editor.org/rfc/rfc6962#section-3.2 CertificateTimestamp}:
 * the SCT timestamp, the issuing CA's key hash, the pre-certificate TBSCertificate
 * (this leaf with the SCT extension removed), and the SCT extensions. This
 * rebuilds that structure and checks the SCT signature under a trusted log key
 * whose operating window covers the SCT timestamp.
 *
 * Fail-closed: a certificate with no embedded SCT, an SCT from an unknown or
 * out-of-window log, or a signature that does not verify all throw. At least one
 * SCT must verify.
 *
 * @internal
 */
final class SctVerifier
{
    private const SIGNATURE_TYPE_CERTIFICATE_TIMESTAMP = 0x00;
    private const ENTRY_TYPE_PRECERT = 0x0001;

    /**
     * @param  list<TransparencyLogInstance> $ctLogs non-empty; the caller verifies SCTs only when configured
     * @throws VerificationFailedException
     */
    public function verify(Certificate $leaf, Certificate $issuer, array $ctLogs): void
    {
        $listBytes = $leaf->embeddedSctListBytes();

        if ($listBytes === null) {
            throw new VerificationFailedException(
                'Certificate carries no embedded SCT, but the trusted root requires certificate transparency.'
            );
        }
        $scts = Sct::parseList($listBytes);

        if ($scts === []) {
            throw new VerificationFailedException('Certificate embedded SCT list is empty.');
        }
        $tbs = $leaf->precertificateTbs();
        $issuerKeyHash = hash('sha256', $issuer->subjectPublicKeyInfoDer(), true);

        foreach ($scts as $sct) {
            if ($this->verifyOne($sct, $tbs, $issuerKeyHash, $ctLogs)) {
                return;
            }
        }
        throw new VerificationFailedException(
            'No embedded Signed Certificate Timestamp verifies against a trusted certificate transparency log.'
        );
    }

    /** @param list<TransparencyLogInstance> $ctLogs */
    private function verifyOne(Sct $sct, string $tbs, string $issuerKeyHash, array $ctLogs): bool
    {
        if ($sct->hashAlgorithm !== Sct::HASH_SHA256 || $sct->signatureAlgorithm !== Sct::SIGNATURE_ECDSA) {
            return false;
        }
        $log = $this->findLog($sct->logId, $ctLogs);

        if ($log === null || !$log->isValidAt($sct->time())) {
            return false;
        }

        return Ecdsa::verifyDer(
            message: $this->certificateTimestamp($sct, $tbs, $issuerKeyHash),
            derSignature: $sct->signature,
            publicKeyPem: $log->publicKeyPem,
        );
    }

    /**
     * The signed CertificateTimestamp body for a pre-certificate entry:
     * version, signature type, timestamp, entry type, then the PreCert
     * (issuer key hash and length-prefixed TBSCertificate) and SCT extensions.
     */
    private function certificateTimestamp(Sct $sct, string $tbs, string $issuerKeyHash): string
    {
        return chr(0x00) // sct_version v1
            . chr(self::SIGNATURE_TYPE_CERTIFICATE_TIMESTAMP)
            . pack('J', $sct->timestamp)
            . pack('n', self::ENTRY_TYPE_PRECERT)
            . $issuerKeyHash
            . substr(pack('N', strlen($tbs)), 1) . $tbs // uint24-length-prefixed
            . pack('n', strlen($sct->extensions)) . $sct->extensions;
    }

    /** @param list<TransparencyLogInstance> $ctLogs */
    private function findLog(string $logId, array $ctLogs): ?TransparencyLogInstance
    {
        foreach ($ctLogs as $log) {
            if (hash_equals($log->logId, $logId)) {
                return $log;
            }
        }

        return null;
    }
}

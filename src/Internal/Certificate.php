<?php

declare(strict_types=1);

namespace K2gl\Sigstore\Internal;

use K2gl\Sigstore\Exception\VerificationFailedException;
use phpseclib3\Crypt\Common\PublicKey;
use phpseclib3\File\X509;

/**
 * A thin wrapper over phpseclib's X.509 parser for the few things the verifier
 * needs from a certificate: its public key, the curve, validity at a point in
 * time, who signed it, the subject alternative names and the Fulcio OIDC issuer
 * extension.
 *
 * Parsing happens at verification time, so any malformed certificate (in the
 * bundle or the trusted root) surfaces as a {@see VerificationFailedException}.
 *
 * @internal
 */
final class Certificate
{
    /** Fulcio "Issuer" extension (v1), holding the OIDC issuer as a plain string. */
    private const OID_FULCIO_ISSUER_V1 = '1.3.6.1.4.1.57264.1.1';

    /** RFC 6962 embedded Signed Certificate Timestamp list extension. */
    private const OID_SCT_LIST = '1.3.6.1.4.1.11129.2.4.2';

    private function __construct(
        private readonly X509 $x509,
        private readonly string $der,
    ) {
    }

    public static function fromDer(string $der): self
    {
        $x509 = new X509();

        if (!is_array($x509->loadX509($der))) {
            throw new VerificationFailedException('Unable to parse an X.509 certificate.');
        }

        return new self($x509, $der);
    }

    /** PEM-encoded SubjectPublicKeyInfo for this certificate's key. */
    public function publicKeyPem(): string
    {
        return $this->publicKey()->toString('PKCS8');
    }

    /**
     * The certificate's public key as a {@see SignatureKey}, resolved to the
     * Sigstore signature scheme for its algorithm. Throws
     * {@see \K2gl\Sigstore\Exception\UnsupportedBundleException} for a key whose
     * algorithm this version does not verify.
     */
    public function signatureKey(): SignatureKey
    {
        return SignatureKey::fromPublicKey($this->publicKey());
    }

    private function publicKey(): PublicKey
    {
        $key = $this->x509->getPublicKey();

        if (!$key instanceof PublicKey) {
            throw new VerificationFailedException('Certificate has no usable public key.');
        }

        return $key;
    }

    public function isValidAt(\DateTimeImmutable $moment): bool
    {
        return $this->x509->validateDate($moment) === true;
    }

    /** True if this certificate's signature verifies under the issuer's key. */
    public function isSignedBy(self $issuer): bool
    {
        $subject = new X509();

        if (!is_array($subject->loadX509($this->der))) {
            return false;
        }
        $subject->loadCA($issuer->pemCertificate());

        return $subject->validateSignature() === true;
    }

    public function pemCertificate(): string
    {
        return Pem::fromDer($this->der, 'CERTIFICATE');
    }

    /**
     * Subject alternative names as flat strings (URIs, emails, DNS names). The
     * Fulcio signing identity lives here.
     *
     * @return list<string>
     */
    public function subjectAlternativeNames(): array
    {
        $extension = $this->x509->getExtension('id-ce-subjectAltName');

        if (!is_array($extension)) {
            return [];
        }
        $names = [];

        foreach ($extension as $entry) {
            if (!is_array($entry)) {
                continue;
            }

            foreach (['uniformResourceIdentifier', 'rfc822Name', 'dNSName'] as $type) {
                $value = $entry[$type] ?? null;

                if (is_string($value) && $value !== '') {
                    $names[] = $value;
                }
            }
        }

        return $names;
    }

    /** The OIDC issuer from the Fulcio v1 extension, or null if absent. */
    public function oidcIssuer(): ?string
    {
        $value = $this->x509->getExtension(self::OID_FULCIO_ISSUER_V1);

        return is_string($value) && $value !== '' ? $value : null;
    }

    /**
     * The TLS-encoded SignedCertificateTimestampList carried in the leaf's
     * embedded SCT extension, or null when the extension is absent. The X.509
     * extnValue is an OCTET STRING that itself wraps an OCTET STRING (RFC 6962
     * §3.3); this returns the inner content — the SCT list itself.
     */
    public function embeddedSctListBytes(): ?string
    {
        $extension = $this->findExtension(self::OID_SCT_LIST);

        if ($extension === null) {
            return null;
        }
        $children = Asn1::children($this->der, $extension);
        $extnValue = $children[count($children) - 1];

        if ($extnValue['tag'] !== Asn1::TAG_OCTET_STRING || $extnValue['class'] !== Asn1::CLASS_UNIVERSAL) {
            throw new VerificationFailedException('SCT extension value is not an OCTET STRING.');
        }
        $wrapped = substr($this->der, $extnValue['contentStart'], $extnValue['contentLen']);
        $inner = Asn1::read($wrapped, 0);

        if ($inner['tag'] !== Asn1::TAG_OCTET_STRING || $inner['class'] !== Asn1::CLASS_UNIVERSAL) {
            throw new VerificationFailedException('SCT extension does not wrap an OCTET STRING.');
        }

        return substr($wrapped, $inner['contentStart'], $inner['contentLen']);
    }

    /**
     * The pre-certificate TBSCertificate (RFC 6962 §3.2): this certificate's
     * TBSCertificate with the embedded SCT extension removed, re-encoded as DER.
     * This is the body a CT log signed before the SCT was embedded.
     */
    public function precertificateTbs(): string
    {
        $tbs = $this->tbs();
        $extensions = $this->extensionsWrapper($tbs);
        $sequence = Asn1::children($this->der, $extensions)[0]
            ?? throw new VerificationFailedException('Certificate extensions are empty.');

        $sct = $this->findExtension(self::OID_SCT_LIST)
            ?? throw new VerificationFailedException('Certificate carries no embedded SCT extension.');

        $sequenceContent = substr($this->der, $sequence['contentStart'], $sct['start'] - $sequence['contentStart'])
            . substr($this->der, $sct['start'] + $sct['length'], ($sequence['contentStart'] + $sequence['contentLen']) - ($sct['start'] + $sct['length']));

        $newSequence = chr(0x30) . Asn1::encodeLength(strlen($sequenceContent)) . $sequenceContent;
        $newWrapper = $this->der[$extensions['start']] . Asn1::encodeLength(strlen($newSequence)) . $newSequence;

        $tbsContent = substr($this->der, $tbs['contentStart'], $extensions['start'] - $tbs['contentStart']) . $newWrapper;

        return chr(0x30) . Asn1::encodeLength(strlen($tbsContent)) . $tbsContent;
    }

    /**
     * The exact DER subjectPublicKeyInfo bytes of this certificate. Used to
     * compute the issuer key hash a pre-certificate SCT is signed over.
     */
    public function subjectPublicKeyInfoDer(): string
    {
        $tbs = $this->tbs();
        $fields = Asn1::children($this->der, $tbs);

        // TBSCertificate: [0] version (Fulcio is always v3), serialNumber, signature,
        // issuer, validity, subject, subjectPublicKeyInfo, ...
        $versionPresent = isset($fields[0])
            && $fields[0]['class'] === Asn1::CLASS_CONTEXT
            && $fields[0]['tag'] === 0;
        $spki = $fields[$versionPresent ? 6 : 5] ?? null;

        if ($spki === null || $spki['tag'] !== Asn1::TAG_SEQUENCE || $spki['class'] !== Asn1::CLASS_UNIVERSAL) {
            throw new VerificationFailedException('Certificate has no subjectPublicKeyInfo.');
        }

        return substr($this->der, $spki['start'], $spki['length']);
    }

    /**
     * The TBSCertificate node (the first element of the Certificate SEQUENCE).
     *
     * @return array{class:int, constructed:bool, tag:int, start:int, headerLen:int, length:int, contentStart:int, contentLen:int}
     */
    private function tbs(): array
    {
        return Asn1::children($this->der, Asn1::read($this->der, 0))[0]
            ?? throw new VerificationFailedException('Certificate has no TBSCertificate.');
    }

    /**
     * The EXPLICIT [3] wrapper around the extensions SEQUENCE.
     *
     * @param  array{class:int, constructed:bool, tag:int, start:int, headerLen:int, length:int, contentStart:int, contentLen:int} $tbs
     * @return array{class:int, constructed:bool, tag:int, start:int, headerLen:int, length:int, contentStart:int, contentLen:int}
     */
    private function extensionsWrapper(array $tbs): array
    {
        foreach (Asn1::children($this->der, $tbs) as $field) {
            if ($field['class'] === Asn1::CLASS_CONTEXT && $field['tag'] === 3 && $field['constructed']) {
                return $field;
            }
        }
        throw new VerificationFailedException('Certificate has no extensions.');
    }

    /**
     * The Extension SEQUENCE whose extnID matches the given OID, or null.
     *
     * @return array{class:int, constructed:bool, tag:int, start:int, headerLen:int, length:int, contentStart:int, contentLen:int}|null
     */
    private function findExtension(string $oid): ?array
    {
        $sequence = Asn1::children($this->der, $this->extensionsWrapper($this->tbs()))[0] ?? null;

        if ($sequence === null) {
            return null;
        }

        foreach (Asn1::children($this->der, $sequence) as $extension) {
            $oidNode = Asn1::children($this->der, $extension)[0] ?? null;

            if ($oidNode === null || $oidNode['tag'] !== Asn1::TAG_OID) {
                continue;
            }

            if (Asn1::decodeOid(substr($this->der, $oidNode['contentStart'], $oidNode['contentLen'])) === $oid) {
                return $extension;
            }
        }

        return null;
    }
}

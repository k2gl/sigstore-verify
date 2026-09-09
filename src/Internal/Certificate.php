<?php

declare(strict_types=1);

namespace K2gl\Sigstore\Internal;

use K2gl\Sigstore\Exception\VerificationFailedException;
use phpseclib3\Crypt\Common\PublicKey;
use phpseclib3\File\X509;
use DateTimeImmutable;
use Throwable;

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

    /** Fulcio "Issuer" extension (v2), holding the OIDC issuer as a DER UTF8String. */
    private const OID_FULCIO_ISSUER_V2 = '1.3.6.1.4.1.57264.1.8';

    /** X.509 Extended Key Usage extension, and the code-signing purpose inside it. */
    private const OID_EXT_KEY_USAGE = '2.5.29.37';

    private const OID_CODE_SIGNING = '1.3.6.1.5.5.7.3.3';

    /** X.509 Subject Alternative Name extension — the Fulcio signing identity. */
    private const OID_SUBJECT_ALT_NAME = '2.5.29.17';

    /** RFC 6962 embedded Signed Certificate Timestamp list extension. */
    private const OID_SCT_LIST = '1.3.6.1.4.1.11129.2.4.2';

    private function __construct(
        private readonly X509 $x509,
        private readonly string $der,
    ) {}

    public static function fromDer(string $der): self
    {
        $x509 = self::load($der) ?? throw new VerificationFailedException('Unable to parse an X.509 certificate.');

        return new self($x509, $der);
    }

    /**
     * phpseclib 3 parses into an instance with loadX509(); phpseclib 4 made
     * load() static and hands back a fresh instance instead. Both are spoken
     * here so the verifier runs on either major version.
     */
    private static function load(string $der): ?X509
    {
        try {
            if (method_exists(X509::class, 'loadX509')) {
                $x509 = new X509;

                return is_array($x509->loadX509($der)) ? $x509 : null;
            }

            return X509::load($der);
        } catch (Throwable) {
            return null;
        }
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

        if (! $key instanceof PublicKey) {
            throw new VerificationFailedException('Certificate has no usable public key.');
        }

        return $key;
    }

    /**
     * Whether $moment falls inside the certificate's validity, endpoints
     * included. The dates are read from the DER rather than from phpseclib,
     * whose accessor for them is not the same across major versions.
     */
    public function isValidAt(DateTimeImmutable $moment): bool
    {
        [$notBefore, $notAfter] = $this->validity();

        return $moment >= $notBefore && $moment <= $notAfter;
    }

    /** @return array{0: DateTimeImmutable, 1: DateTimeImmutable} */
    private function validity(): array
    {
        $fields = Asn1::children($this->der, $this->tbs());

        // TBSCertificate: [0] version (Fulcio is always v3), serialNumber, signature,
        // issuer, validity, ...
        $versionPresent = isset($fields[0])
            && $fields[0]['class'] === Asn1::CLASS_CONTEXT
            && $fields[0]['tag'] === 0;
        $validity = $fields[$versionPresent ? 4 : 3] ?? null;

        if ($validity === null || $validity['tag'] !== Asn1::TAG_SEQUENCE || $validity['class'] !== Asn1::CLASS_UNIVERSAL) {
            throw new VerificationFailedException('Certificate has no validity period.');
        }
        $bounds = Asn1::children($this->der, $validity);

        if (count($bounds) !== 2) {
            throw new VerificationFailedException('Certificate validity is not a notBefore/notAfter pair.');
        }

        return [Asn1::decodeTime($this->der, $bounds[0]), Asn1::decodeTime($this->der, $bounds[1])];
    }

    /**
     * True if the certificate's Extended Key Usage includes code signing
     * (id-kp-codeSigning). Fulcio issues code-signing certificates, and the
     * reference clients reject a leaf that lacks this usage.
     */
    public function hasCodeSigningExtendedKeyUsage(): bool
    {
        return in_array(self::OID_CODE_SIGNING, $this->extendedKeyUsage(), true);
    }

    /**
     * The purpose OIDs in the Extended Key Usage extension. Read from the DER:
     * phpseclib's shape for a decoded extension is not the same across major
     * versions, and an OID comparison does not need its friendly names.
     *
     * @return list<string>
     */
    private function extendedKeyUsage(): array
    {
        $sequence = $this->extensionValue(self::OID_EXT_KEY_USAGE, Asn1::TAG_SEQUENCE);

        if ($sequence === null) {
            return [];
        }
        $purposes = [];

        foreach (Asn1::children($this->der, $sequence) as $purpose) {
            if ($purpose['tag'] === Asn1::TAG_OID && $purpose['class'] === Asn1::CLASS_UNIVERSAL) {
                $purposes[] = Asn1::decodeOid(substr($this->der, $purpose['contentStart'], $purpose['contentLen']));
            }
        }

        return $purposes;
    }

    /**
     * True if this certificate's signature verifies under the issuer's key.
     *
     * $at is the moment the chain is being validated for. phpseclib 3 checked
     * only the signature here, while 4 also compares both certificates against
     * a validation date that defaults to now — which would reject every chain
     * signed in the past. Handing it the same moment the caller checks validity
     * at keeps the two majors saying the same thing.
     */
    public function isSignedBy(self $issuer, DateTimeImmutable $at): bool
    {
        $subject = self::load($this->der);

        if ($subject === null) {
            return false;
        }

        if (method_exists($subject, 'loadCA')) {
            $subject->loadCA($issuer->pemCertificate());

            return $subject->validateSignature() === true;
        }

        // phpseclib 4 keeps the CA store and the validation date in static,
        // process-wide state, so trusting exactly one issuer at one moment means
        // emptying both first — and putting back whatever the host application
        // had set.
        $savedCAs = X509::getCAs();
        $savedDate = X509::getTargetValidationDate();

        try {
            X509::clearCAStore();
            X509::addCA($issuer->pemCertificate());
            X509::setTargetValidationDate($at);

            return $subject->validateSignature() === true;
        } catch (Throwable) {
            return false;
        } finally {
            X509::clearCAStore();
            X509::setTargetValidationDate($savedDate);

            foreach ($savedCAs as $ca) {
                X509::addCA($ca);
            }
        }
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
        $sequence = $this->extensionValue(self::OID_SUBJECT_ALT_NAME, Asn1::TAG_SEQUENCE);

        if ($sequence === null) {
            return [];
        }
        $names = [];

        foreach (Asn1::children($this->der, $sequence) as $name) {
            // GeneralName is a CHOICE tagged by position; rfc822Name [1], dNSName [2]
            // and uniformResourceIdentifier [6] are the plain IA5Strings the Fulcio
            // signing identity is written as.
            if ($name['class'] !== Asn1::CLASS_CONTEXT || ! in_array($name['tag'], [1, 2, 6], true)) {
                continue;
            }
            $value = substr($this->der, $name['contentStart'], $name['contentLen']);

            if ($value !== '') {
                $names[] = $value;
            }
        }

        return $names;
    }

    /**
     * The parsed content of an extension's extnValue, or null when the
     * certificate does not carry that extension. $expectedTag is the universal
     * tag the value must have once the OCTET STRING wrapper is removed.
     *
     * @return array{class:int, constructed:bool, tag:int, start:int, headerLen:int, length:int, contentStart:int, contentLen:int}|null
     */
    private function extensionValue(string $oid, int $expectedTag): ?array
    {
        $extension = $this->findExtension($oid);

        if ($extension === null) {
            return null;
        }
        $children = Asn1::children($this->der, $extension);
        $extnValue = $children[count($children) - 1];

        if ($extnValue['tag'] !== Asn1::TAG_OCTET_STRING || $extnValue['class'] !== Asn1::CLASS_UNIVERSAL) {
            throw new VerificationFailedException(sprintf('Extension %s does not hold an OCTET STRING.', $oid));
        }
        $inner = Asn1::read($this->der, $extnValue['contentStart']);

        if ($inner['tag'] !== $expectedTag || $inner['class'] !== Asn1::CLASS_UNIVERSAL) {
            throw new VerificationFailedException(sprintf('Extension %s has an unexpected value.', $oid));
        }

        return $inner;
    }

    /**
     * The Fulcio OIDC issuer, or null if absent. Prefers the v2 extension
     * (OID …57264.1.8, a DER-encoded UTF8String — the one the Sigstore client
     * spec says to check "at a minimum"); falls back to the deprecated v1
     * extension (OID …57264.1.1, a bare string) that older certificates carry.
     */
    public function oidcIssuer(): ?string
    {
        return $this->fulcioIssuerV2() ?? $this->fulcioIssuerV1();
    }

    /**
     * The deprecated v1 extension stores the issuer as bare bytes inside
     * extnValue, with no inner DER value to unwrap. Read straight from the DER:
     * phpseclib 4 narrowed getExtension() to return an array, so it can no
     * longer hand back a plain string at all.
     */
    private function fulcioIssuerV1(): ?string
    {
        $extension = $this->findExtension(self::OID_FULCIO_ISSUER_V1);

        if ($extension === null) {
            return null;
        }
        $children = Asn1::children($this->der, $extension);
        $extnValue = $children[count($children) - 1];

        if ($extnValue['tag'] !== Asn1::TAG_OCTET_STRING || $extnValue['class'] !== Asn1::CLASS_UNIVERSAL) {
            throw new VerificationFailedException('Fulcio issuer (v1) extension value is not an OCTET STRING.');
        }
        $value = substr($this->der, $extnValue['contentStart'], $extnValue['contentLen']);

        return $value !== '' ? $value : null;
    }

    private function fulcioIssuerV2(): ?string
    {
        $extension = $this->findExtension(self::OID_FULCIO_ISSUER_V2);

        if ($extension === null) {
            return null;
        }
        $children = Asn1::children($this->der, $extension);
        $extnValue = $children[count($children) - 1];

        if ($extnValue['tag'] !== Asn1::TAG_OCTET_STRING || $extnValue['class'] !== Asn1::CLASS_UNIVERSAL) {
            throw new VerificationFailedException('Fulcio issuer (v2) extension value is not an OCTET STRING.');
        }
        $wrapped = substr($this->der, $extnValue['contentStart'], $extnValue['contentLen']);
        $inner = Asn1::read($wrapped, 0);

        if ($inner['tag'] !== Asn1::TAG_UTF8_STRING || $inner['class'] !== Asn1::CLASS_UNIVERSAL) {
            throw new VerificationFailedException('Fulcio issuer (v2) extension does not wrap a UTF8String.');
        }
        $value = substr($wrapped, $inner['contentStart'], $inner['contentLen']);

        return $value !== '' ? $value : null;
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

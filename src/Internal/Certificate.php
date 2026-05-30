<?php

declare(strict_types=1);

namespace K2gl\Sigstore\Internal;

use K2gl\Sigstore\Exception\VerificationFailedException;
use phpseclib3\Crypt\Common\PublicKey;
use phpseclib3\Crypt\EC;
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

    /** True if the certificate carries an ECDSA NIST P-256 (secp256r1) key. */
    public function isEcdsaP256(): bool
    {
        $key = $this->publicKey();
        return $key instanceof EC && $key->getCurve() === 'secp256r1';
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
}

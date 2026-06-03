<?php

declare(strict_types=1);

namespace K2gl\Sigstore\Internal;

use K2gl\Dsse\Ed25519Verifier;
use K2gl\Dsse\Verifier;
use K2gl\Sigstore\Exception\UnsupportedBundleException;
use K2gl\Sigstore\Exception\VerificationFailedException;
use phpseclib3\Crypt\Common\PublicKey;
use phpseclib3\Crypt\EC;
use phpseclib3\Crypt\PublicKeyLoader;
use phpseclib3\Crypt\RSA;
use Throwable;

/**
 * The public key that signed a bundle's content, resolved to the one signature
 * scheme Sigstore defines for its algorithm and exposed as a {@see Verifier}.
 *
 * Sigstore ties the digest to the key: ECDSA over NIST P-256/P-384/P-521 uses
 * SHA-256/384/512, RSA (PKCS#1 v1.5) uses SHA-256, and Ed25519 signs the
 * message directly with no prehash. A key whose algorithm Sigstore defines no
 * scheme for is rejected with {@see UnsupportedBundleException}.
 *
 * The same instance verifies a DSSE envelope (over its PAE) and a message
 * signature (over the artifact bytes): for ECDSA and RSA ext-openssl recomputes
 * the digest ({@see OpensslVerifier}), and for Ed25519 the dsse
 * {@see Ed25519Verifier} is reused. For ECDSA and RSA it can also verify from a
 * bare artifact digest ({@see verifyDigest()}), which ext-openssl cannot do.
 *
 * @internal
 */
final class SignatureKey implements Verifier
{
    private function __construct(
        private readonly Verifier $verifier,
        private readonly string $digestAlgorithm,
        private readonly bool $ed25519,
        private readonly ?DigestVerifier $digestVerifier = null,
    ) {}

    /** Resolve a PEM-encoded public key supplied out of band (public-key bundles). */
    public static function fromPem(string $pem): self
    {
        try {
            $key = PublicKeyLoader::load($pem);
        } catch (Throwable $e) {
            throw new VerificationFailedException('Unable to load the supplied public key.', previous: $e);
        }

        if (! $key instanceof PublicKey) {
            throw new VerificationFailedException('The supplied key is not a public key.');
        }

        return self::fromPublicKey($key);
    }

    public static function fromPublicKey(PublicKey $key): self
    {
        if ($key instanceof EC) {
            return self::fromEc($key);
        }

        if ($key instanceof RSA) {
            // Sigstore RSA signatures are PKCS#1 v1.5 over SHA-256.
            $pem = self::pem($key->toString('PKCS8'));

            return new self(
                verifier: new OpensslVerifier($pem, OPENSSL_ALGO_SHA256),
                digestAlgorithm: 'sha256',
                ed25519: false,
                digestVerifier: new RsaPrehashed($pem, 'sha256'),
            );
        }

        throw new UnsupportedBundleException(sprintf('Unsupported signing-key algorithm "%s".', $key::class));
    }

    private static function fromEc(EC $key): self
    {
        $curve = $key->getCurve();

        if ($curve === 'Ed25519') {
            $raw = $key->toString('libsodium');

            if (! is_string($raw) || $raw === '') {
                throw new VerificationFailedException('Unable to extract the Ed25519 public key.');
            }

            return new self(new Ed25519Verifier($raw), 'sha512', true);
        }

        [$algorithm, $digest] = match ($curve) {
            'secp256r1' => [OPENSSL_ALGO_SHA256, 'sha256'],
            'secp384r1' => [OPENSSL_ALGO_SHA384, 'sha384'],
            'secp521r1' => [OPENSSL_ALGO_SHA512, 'sha512'],
            default => throw new UnsupportedBundleException(sprintf(
                'Unsupported ECDSA curve "%s".',
                is_string($curve) ? $curve : 'unknown',
            )),
        };

        return new self(
            verifier: new OpensslVerifier(self::pem($key->toString('PKCS8')), $algorithm),
            digestAlgorithm: $digest,
            ed25519: false,
            digestVerifier: EcdsaPrehashed::fromEcKey($key),
        );
    }

    /**
     * Narrow a phpseclib PKCS#8 encoding to the PEM string OpenSSL needs.
     *
     * @param string|array<mixed> $encoded
     */
    private static function pem(string|array $encoded): string
    {
        if (! is_string($encoded)) {
            throw new VerificationFailedException('Unable to encode the public key.');
        }

        return $encoded;
    }

    public function verify(string $message, string $signature): bool
    {
        return $this->verifier->verify($message, $signature);
    }

    /**
     * Verify a message signature against an already-computed artifact digest,
     * for bundles verified from a bare digest. Defined for ECDSA and RSA; an
     * Ed25519 key has none (its message-signature flow is rejected upstream).
     */
    public function verifyDigest(string $digest, string $signature): bool
    {
        if ($this->digestVerifier === null) {
            throw new UnsupportedBundleException(
                'This signing key cannot verify a message signature from a digest.'
            );
        }

        return $this->digestVerifier->verifyDigest($digest, $signature);
    }

    /** The digest the message-signature digest field is expected to use for this key. */
    public function digestAlgorithm(): string
    {
        return $this->digestAlgorithm;
    }

    /**
     * Ed25519 signs the message with no prehash, but cosign's message-signature
     * flow signs the artifact digest rather than the artifact itself, so an
     * Ed25519 message signature cannot be verified the same way as ECDSA/RSA and
     * is rejected. DSSE Ed25519 is unambiguous and supported.
     */
    public function isEd25519(): bool
    {
        return $this->ed25519;
    }
}

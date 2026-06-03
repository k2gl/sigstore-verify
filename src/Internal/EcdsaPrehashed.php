<?php

declare(strict_types=1);

namespace K2gl\Sigstore\Internal;

use K2gl\Sigstore\Exception\UnsupportedBundleException;
use phpseclib3\Crypt\EC;
use phpseclib3\Crypt\EC\BaseCurves\Prime;
use phpseclib3\Crypt\EC\Curves\secp256r1;
use phpseclib3\Crypt\EC\Curves\secp384r1;
use phpseclib3\Crypt\EC\Curves\secp521r1;
use phpseclib3\Math\BigInteger;
use phpseclib3\Math\PrimeField\Integer as PrimeFieldInteger;
use Throwable;

/**
 * Verifies an ECDSA signature against an already-computed digest, for the NIST
 * curves Sigstore defines (P-256/P-384/P-521). ext-openssl can only verify from
 * the message bytes, so this reproduces the ECDSA verification equation over the
 * supplied digest using phpseclib's vetted curve arithmetic: the digest stands
 * in for the hash phpseclib would otherwise compute, with the same left-shift to
 * the curve order's bit length.
 *
 * The signature is the ASN.1 DER {@code SEQUENCE { INTEGER r, INTEGER s }} that
 * OpenSSL and Sigstore emit.
 *
 * @internal
 */
final class EcdsaPrehashed implements DigestVerifier
{
    private function __construct(
        private readonly Prime $curve,
        private readonly BigInteger $qx,
        private readonly BigInteger $qy,
    ) {}

    /** Resolve the curve and public point from a loaded phpseclib EC public key. */
    public static function fromEcKey(EC $key): self
    {
        $name = $key->getCurve();

        $curve = match ($name) {
            'secp256r1' => new secp256r1,
            'secp384r1' => new secp384r1,
            'secp521r1' => new secp521r1,
            default => throw new UnsupportedBundleException(sprintf(
                'Unsupported ECDSA curve "%s".',
                is_string($name) ? $name : 'unknown',
            )),
        };

        // Weierstrass curves encode the public point as 0x04 || X || Y, each
        // coordinate padded to the modulo length.
        $encoded = $key->getEncodedCoordinates();
        $length = $curve->getLengthInBytes();

        if (strlen($encoded) !== 1 + 2 * $length || $encoded[0] !== "\x04") {
            throw new UnsupportedBundleException('Unexpected EC public-point encoding.');
        }

        return new self(
            curve: $curve,
            qx: new BigInteger(substr($encoded, 1, $length), 256),
            qy: new BigInteger(substr($encoded, 1 + $length, $length), 256),
        );
    }

    public function verifyDigest(string $digest, string $signature): bool
    {
        try {
            return $this->verify($digest, $signature);
        } catch (Throwable) {
            return false;
        }
    }

    private function verify(string $digest, string $signature): bool
    {
        [$r, $s] = $this->parseSignature($signature);

        $order = $this->curve->getOrder();
        $one = new BigInteger(1);
        $upper = $order->subtract($one);

        if (! $r->between($one, $upper) || ! $s->between($one, $upper)) {
            return false;
        }

        $e = new BigInteger($digest, 256);
        $excessBits = strlen($digest) * 8 - $order->getLength();
        $z = $excessBits > 0 ? $e->bitwise_rightShift($excessBits) : $e;

        $w = $s->modInverse($order);
        [, $u1] = $z->multiply($w)->divide($order);
        [, $u2] = $r->multiply($w)->divide($order);

        $point = $this->curve->multiplyAddPoints(
            [$this->curve->getBasePoint(), [$this->curve->convertInteger($this->qx), $this->curve->convertInteger($this->qy)]],
            [$this->curve->convertInteger($u1), $this->curve->convertInteger($u2)],
        );

        [, $remainder] = $this->affineX($point)->divide($order);

        return $remainder->equals($r);
    }

    /**
     * The affine x-coordinate of a phpseclib point as a BigInteger. The point's
     * elements are field integers, but phpseclib annotates them as int, so this
     * crosses that boundary with a real runtime check rather than a cast.
     *
     * @param array<int, mixed> $point
     */
    private function affineX(array $point): BigInteger
    {
        $x = $point[0] ?? null;

        if (! $x instanceof PrimeFieldInteger) {
            throw new UnsupportedBundleException('Unexpected EC point representation.');
        }

        return $x->toBigInteger();
    }

    /**
     * Parse an ASN.1 DER ECDSA signature into its (r, s) integers.
     *
     * @return array{0: BigInteger, 1: BigInteger}
     */
    private function parseSignature(string $signature): array
    {
        $node = Asn1::read($signature, 0);

        if ($node['tag'] !== Asn1::TAG_SEQUENCE || $node['length'] !== strlen($signature)) {
            throw new UnsupportedBundleException('Malformed ECDSA signature.');
        }
        $parts = Asn1::children($signature, $node);

        if (count($parts) !== 2) {
            throw new UnsupportedBundleException('Malformed ECDSA signature.');
        }

        return [
            new BigInteger(substr($signature, $parts[0]['contentStart'], $parts[0]['contentLen']), 256),
            new BigInteger(substr($signature, $parts[1]['contentStart'], $parts[1]['contentLen']), 256),
        ];
    }
}

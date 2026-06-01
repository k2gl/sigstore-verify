<?php

declare(strict_types=1);

namespace K2gl\Sigstore\Tests;

use K2gl\Sigstore\Exception\UnsupportedBundleException;
use K2gl\Sigstore\Exception\VerificationFailedException;
use K2gl\Sigstore\Internal\OpensslVerifier;
use K2gl\Sigstore\Internal\SignatureKey;
use phpseclib3\Crypt\DSA;
use phpseclib3\Crypt\EC;
use phpseclib3\Crypt\RSA;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

use function K2gl\PHPUnitFluentAssertions\fact;

/**
 * The signing-key abstraction, exercised with freshly generated keys of every
 * algorithm Sigstore defines a scheme for: the resolved verifier accepts a
 * genuine signature, rejects a tampered one, and reports the matching digest.
 * Algorithms the spec defines no scheme for are rejected.
 */
#[CoversClass(SignatureKey::class)]
#[CoversClass(OpensslVerifier::class)]
final class SignatureKeyTest extends TestCase
{
    private const MESSAGE = 'the-bytes-that-were-signed';

    /** @return iterable<string, array{string, string}> curve => [openssl/phpseclib hash, expected digest] */
    public static function ecdsaCurves(): iterable
    {
        yield 'P-256' => ['secp256r1', 'sha256'];
        yield 'P-384' => ['secp384r1', 'sha384'];
        yield 'P-521' => ['secp521r1', 'sha512'];
    }

    #[DataProvider('ecdsaCurves')]
    public function testVerifiesEcdsa(string $curve, string $digest): void
    {
        $private = EC::createKey($curve)->withHash($digest);
        $signature = $private->sign(self::MESSAGE);
        $key = SignatureKey::fromPem($private->getPublicKey()->toString('PKCS8'));

        fact($key->verify(self::MESSAGE, $signature))->true();
        fact($key->digestAlgorithm())->is($digest);
        fact($key->isEd25519())->false();
        fact($key->verify('tampered', $signature))->false();
    }

    public function testVerifiesRsa(): void
    {
        $private = RSA::createKey(2048)->withPadding(RSA::SIGNATURE_PKCS1)->withHash('sha256');
        $signature = $private->sign(self::MESSAGE);
        $key = SignatureKey::fromPem($private->getPublicKey()->toString('PKCS8'));

        fact($key->verify(self::MESSAGE, $signature))->true();
        fact($key->digestAlgorithm())->is('sha256');
        fact($key->verify(self::MESSAGE, strrev($signature)))->false();
    }

    public function testVerifiesEd25519(): void
    {
        $private = EC::createKey('Ed25519');
        $signature = $private->sign(self::MESSAGE);
        $key = SignatureKey::fromPem($private->getPublicKey()->toString('PKCS8'));

        fact($key->isEd25519())->true();
        fact($key->verify(self::MESSAGE, $signature))->true();
        fact($key->verify('tampered', $signature))->false();
    }

    public function testRejectsUnsupportedCurve(): void
    {
        $pem = EC::createKey('secp256k1')->getPublicKey()->toString('PKCS8');

        $this->expectException(UnsupportedBundleException::class);
        SignatureKey::fromPem($pem);
    }

    public function testRejectsUnsupportedAlgorithm(): void
    {
        $pem = DSA::createKey()->getPublicKey()->toString('PKCS8');

        $this->expectException(UnsupportedBundleException::class);
        SignatureKey::fromPem($pem);
    }

    public function testRejectsMalformedKey(): void
    {
        $this->expectException(VerificationFailedException::class);
        SignatureKey::fromPem('not a key');
    }
}

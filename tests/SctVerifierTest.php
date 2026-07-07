<?php

declare(strict_types=1);

namespace K2gl\Sigstore\Tests;

use K2gl\Sigstore\CertificateAuthority;
use K2gl\Sigstore\Exception\VerificationFailedException;
use K2gl\Sigstore\Internal\Asn1;
use K2gl\Sigstore\Internal\Certificate;
use K2gl\Sigstore\Internal\Ecdsa;
use K2gl\Sigstore\Internal\Pem;
use K2gl\Sigstore\Internal\Sct;
use K2gl\Sigstore\Internal\SctVerifier;
use K2gl\Sigstore\Internal\TrustRootJson;
use K2gl\Sigstore\TransparencyLogInstance;
use K2gl\Sigstore\TrustedRoot;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use DateTimeImmutable;

use function K2gl\PHPUnitFluentAssertions\fact;

/**
 * Certificate-transparency verification against a real public-good Fulcio leaf
 * certificate and the public-good trusted root: the leaf's embedded SCT verifies
 * under the trusted CT log, and tampering with the log id, key or window, or
 * presenting a certificate with no embedded SCT, all fail closed.
 */
#[CoversClass(SctVerifier::class)]
#[CoversClass(Sct::class)]
#[CoversClass(Asn1::class)]
#[CoversClass(Certificate::class)]
#[CoversClass(TrustedRoot::class)]
#[CoversClass(CertificateAuthority::class)]
#[CoversClass(TransparencyLogInstance::class)]
#[CoversClass(TrustRootJson::class)]
#[CoversClass(Pem::class)]
#[CoversClass(Ecdsa::class)]
#[CoversClass(VerificationFailedException::class)]
final class SctVerifierTest extends TestCase
{
    public function testVerifiesEmbeddedSct(): void
    {
        $leaf = $this->leaf();

        (new SctVerifier)->verify($leaf, $this->issuerFor($leaf), $this->trustedRoot()->ctLogs);

        fact($leaf->embeddedSctListBytes() !== null)->true();
    }

    public function testRejectsUnknownCtLog(): void
    {
        // arrange
        // A CT log set whose ids do not match the SCT: the log is unknown.
        $logs = array_map(
            static fn (TransparencyLogInstance $log): TransparencyLogInstance => new TransparencyLogInstance(
                logId: str_repeat("\x00", 32),
                publicKeyPem: $log->publicKeyPem,
                validForStart: $log->validForStart,
                validForEnd: $log->validForEnd,
            ),
            $this->trustedRoot()->ctLogs,
        );

        $leaf = $this->leaf();

        // act + assert
        fact(fn () => (new SctVerifier)->verify($leaf, $this->issuerFor($leaf), $logs))
            ->throws(VerificationFailedException::class);
    }

    public function testRejectsWrongCtLogKey(): void
    {
        // arrange
        // Right log id, wrong key: the SCT signature no longer verifies.
        $strangerKey = $this->trustedRoot()->transparencyLogs[0]->publicKeyPem;
        $logs = array_map(
            static fn (TransparencyLogInstance $log): TransparencyLogInstance => new TransparencyLogInstance(
                logId: $log->logId,
                publicKeyPem: $strangerKey,
                validForStart: $log->validForStart,
                validForEnd: $log->validForEnd,
            ),
            $this->trustedRoot()->ctLogs,
        );

        $leaf = $this->leaf();

        // act + assert
        fact(fn () => (new SctVerifier)->verify($leaf, $this->issuerFor($leaf), $logs))
            ->throws(VerificationFailedException::class);
    }

    public function testRejectsSctOutsideLogWindow(): void
    {
        // arrange
        // The SCT timestamp falls outside every log's operating window.
        $past = new DateTimeImmutable('2000-01-01T00:00:00Z');
        $logs = array_map(
            static fn (TransparencyLogInstance $log): TransparencyLogInstance => new TransparencyLogInstance(
                logId: $log->logId,
                publicKeyPem: $log->publicKeyPem,
                validForStart: $log->validForStart,
                validForEnd: $past,
            ),
            $this->trustedRoot()->ctLogs,
        );

        $leaf = $this->leaf();

        // act + assert
        fact(fn () => (new SctVerifier)->verify($leaf, $this->issuerFor($leaf), $logs))
            ->throws(VerificationFailedException::class);
    }

    public function testRejectsCertificateWithoutEmbeddedSct(): void
    {
        // arrange
        // The intermediate CA certificate carries no embedded SCT.
        $intermediate = $this->issuerFor($this->leaf());

        // act + assert
        fact(fn () => (new SctVerifier)->verify($intermediate, $intermediate, $this->trustedRoot()->ctLogs))
            ->throws(VerificationFailedException::class);
    }

    public function testEncodeLengthUsesDefiniteForm(): void
    {
        fact(bin2hex(Asn1::encodeLength(0)))->is('00');
        fact(bin2hex(Asn1::encodeLength(127)))->is('7f');
        fact(bin2hex(Asn1::encodeLength(128)))->is('8180');
        fact(bin2hex(Asn1::encodeLength(256)))->is('820100');
    }

    private function leaf(): Certificate
    {
        $bundle = json_decode($this->fixture('bundle-provenance.json'), true);
        fact($bundle)->isArray();
        $raw = $bundle['verificationMaterial']['x509CertificateChain']['certificates'][0]['rawBytes'];
        fact($raw)->isString();
        $der = base64_decode($raw, true);
        fact($der)->isString();

        return Certificate::fromDer($der);
    }

    /** The CA certificate from the trusted root that signed the leaf. */
    private function issuerFor(Certificate $leaf): Certificate
    {
        foreach ($this->trustedRoot()->certificateAuthorities as $authority) {
            foreach ($authority->certificates() as $candidate) {
                if ($leaf->isSignedBy($candidate)) {
                    return $candidate;
                }
            }
        }
        self::fail('No trusted CA issued the leaf certificate.');
    }

    private function trustedRoot(): TrustedRoot
    {
        return TrustedRoot::fromJson($this->fixture('trusted-root-public-good.json'));
    }

    private function fixture(string $name): string
    {
        $contents = file_get_contents(__DIR__ . '/fixtures/' . $name);
        fact($contents)->isString();

        return $contents;
    }
}

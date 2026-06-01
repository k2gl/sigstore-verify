<?php

declare(strict_types=1);

namespace K2gl\Sigstore\Tests;

use K2gl\Dsse\Envelope;
use K2gl\Dsse\Pae;
use K2gl\Dsse\Signature;
use K2gl\InToto\Statement;

use function K2gl\PHPUnitFluentAssertions\fact;

use K2gl\Sigstore\Bundle;
use K2gl\Sigstore\CertificateAuthority;
use K2gl\Sigstore\Checkpoint;
use K2gl\Sigstore\Exception\UnsupportedBundleException;
use K2gl\Sigstore\Exception\VerificationFailedException;
use K2gl\Sigstore\IdentityPolicy;
use K2gl\Sigstore\InclusionProof;
use K2gl\Sigstore\Internal\Ecdsa;
use K2gl\Sigstore\Internal\MerkleInclusion;
use K2gl\Sigstore\Internal\OpensslVerifier;
use K2gl\Sigstore\Internal\SignatureKey;
use K2gl\Sigstore\MessageSignature;
use K2gl\Sigstore\SigstoreVerifier;
use K2gl\Sigstore\TlogEntry;
use K2gl\Sigstore\TransparencyLogInstance;
use K2gl\Sigstore\TrustedRoot;
use phpseclib3\Crypt\Common\PrivateKey;
use phpseclib3\Crypt\EC;
use phpseclib3\Crypt\RSA;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * End-to-end verification of public-key (non-certificate) bundles through
 * {@see SigstoreVerifier}, with the signing key supplied out of band, across
 * every algorithm the verifier supports. The Sigstore infrastructure is
 * hermetic: a freshly generated key plays the role of the Rekor log, signing a
 * single-leaf tree's checkpoint, so the inclusion proof, the payload binding and
 * the content signature are all driven by real cryptography — no certificate
 * chain is involved, which is exactly what a public-key bundle omits.
 *
 * Public-good Sigstore issues only ECDSA P-256 Fulcio certificates, so there is
 * no real-world fixture for the other algorithms or for key-based bundles; these
 * are generated here rather than captured.
 */
#[CoversClass(SigstoreVerifier::class)]
#[CoversClass(Bundle::class)]
#[CoversClass(SignatureKey::class)]
#[CoversClass(OpensslVerifier::class)]
#[CoversClass(MessageSignature::class)]
#[CoversClass(TlogEntry::class)]
#[CoversClass(InclusionProof::class)]
#[CoversClass(Checkpoint::class)]
#[CoversClass(MerkleInclusion::class)]
#[CoversClass(Ecdsa::class)]
#[CoversClass(TransparencyLogInstance::class)]
#[CoversClass(TrustedRoot::class)]
#[CoversClass(CertificateAuthority::class)]
#[CoversClass(UnsupportedBundleException::class)]
#[CoversClass(VerificationFailedException::class)]
final class PublicKeyBundleTest extends TestCase
{
    private const PAYLOAD = '{"_type":"https://in-toto.io/Statement/v1","subject":[]}';
    private const ARTIFACT = 'the artifact bytes that were signed';
    private const HINT = 'sha256:the-key-hint';

    private PrivateKey $logKey;
    private string $logId;
    private string $logKeyPem;

    protected function setUp(): void
    {
        // An ECDSA P-256 key standing in for the Rekor log (Rekor uses ECDSA).
        $log = EC::createKey('secp256r1')->withHash('sha256');
        $this->logKey = $log;
        $this->logKeyPem = $log->getPublicKey()->toString('PKCS8');
        $this->logId = random_bytes(32);
    }

    /** @return iterable<string, array{string}> */
    public static function dsseAlgorithms(): iterable
    {
        yield 'ECDSA P-256' => ['ecdsa-p256'];
        yield 'ECDSA P-384' => ['ecdsa-p384'];
        yield 'ECDSA P-521' => ['ecdsa-p521'];
        yield 'RSA' => ['rsa'];
        yield 'Ed25519' => ['ed25519'];
    }

    #[DataProvider('dsseAlgorithms')]
    public function testVerifiesDssePublicKeyBundle(string $algorithm): void
    {
        [$private, $publicKeyPem] = $this->keyPair($algorithm);
        $signature = $private->sign(Pae::encode(Statement::PAYLOAD_TYPE, self::PAYLOAD));
        $bundle = $this->dsseBundle($signature);

        $envelope = (new SigstoreVerifier())->verifyWithPublicKey($bundle, $publicKeyPem, $this->trustedRoot());

        fact($envelope->payload)->is(self::PAYLOAD);
    }

    /** @return iterable<string, array{string, string}> algorithm => [.., message-digest algorithm] */
    public static function artifactAlgorithms(): iterable
    {
        yield 'ECDSA P-256' => ['ecdsa-p256', 'SHA2_256'];
        yield 'ECDSA P-384' => ['ecdsa-p384', 'SHA2_384'];
        yield 'RSA' => ['rsa', 'SHA2_256'];
    }

    #[DataProvider('artifactAlgorithms')]
    public function testVerifiesArtifactPublicKeyBundle(string $algorithm, string $hashAlgorithm): void
    {
        [$private, $publicKeyPem] = $this->keyPair($algorithm);
        $signature = $private->sign(self::ARTIFACT);
        $bundle = $this->artifactBundle($hashAlgorithm, $signature);

        (new SigstoreVerifier())->verifyArtifactWithPublicKey(
            $bundle,
            self::ARTIFACT,
            $publicKeyPem,
            $this->trustedRoot(),
        );
        $this->addToAssertionCount(1);
    }

    public function testMatchesExpectedHint(): void
    {
        [$private, $publicKeyPem] = $this->keyPair('ecdsa-p256');
        $signature = $private->sign(Pae::encode(Statement::PAYLOAD_TYPE, self::PAYLOAD));

        $envelope = (new SigstoreVerifier())->verifyWithPublicKey(
            $this->dsseBundle($signature),
            $publicKeyPem,
            $this->trustedRoot(),
            expectedHint: self::HINT,
        );

        fact($envelope->payload)->is(self::PAYLOAD);
    }

    public function testRejectsHintMismatch(): void
    {
        [$private, $publicKeyPem] = $this->keyPair('ecdsa-p256');
        $signature = $private->sign(Pae::encode(Statement::PAYLOAD_TYPE, self::PAYLOAD));

        $this->expectException(VerificationFailedException::class);
        (new SigstoreVerifier())->verifyWithPublicKey(
            $this->dsseBundle($signature),
            $publicKeyPem,
            $this->trustedRoot(),
            expectedHint: 'sha256:a-different-key',
        );
    }

    public function testRejectsWrongKey(): void
    {
        [$private] = $this->keyPair('ecdsa-p256');
        $signature = $private->sign(Pae::encode(Statement::PAYLOAD_TYPE, self::PAYLOAD));
        [, $strangerPem] = $this->keyPair('ecdsa-p256');

        $this->expectException(VerificationFailedException::class);
        (new SigstoreVerifier())->verifyWithPublicKey($this->dsseBundle($signature), $strangerPem, $this->trustedRoot());
    }

    public function testRejectsTamperedPayload(): void
    {
        [$private, $publicKeyPem] = $this->keyPair('ecdsa-p256');
        $signature = $private->sign(Pae::encode(Statement::PAYLOAD_TYPE, self::PAYLOAD));

        // A bundle whose envelope payload differs from the one that was signed.
        $envelope = new Envelope('{"_type":"tampered"}', Statement::PAYLOAD_TYPE, [new Signature($signature, null)]);
        $bundle = new Bundle(
            mediaType: 'application/vnd.dev.sigstore.bundle.v0.3+json',
            leafCertificate: null,
            tlogEntries: [$this->entry('dsse', $this->dsseBody('{"_type":"tampered"}'))],
            dsseEnvelope: $envelope,
            publicKeyHint: self::HINT,
        );

        $this->expectException(VerificationFailedException::class);
        (new SigstoreVerifier())->verifyWithPublicKey($bundle, $publicKeyPem, $this->trustedRoot());
    }

    public function testRejectsTamperedArtifact(): void
    {
        [$private, $publicKeyPem] = $this->keyPair('ecdsa-p256');
        $signature = $private->sign(self::ARTIFACT);
        $bundle = $this->artifactBundle('SHA2_256', $signature);

        $this->expectException(VerificationFailedException::class);
        (new SigstoreVerifier())->verifyArtifactWithPublicKey(
            $bundle,
            'a different artifact',
            $publicKeyPem,
            $this->trustedRoot(),
        );
    }

    public function testRejectsEd25519MessageSignature(): void
    {
        [$private, $publicKeyPem] = $this->keyPair('ed25519');
        $signature = $private->sign(self::ARTIFACT);
        $bundle = $this->artifactBundle('SHA2_512', $signature);

        $this->expectException(UnsupportedBundleException::class);
        (new SigstoreVerifier())->verifyArtifactWithPublicKey(
            $bundle,
            self::ARTIFACT,
            $publicKeyPem,
            $this->trustedRoot(),
        );
    }

    public function testRejectsCertificateBundlePassedToPublicKeyMethod(): void
    {
        $contents = file_get_contents(__DIR__ . '/fixtures/bundle-provenance.json');
        fact($contents)->isString();
        [, $publicKeyPem] = $this->keyPair('ecdsa-p256');

        $this->expectException(UnsupportedBundleException::class);
        (new SigstoreVerifier())->verifyWithPublicKey(Bundle::fromJson($contents), $publicKeyPem, $this->trustedRoot());
    }

    public function testRejectsPublicKeyBundlePassedToKeylessMethod(): void
    {
        [$private] = $this->keyPair('ecdsa-p256');
        $signature = $private->sign(Pae::encode(Statement::PAYLOAD_TYPE, self::PAYLOAD));
        $policy = new IdentityPolicy(san: 'https://example.test/id', issuer: 'https://issuer.test');

        $this->expectException(UnsupportedBundleException::class);
        (new SigstoreVerifier())->verify($this->dsseBundle($signature), $this->trustedRoot(), $policy);
    }

    /** @return array{0: PrivateKey, 1: string} a signing key (hash already set) and its public PEM */
    private function keyPair(string $algorithm): array
    {
        $private = match ($algorithm) {
            'ecdsa-p256' => EC::createKey('secp256r1')->withHash('sha256'),
            'ecdsa-p384' => EC::createKey('secp384r1')->withHash('sha384'),
            'ecdsa-p521' => EC::createKey('secp521r1')->withHash('sha512'),
            'rsa' => RSA::createKey(2048)->withPadding(RSA::SIGNATURE_PKCS1)->withHash('sha256'),
            'ed25519' => EC::createKey('Ed25519'),
            default => self::fail('Unknown algorithm ' . $algorithm),
        };

        return [$private, $private->getPublicKey()->toString('PKCS8')];
    }

    private function dsseBundle(string $signature): Bundle
    {
        return new Bundle(
            mediaType: 'application/vnd.dev.sigstore.bundle.v0.3+json',
            leafCertificate: null,
            tlogEntries: [$this->entry('dsse', $this->dsseBody(self::PAYLOAD))],
            dsseEnvelope: new Envelope(self::PAYLOAD, Statement::PAYLOAD_TYPE, [new Signature($signature, null)]),
            publicKeyHint: self::HINT,
        );
    }

    private function artifactBundle(string $hashAlgorithm, string $signature): Bundle
    {
        $digest = hash($this->digest($hashAlgorithm), self::ARTIFACT, true);

        return new Bundle(
            mediaType: 'application/vnd.dev.sigstore.bundle.v0.3+json',
            leafCertificate: null,
            tlogEntries: [$this->entry('hashedrekord', $this->hashedrekordBody(bin2hex($digest)))],
            messageSignature: new MessageSignature($hashAlgorithm, $digest, $signature),
            publicKeyHint: self::HINT,
        );
    }

    private function digest(string $hashAlgorithm): string
    {
        return match ($hashAlgorithm) {
            'SHA2_256' => 'sha256',
            'SHA2_384' => 'sha384',
            'SHA2_512' => 'sha512',
            default => self::fail('Unknown digest ' . $hashAlgorithm),
        };
    }

    private function dsseBody(string $payload): string
    {
        return (string) json_encode([
            'kind' => 'dsse',
            'apiVersion' => '0.0.1',
            'spec' => ['payloadHash' => ['algorithm' => 'sha256', 'value' => hash('sha256', $payload)]],
        ]);
    }

    private function hashedrekordBody(string $digestHex): string
    {
        return (string) json_encode([
            'kind' => 'hashedrekord',
            'apiVersion' => '0.0.1',
            'spec' => ['data' => ['hash' => ['algorithm' => 'sha256', 'value' => $digestHex]]],
        ]);
    }

    private function entry(string $kind, string $canonicalBody): TlogEntry
    {
        $rootHash = MerkleInclusion::leafHash($canonicalBody);

        return new TlogEntry(
            logIndex: 0,
            logId: $this->logId,
            kind: $kind,
            integratedTime: 1700000000,
            signedEntryTimestamp: null,
            inclusionProof: new InclusionProof(
                logIndex: 0,
                treeSize: 1,
                rootHash: $rootHash,
                hashes: [],
                checkpoint: $this->checkpoint($rootHash),
            ),
            canonicalizedBody: $canonicalBody,
        );
    }

    private function checkpoint(string $rootHash): Checkpoint
    {
        $body = "test-log\n1\n" . base64_encode($rootHash);
        $signature = $this->logKey->sign($body . "\n");
        $note = base64_encode("\x00\x00\x00\x00" . $signature);

        return new Checkpoint($body . "\n\n— test-log " . $note . "\n");
    }

    private function trustedRoot(): TrustedRoot
    {
        return new TrustedRoot(
            [new CertificateAuthority(certChainDer: [], validForStart: null, validForEnd: null)],
            [new TransparencyLogInstance($this->logId, $this->logKeyPem)],
        );
    }
}

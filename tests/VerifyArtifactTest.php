<?php

declare(strict_types=1);

namespace K2gl\Sigstore\Tests;

use K2gl\Sigstore\Bundle;
use K2gl\Sigstore\CertificateAuthority;
use K2gl\Sigstore\Checkpoint;
use K2gl\Sigstore\Exception\UnsupportedBundleException;
use K2gl\Sigstore\Exception\VerificationFailedException;
use K2gl\Sigstore\IdentityPolicy;
use K2gl\Sigstore\InclusionProof;
use K2gl\Sigstore\Internal\Asn1;
use K2gl\Sigstore\Internal\Certificate;
use K2gl\Sigstore\Internal\CertificateChainVerifier;
use K2gl\Sigstore\Internal\Ecdsa;
use K2gl\Sigstore\Internal\Json;
use K2gl\Sigstore\Internal\MerkleInclusion;
use K2gl\Sigstore\Internal\Pem;
use K2gl\Sigstore\Internal\RekorVerifier;
use K2gl\Sigstore\Internal\Sct;
use K2gl\Sigstore\Internal\SctVerifier;
use K2gl\Sigstore\Internal\TrustRootJson;
use K2gl\Sigstore\MessageSignature;
use K2gl\Sigstore\SigstoreVerifier;
use K2gl\Sigstore\TlogEntry;
use K2gl\Sigstore\TransparencyLogInstance;
use K2gl\Sigstore\TrustedRoot;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;

/**
 * End-to-end message-signature verification against a real public-good
 * conformance bundle (`cosign sign-blob`-style: a Fulcio certificate, a
 * signature over `a.txt`, and a hashedrekord Rekor entry with a full inclusion
 * proof and signed checkpoint). Exercises the whole pipeline — certificate
 * chain, artifact signature, Rekor inclusion proof + checkpoint signature, and
 * identity — against public-good trust material.
 */
#[CoversClass(SigstoreVerifier::class)]
#[CoversClass(Bundle::class)]
#[CoversClass(MessageSignature::class)]
#[CoversClass(TlogEntry::class)]
#[CoversClass(InclusionProof::class)]
#[CoversClass(Checkpoint::class)]
#[CoversClass(TrustedRoot::class)]
#[CoversClass(CertificateAuthority::class)]
#[CoversClass(TransparencyLogInstance::class)]
#[CoversClass(IdentityPolicy::class)]
#[CoversClass(Certificate::class)]
#[CoversClass(CertificateChainVerifier::class)]
#[CoversClass(RekorVerifier::class)]
#[CoversClass(MerkleInclusion::class)]
#[CoversClass(SctVerifier::class)]
#[CoversClass(Sct::class)]
#[CoversClass(Asn1::class)]
#[CoversClass(Ecdsa::class)]
#[CoversClass(Json::class)]
#[CoversClass(TrustRootJson::class)]
#[CoversClass(Pem::class)]
#[CoversClass(VerificationFailedException::class)]
#[CoversClass(UnsupportedBundleException::class)]
final class VerifyArtifactTest extends TestCase
{
    private const SAN = 'https://github.com/sigstore-conformance/extremely-dangerous-public-oidc-beacon/'
        . '.github/workflows/extremely-dangerous-oidc-beacon.yml@refs/heads/main';
    private const ISSUER = 'https://token.actions.githubusercontent.com';

    private function bundle(): Bundle
    {
        return Bundle::fromJson(self::fixture('conformance-msgsig-v0.3.json'));
    }

    private function artifact(): string
    {
        return self::fixture('conformance-artifact.txt');
    }

    private function trustedRoot(): TrustedRoot
    {
        return TrustedRoot::fromJson(self::fixture('trusted-root-public-good.json'));
    }

    private function policy(): IdentityPolicy
    {
        return new IdentityPolicy(self::SAN, self::ISSUER);
    }

    private static function fixture(string $name): string
    {
        $contents = file_get_contents(__DIR__ . '/fixtures/' . $name);
        self::assertIsString($contents);

        return $contents;
    }

    public function testVerifiesRealMessageSignatureBundle(): void
    {
        (new SigstoreVerifier())->verifyArtifact(
            bundle: $this->bundle(),
            artifact: $this->artifact(),
            trustedRoot: $this->trustedRoot(),
            identityPolicy: $this->policy(),
        );

        $this->addToAssertionCount(1);
    }

    public function testVerifyArtifactFromJson(): void
    {
        (new SigstoreVerifier())->verifyArtifactFromJson(
            bundleJson: self::fixture('conformance-msgsig-v0.3.json'),
            artifact: $this->artifact(),
            trustedRootJson: self::fixture('trusted-root-public-good.json'),
            identityPolicy: $this->policy(),
        );

        $this->addToAssertionCount(1);
    }

    public function testRejectsWrongArtifact(): void
    {
        $this->expectException(VerificationFailedException::class);
        (new SigstoreVerifier())->verifyArtifact(
            bundle: $this->bundle(),
            artifact: $this->artifact() . 'tampered',
            trustedRoot: $this->trustedRoot(),
            identityPolicy: $this->policy(),
        );
    }

    public function testRejectsWrongIdentity(): void
    {
        $this->expectException(VerificationFailedException::class);
        (new SigstoreVerifier())->verifyArtifact(
            bundle: $this->bundle(),
            artifact: $this->artifact(),
            trustedRoot: $this->trustedRoot(),
            identityPolicy: new IdentityPolicy('https://example.com/someone-else', self::ISSUER),
        );
    }

    public function testRejectsTamperedSignature(): void
    {
        $raw = json_decode(self::fixture('conformance-msgsig-v0.3.json'), true);
        self::assertIsArray($raw);

        $signature = base64_decode((string) $raw['messageSignature']['signature'], true);
        self::assertIsString($signature);
        $signature[8] = $signature[8] === "\x00" ? "\x01" : "\x00";
        $raw['messageSignature']['signature'] = base64_encode($signature);

        $this->expectException(VerificationFailedException::class);
        (new SigstoreVerifier())->verifyArtifact(
            bundle: Bundle::fromArray($raw),
            artifact: $this->artifact(),
            trustedRoot: $this->trustedRoot(),
            identityPolicy: $this->policy(),
        );
    }

    public function testVerifyArtifactRejectsDsseBundle(): void
    {
        $this->expectException(UnsupportedBundleException::class);
        (new SigstoreVerifier())->verifyArtifact(
            bundle: Bundle::fromJson(self::fixture('bundle-provenance.json')),
            artifact: $this->artifact(),
            trustedRoot: $this->trustedRoot(),
            identityPolicy: $this->policy(),
        );
    }
}

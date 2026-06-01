<?php

declare(strict_types=1);

namespace K2gl\Sigstore\Tests;

use function K2gl\PHPUnitFluentAssertions\fact;

use K2gl\Sigstore\Bundle;
use K2gl\Sigstore\CertificateAuthority;
use K2gl\Sigstore\Exception\UnsupportedBundleException;
use K2gl\Sigstore\Exception\VerificationFailedException;
use K2gl\Sigstore\IdentityPolicy;
use K2gl\Sigstore\Internal\Asn1;
use K2gl\Sigstore\Internal\Certificate;
use K2gl\Sigstore\Internal\CertificateChainVerifier;
use K2gl\Sigstore\Internal\Ecdsa;
use K2gl\Sigstore\Internal\Json;
use K2gl\Sigstore\Internal\OpensslVerifier;
use K2gl\Sigstore\Internal\Pem;
use K2gl\Sigstore\Internal\RekorVerifier;
use K2gl\Sigstore\Internal\Sct;
use K2gl\Sigstore\Internal\SctVerifier;
use K2gl\Sigstore\Internal\SignatureKey;
use K2gl\Sigstore\Internal\TrustRootJson;
use K2gl\Sigstore\SigstoreVerifier;
use K2gl\Sigstore\TlogEntry;
use K2gl\Sigstore\TransparencyLogInstance;
use K2gl\Sigstore\TrustedRoot;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;

/**
 * End-to-end verification against a real public-good Sigstore bundle (a SLSA
 * provenance attestation produced by sigstore-js) and the public-good trusted
 * root. This is the test that makes the verifier trustworthy: real Fulcio
 * certificate, real DSSE signature, real Rekor signed entry timestamp.
 */
#[CoversClass(SigstoreVerifier::class)]
#[CoversClass(Bundle::class)]
#[CoversClass(TlogEntry::class)]
#[CoversClass(TrustedRoot::class)]
#[CoversClass(CertificateAuthority::class)]
#[CoversClass(TransparencyLogInstance::class)]
#[CoversClass(IdentityPolicy::class)]
#[CoversClass(Certificate::class)]
#[CoversClass(CertificateChainVerifier::class)]
#[CoversClass(OpensslVerifier::class)]
#[CoversClass(SignatureKey::class)]
#[CoversClass(RekorVerifier::class)]
#[CoversClass(SctVerifier::class)]
#[CoversClass(Sct::class)]
#[CoversClass(Asn1::class)]
#[CoversClass(Ecdsa::class)]
#[CoversClass(Json::class)]
#[CoversClass(TrustRootJson::class)]
#[CoversClass(Pem::class)]
#[CoversClass(VerificationFailedException::class)]
#[CoversClass(UnsupportedBundleException::class)]
final class SigstoreVerifierTest extends TestCase
{
    private const SAN = 'https://github.com/sigstore/sigstore-js/.github/workflows/release.yml@refs/heads/main';
    private const ISSUER = 'https://token.actions.githubusercontent.com';

    private function bundle(): Bundle
    {
        return Bundle::fromJson(self::fixture('bundle-provenance.json'));
    }

    private function trustedRoot(): TrustedRoot
    {
        return TrustedRoot::fromJson(self::fixture('trusted-root-public-good.json'));
    }

    private static function fixture(string $name): string
    {
        $contents = file_get_contents(__DIR__ . '/fixtures/' . $name);
        self::assertIsString($contents);

        return $contents;
    }

    public function testVerifiesRealProvenanceBundle(): void
    {
        $envelope = (new SigstoreVerifier())->verify(
            bundle: $this->bundle(),
            trustedRoot: $this->trustedRoot(),
            identityPolicy: new IdentityPolicy(self::SAN, self::ISSUER),
        );

        fact($envelope->payloadType)->is('application/vnd.in-toto+json');

        $statement = json_decode($envelope->payload, true);
        fact(is_array($statement))->true();
        fact($statement['predicateType'])->is('https://slsa.dev/provenance/v0.2');
    }

    public function testRejectsWrongSan(): void
    {
        $this->expectException(VerificationFailedException::class);
        (new SigstoreVerifier())->verify(
            bundle: $this->bundle(),
            trustedRoot: $this->trustedRoot(),
            identityPolicy: new IdentityPolicy('https://example.com/not-the-signer', self::ISSUER),
        );
    }

    public function testRejectsWrongIssuer(): void
    {
        $this->expectException(VerificationFailedException::class);
        (new SigstoreVerifier())->verify(
            bundle: $this->bundle(),
            trustedRoot: $this->trustedRoot(),
            identityPolicy: new IdentityPolicy(self::SAN, 'https://accounts.google.com'),
        );
    }

    public function testRejectsTamperedPayload(): void
    {
        $raw = json_decode($this->fixture('bundle-provenance.json'), true);
        self::assertIsArray($raw);
        $raw['dsseEnvelope']['payload'] = base64_encode(
            '{"_type":"https://in-toto.io/Statement/v0.1","subject":[{"name":"x",'
            . '"digest":{"sha256":"00"}}],"predicateType":"https://slsa.dev/provenance/v0.2","predicate":{}}'
        );

        $this->expectException(VerificationFailedException::class);
        (new SigstoreVerifier())->verify(
            bundle: Bundle::fromArray($raw),
            trustedRoot: $this->trustedRoot(),
            identityPolicy: new IdentityPolicy(self::SAN, self::ISSUER),
        );
    }

    public function testRejectsWhenNoTrustedCaChains(): void
    {
        // A trusted root whose only CA chain (a single self-signed root) did not
        // issue this leaf: the chain cannot be built, so verification fails.
        $root = $this->trustedRoot();
        $onlyOldCa = new TrustedRoot([$root->certificateAuthorities[0]], $root->transparencyLogs);

        $this->expectException(VerificationFailedException::class);
        (new SigstoreVerifier())->verify(
            bundle: $this->bundle(),
            trustedRoot: $onlyOldCa,
            identityPolicy: new IdentityPolicy(self::SAN, self::ISSUER),
        );
    }

    public function testRejectsUnknownTransparencyLog(): void
    {
        // Replace the Rekor instance with one bearing a different log id: the
        // entry no longer matches any trusted log.
        $root = $this->trustedRoot();
        $stranger = new TransparencyLogInstance(str_repeat("\x00", 32), $root->transparencyLogs[0]->publicKeyPem);
        $rerooted = new TrustedRoot($root->certificateAuthorities, [$stranger]);

        $this->expectException(VerificationFailedException::class);
        (new SigstoreVerifier())->verify(
            bundle: $this->bundle(),
            trustedRoot: $rerooted,
            identityPolicy: new IdentityPolicy(self::SAN, self::ISSUER),
        );
    }

    public function testVerifyRejectsMessageSignatureBundle(): void
    {
        // verify() is for DSSE attestations; a message-signature bundle must go
        // through verifyArtifact().
        $this->expectException(UnsupportedBundleException::class);
        (new SigstoreVerifier())->verify(
            bundle: Bundle::fromJson($this->fixture('conformance-msgsig-v0.3.json')),
            trustedRoot: $this->trustedRoot(),
            identityPolicy: new IdentityPolicy(self::SAN, self::ISSUER),
        );
    }

    public function testVerifyFromJsonAcceptsTheRealBundle(): void
    {
        $envelope = (new SigstoreVerifier())->verifyFromJson(
            bundleJson: $this->fixture('bundle-provenance.json'),
            trustedRootJson: $this->fixture('trusted-root-public-good.json'),
            identityPolicy: new IdentityPolicy(self::SAN, self::ISSUER),
        );

        fact($envelope->payloadType)->is('application/vnd.in-toto+json');
    }

    public function testRejectsTamperedSignedEntryTimestamp(): void
    {
        $raw = json_decode($this->fixture('bundle-provenance.json'), true);
        self::assertIsArray($raw);

        $entry = &$raw['verificationMaterial']['tlogEntries'][0];
        $set = base64_decode((string) $entry['inclusionPromise']['signedEntryTimestamp'], true);
        self::assertIsString($set);
        $set[10] = $set[10] === "\x00" ? "\x01" : "\x00"; // flip a byte inside the signature
        $entry['inclusionPromise']['signedEntryTimestamp'] = base64_encode($set);

        $this->expectException(VerificationFailedException::class);
        (new SigstoreVerifier())->verify(
            bundle: Bundle::fromArray($raw),
            trustedRoot: $this->trustedRoot(),
            identityPolicy: new IdentityPolicy(self::SAN, self::ISSUER),
        );
    }

    public function testRejectsNonInTotoPayloadTypeAsUnsupported(): void
    {
        $raw = json_decode($this->fixture('bundle-provenance.json'), true);
        self::assertIsArray($raw);
        $raw['dsseEnvelope']['payloadType'] = 'application/vnd.dev.cosign.simplesigning.v1+json';

        $this->expectException(UnsupportedBundleException::class);
        (new SigstoreVerifier())->verify(
            bundle: Bundle::fromArray($raw),
            trustedRoot: $this->trustedRoot(),
            identityPolicy: new IdentityPolicy(self::SAN, self::ISSUER),
        );
    }
}

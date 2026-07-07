<?php

declare(strict_types=1);

namespace K2gl\Sigstore\Tests;

use K2gl\Sigstore\Bundle;
use K2gl\Sigstore\CertificateAuthority;
use K2gl\Sigstore\Exception\UnsupportedBundleException;
use K2gl\Sigstore\Exception\VerificationFailedException;
use K2gl\Sigstore\IdentityPolicy;
use K2gl\Sigstore\SubjectPolicy;
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

use function K2gl\PHPUnitFluentAssertions\fact;

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
#[CoversClass(SubjectPolicy::class)]
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
    private const BEACON_SAN = 'https://github.com/sigstore-conformance/extremely-dangerous-public-oidc-beacon/.github/workflows/extremely-dangerous-oidc-beacon.yml@refs/heads/main';

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
        fact($contents)->isString();

        return $contents;
    }

    public function testVerifiesRealProvenanceBundle(): void
    {
        $envelope = (new SigstoreVerifier)->verify(
            bundle: $this->bundle(),
            trustedRoot: $this->trustedRoot(),
            identityPolicy: new IdentityPolicy(self::SAN, self::ISSUER),
        );

        fact($envelope->payloadType)->is('application/vnd.in-toto+json');

        $statement = json_decode($envelope->payload, true);
        fact(is_array($statement))->true();
        fact($statement['predicateType'])->is('https://slsa.dev/provenance/v0.2');
    }

    public function testVerifiesWithMatchingSubjectPolicy(): void
    {
        $envelope = (new SigstoreVerifier)->verify(
            bundle: $this->bundle(),
            trustedRoot: $this->trustedRoot(),
            identityPolicy: new IdentityPolicy(self::SAN, self::ISSUER),
            subjectPolicy: new SubjectPolicy(
                'sha512',
                '76176ffa33808b54602c7c35de5c6e9a4deb96066dba6533f50ac234f4f1f4c6b3527515dc17c06fbe2860030f410eee69ea20079bd3a2c6f3dcf3b329b10751',
            ),
        );

        fact($envelope->payloadType)->is('application/vnd.in-toto+json');
    }

    public function testRejectsSubjectDigestNotInAttestation(): void
    {
        // act + assert
        fact(fn () => (new SigstoreVerifier)->verify(
            bundle: $this->bundle(),
            trustedRoot: $this->trustedRoot(),
            identityPolicy: new IdentityPolicy(self::SAN, self::ISSUER),
            subjectPolicy: new SubjectPolicy('sha512', str_repeat('0', 128)),
        ))->throws(VerificationFailedException::class);
    }

    public function testVerifiesRekorV2DsseAttestationBundle(): void
    {
        // A DSSE in-toto attestation whose Rekor v2 entry is a hashedrekord
        // (0.0.2): the log records the digest of the DSSE PAE, not the payload
        // digest a v1 dsse/intoto entry stores, and binds it to the envelope.
        // The entry carries no integrated time, so an RFC 3161 TSA stands in.
        $envelope = (new SigstoreVerifier)->verify(
            bundle: Bundle::fromJson(self::fixture('conformance-rekor2-dsse.json')),
            trustedRoot: TrustedRoot::fromJson(self::fixture('trusted-root-rekor2-dsse.json')),
            identityPolicy: new IdentityPolicy(self::BEACON_SAN, self::ISSUER),
        );

        fact($envelope->payloadType)->is('application/vnd.in-toto+json');
    }

    public function testRejectsTamperedRekorV2DsseEnvelope(): void
    {
        // arrange
        $raw = json_decode(self::fixture('conformance-rekor2-dsse.json'), true);
        fact($raw)->isArray();
        $raw['dsseEnvelope']['payload'] = base64_encode(
            '{"_type":"https://in-toto.io/Statement/v1","subject":[{"name":"x",'
            . '"digest":{"sha256":"00"}}],"predicateType":"https://slsa.dev/provenance/v1","predicate":{}}'
        );

        // act + assert
        fact(static fn () => (new SigstoreVerifier)->verify(
            bundle: Bundle::fromArray($raw),
            trustedRoot: TrustedRoot::fromJson(self::fixture('trusted-root-rekor2-dsse.json')),
            identityPolicy: new IdentityPolicy(self::BEACON_SAN, self::ISSUER),
        ))->throws(VerificationFailedException::class);
    }

    public function testRejectsWrongSan(): void
    {
        // act + assert
        fact(fn () => (new SigstoreVerifier)->verify(
            bundle: $this->bundle(),
            trustedRoot: $this->trustedRoot(),
            identityPolicy: new IdentityPolicy('https://example.com/not-the-signer', self::ISSUER),
        ))->throws(VerificationFailedException::class);
    }

    public function testRejectsWrongIssuer(): void
    {
        // act + assert
        fact(fn () => (new SigstoreVerifier)->verify(
            bundle: $this->bundle(),
            trustedRoot: $this->trustedRoot(),
            identityPolicy: new IdentityPolicy(self::SAN, 'https://accounts.google.com'),
        ))->throws(VerificationFailedException::class);
    }

    public function testRejectsTamperedPayload(): void
    {
        // arrange
        $raw = json_decode($this->fixture('bundle-provenance.json'), true);
        fact($raw)->isArray();
        $raw['dsseEnvelope']['payload'] = base64_encode(
            '{"_type":"https://in-toto.io/Statement/v0.1","subject":[{"name":"x",'
            . '"digest":{"sha256":"00"}}],"predicateType":"https://slsa.dev/provenance/v0.2","predicate":{}}'
        );

        // act + assert
        fact(fn () => (new SigstoreVerifier)->verify(
            bundle: Bundle::fromArray($raw),
            trustedRoot: $this->trustedRoot(),
            identityPolicy: new IdentityPolicy(self::SAN, self::ISSUER),
        ))->throws(VerificationFailedException::class);
    }

    public function testRejectsWhenNoTrustedCaChains(): void
    {
        // arrange
        // A trusted root whose only CA chain (a single self-signed root) did not
        // issue this leaf: the chain cannot be built, so verification fails.
        $root = $this->trustedRoot();
        $onlyOldCa = new TrustedRoot([$root->certificateAuthorities[0]], $root->transparencyLogs);

        // act + assert
        fact(fn () => (new SigstoreVerifier)->verify(
            bundle: $this->bundle(),
            trustedRoot: $onlyOldCa,
            identityPolicy: new IdentityPolicy(self::SAN, self::ISSUER),
        ))->throws(VerificationFailedException::class);
    }

    public function testRejectsUnknownTransparencyLog(): void
    {
        // arrange
        // Replace the Rekor instance with one bearing a different log id: the
        // entry no longer matches any trusted log.
        $root = $this->trustedRoot();
        $stranger = new TransparencyLogInstance(str_repeat("\x00", 32), $root->transparencyLogs[0]->publicKeyPem);
        $rerooted = new TrustedRoot($root->certificateAuthorities, [$stranger]);

        // act + assert
        fact(fn () => (new SigstoreVerifier)->verify(
            bundle: $this->bundle(),
            trustedRoot: $rerooted,
            identityPolicy: new IdentityPolicy(self::SAN, self::ISSUER),
        ))->throws(VerificationFailedException::class);
    }

    public function testVerifyRejectsMessageSignatureBundle(): void
    {
        // verify() is for DSSE attestations; a message-signature bundle must go
        // through verifyArtifact().
        // act + assert
        fact(fn () => (new SigstoreVerifier)->verify(
            bundle: Bundle::fromJson($this->fixture('conformance-msgsig-v0.3.json')),
            trustedRoot: $this->trustedRoot(),
            identityPolicy: new IdentityPolicy(self::SAN, self::ISSUER),
        ))->throws(UnsupportedBundleException::class);
    }

    public function testVerifyFromJsonAcceptsTheRealBundle(): void
    {
        $envelope = (new SigstoreVerifier)->verifyFromJson(
            bundleJson: $this->fixture('bundle-provenance.json'),
            trustedRootJson: $this->fixture('trusted-root-public-good.json'),
            identityPolicy: new IdentityPolicy(self::SAN, self::ISSUER),
        );

        fact($envelope->payloadType)->is('application/vnd.in-toto+json');
    }

    public function testRejectsTamperedSignedEntryTimestamp(): void
    {
        // arrange
        $raw = json_decode($this->fixture('bundle-provenance.json'), true);
        fact($raw)->isArray();

        $entry = &$raw['verificationMaterial']['tlogEntries'][0];
        $set = base64_decode((string) $entry['inclusionPromise']['signedEntryTimestamp'], true);
        fact($set)->isString();
        $set[10] = $set[10] === "\x00" ? "\x01" : "\x00"; // flip a byte inside the signature
        $entry['inclusionPromise']['signedEntryTimestamp'] = base64_encode($set);

        // act + assert
        fact(fn () => (new SigstoreVerifier)->verify(
            bundle: Bundle::fromArray($raw),
            trustedRoot: $this->trustedRoot(),
            identityPolicy: new IdentityPolicy(self::SAN, self::ISSUER),
        ))->throws(VerificationFailedException::class);
    }

    public function testRejectsNonInTotoPayloadTypeAsUnsupported(): void
    {
        // arrange
        $raw = json_decode($this->fixture('bundle-provenance.json'), true);
        fact($raw)->isArray();
        $raw['dsseEnvelope']['payloadType'] = 'application/vnd.dev.cosign.simplesigning.v1+json';

        // act + assert
        fact(fn () => (new SigstoreVerifier)->verify(
            bundle: Bundle::fromArray($raw),
            trustedRoot: $this->trustedRoot(),
            identityPolicy: new IdentityPolicy(self::SAN, self::ISSUER),
        ))->throws(UnsupportedBundleException::class);
    }
}

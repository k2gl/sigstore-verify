<?php

declare(strict_types=1);

namespace K2gl\Sigstore\Tests;

use function K2gl\PHPUnitFluentAssertions\fact;

use K2gl\Sigstore\Bundle;
use K2gl\Sigstore\CertificateAuthority;
use K2gl\Sigstore\Exception\VerificationFailedException;
use K2gl\Sigstore\IdentityPolicy;
use K2gl\Sigstore\Internal\Certificate;
use K2gl\Sigstore\Internal\CertificateChainVerifier;
use K2gl\Sigstore\Internal\Cms;
use K2gl\Sigstore\Internal\Ecdsa;
use K2gl\Sigstore\Internal\Pem;
use K2gl\Sigstore\Internal\Rfc3161Verifier;
use K2gl\Sigstore\Internal\TimeStampToken;
use K2gl\Sigstore\Internal\TrustRootJson;
use K2gl\Sigstore\Rfc3161Timestamp;
use K2gl\Sigstore\SigstoreVerifier;
use K2gl\Sigstore\TrustedRoot;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;

/**
 * RFC 3161 timestamp verification against real time-stamp tokens. The token and
 * its trusted root come from the sigstore conformance suite (a `sigstore-tsa`
 * timestamp over the public OIDC beacon's signature). The token is verified in
 * isolation — its bundle uses a Rekor v2 entry this version does not verify, so
 * the message-signature path is exercised here only for the timestamp.
 */
#[CoversClass(Rfc3161Timestamp::class)]
#[CoversClass(Rfc3161Verifier::class)]
#[CoversClass(Cms::class)]
#[CoversClass(TimeStampToken::class)]
#[CoversClass(CertificateAuthority::class)]
#[CoversClass(CertificateChainVerifier::class)]
#[CoversClass(Certificate::class)]
#[CoversClass(Ecdsa::class)]
#[CoversClass(Pem::class)]
#[CoversClass(TrustedRoot::class)]
#[CoversClass(TrustRootJson::class)]
#[CoversClass(Bundle::class)]
#[CoversClass(SigstoreVerifier::class)]
#[CoversClass(VerificationFailedException::class)]
final class Rfc3161TimestampTest extends TestCase
{
    private const GEN_TIME = '2025-08-06T18:51:36+00:00';

    private function trustedRoot(): TrustedRoot
    {
        return TrustedRoot::fromJson(self::fixture('trusted-root-tsa.json'));
    }

    private function timestamp(): Rfc3161Timestamp
    {
        $der = base64_decode($this->bundleField('timestampVerificationData', 'rfc3161Timestamps', 0, 'signedTimestamp'), true);
        fact($der)->isString();

        return new Rfc3161Timestamp($der);
    }

    private function signature(): string
    {
        $signature = base64_decode($this->signatureBase64(), true);
        fact($signature)->isString();

        return $signature;
    }

    public function testTrustedRootParsesTimestampAuthorities(): void
    {
        $authorities = $this->trustedRoot()->timestampAuthorities;

        fact($authorities)->count(1);
        fact($authorities[0]->certificates())->isNotEmptyArray();
    }

    public function testParsesTimeStampToken(): void
    {
        $token = Cms::parse($this->timestamp()->signedTimestamp);

        fact($token->contentTypeOid)->is('1.2.840.113549.1.9.16.1.4');
        fact($token->signatureAlgorithmOid)->is('1.2.840.10045.4.3.2');
        fact($token->genTime->format(DATE_ATOM))->is(self::GEN_TIME);
        fact($token->messageImprintHash)->is(hash('sha256', $this->signature(), true));
    }

    public function testVerifiesRealTimestamp(): void
    {
        $genTime = (new Rfc3161Verifier())->verify(
            timestamp: $this->timestamp(),
            signature: $this->signature(),
            timestampAuthorities: $this->trustedRoot()->timestampAuthorities,
        );

        fact($genTime->format(DATE_ATOM))->is(self::GEN_TIME);
    }

    public function testRejectsTamperedToken(): void
    {
        $der = $this->timestamp()->signedTimestamp;
        $der[strlen($der) - 1] = $der[strlen($der) - 1] === "\x00" ? "\x01" : "\x00";

        $this->expectException(VerificationFailedException::class);
        (new Rfc3161Verifier())->verify(
            timestamp: new Rfc3161Timestamp($der),
            signature: $this->signature(),
            timestampAuthorities: $this->trustedRoot()->timestampAuthorities,
        );
    }

    public function testRejectsSignatureItDoesNotCover(): void
    {
        // A different signature: the message imprint no longer matches.
        $this->expectException(VerificationFailedException::class);
        (new Rfc3161Verifier())->verify(
            timestamp: $this->timestamp(),
            signature: $this->signature() . "\x00",
            timestampAuthorities: $this->trustedRoot()->timestampAuthorities,
        );
    }

    public function testRejectsWhenNoTrustedTimestampAuthority(): void
    {
        $this->expectException(VerificationFailedException::class);
        (new Rfc3161Verifier())->verify(
            timestamp: $this->timestamp(),
            signature: $this->signature(),
            timestampAuthorities: [],
        );
    }

    public function testRejectsGenTimeOutsideAuthorityValidity(): void
    {
        // Same TSA certificate chain, but a validity window that ends before the
        // token's genTime: the authority no longer covers the signing time.
        $authority = $this->trustedRoot()->timestampAuthorities[0];
        $narrowed = new CertificateAuthority(
            certChainDer: $authority->certChainDer,
            validForStart: null,
            validForEnd: new \DateTimeImmutable('2025-05-01T00:00:00Z'),
        );

        $this->expectException(VerificationFailedException::class);
        (new Rfc3161Verifier())->verify(
            timestamp: $this->timestamp(),
            signature: $this->signature(),
            timestampAuthorities: [$narrowed],
        );
    }

    public function testBundleParsesNoTimestampsByDefault(): void
    {
        $bundle = Bundle::fromJson(self::fixture('conformance-msgsig-v0.3.json'));

        fact($bundle->rfc3161Timestamps)->isEmptyArray();
    }

    public function testVerifyArtifactEnforcesPresentTimestamp(): void
    {
        // Inject a real (but unrelated) timestamp into a bundle that otherwise
        // verifies: the token is from a TSA the trusted root does not anchor, so
        // a present timestamp that cannot be verified fails the whole check.
        $raw = json_decode(self::fixture('conformance-msgsig-v0.3.json'), true);
        fact($raw)->isArray();
        $raw['verificationMaterial']['timestampVerificationData']['rfc3161Timestamps'] = [
            ['signedTimestamp' => $this->signatureToken()],
        ];

        $bundle = Bundle::fromArray($raw);
        fact($bundle->rfc3161Timestamps)->count(1);

        $this->expectException(VerificationFailedException::class);
        (new SigstoreVerifier())->verifyArtifact(
            bundle: $bundle,
            artifact: self::fixture('conformance-artifact.txt'),
            trustedRoot: TrustedRoot::fromJson(self::fixture('trusted-root-public-good.json')),
            identityPolicy: new IdentityPolicy(
                'https://github.com/sigstore-conformance/extremely-dangerous-public-oidc-beacon/'
                . '.github/workflows/extremely-dangerous-oidc-beacon.yml@refs/heads/main',
                'https://token.actions.githubusercontent.com',
            ),
        );
    }

    private function signatureBase64(): string
    {
        $bundle = json_decode(self::fixture('bundle-tsa.json'), true);
        fact($bundle)->isArray();
        $value = $bundle['messageSignature']['signature'] ?? null;
        fact($value)->isString();

        return $value;
    }

    private function signatureToken(): string
    {
        return $this->bundleField('timestampVerificationData', 'rfc3161Timestamps', 0, 'signedTimestamp');
    }

    private function bundleField(string $tsData, string $list, int $index, string $field): string
    {
        $bundle = json_decode(self::fixture('bundle-tsa.json'), true);
        fact($bundle)->isArray();
        $value = $bundle['verificationMaterial'][$tsData][$list][$index][$field] ?? null;
        fact($value)->isString();

        return $value;
    }

    private static function fixture(string $name): string
    {
        $contents = file_get_contents(__DIR__ . '/fixtures/' . $name);
        fact($contents)->isString();

        return $contents;
    }
}

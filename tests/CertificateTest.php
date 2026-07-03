<?php

declare(strict_types=1);

namespace K2gl\Sigstore\Tests;

use K2gl\Sigstore\Internal\Asn1;
use K2gl\Sigstore\Internal\Certificate;
use K2gl\Sigstore\TrustedRoot;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

use function K2gl\PHPUnitFluentAssertions\fact;

/**
 * Reading the Fulcio OIDC issuer off a leaf certificate. Real public-good leaves
 * carry both the deprecated v1 extension (a bare string) and the v2 extension
 * (a DER UTF8String, OID …57264.1.8) that the Sigstore client spec says to read.
 */
#[CoversClass(Certificate::class)]
#[CoversClass(Asn1::class)]
final class CertificateTest extends TestCase
{
    private const EXPECTED_ISSUER = 'https://token.actions.githubusercontent.com';

    /** @return iterable<string, array{string}> */
    public static function realLeafFixtures(): iterable
    {
        yield 'provenance (x509 chain)' => ['bundle-provenance.json'];
        yield 'message-signature v0.3' => ['conformance-msgsig-v0.3.json'];
        yield 'rekor v2 dsse' => ['conformance-rekor2-dsse.json'];
    }

    #[DataProvider('realLeafFixtures')]
    public function testReadsOidcIssuerFromRealLeaf(string $fixture): void
    {
        fact($this->leaf($fixture)->oidcIssuer())->is(self::EXPECTED_ISSUER);
    }

    /**
     * The v2 extension wins over v1. Real certificates carry the same string in
     * both, so patch the v2 UTF8String to a distinct marker of equal length and
     * confirm that is what surfaces — proving the value came from v2, not the
     * untouched v1 extension.
     */
    public function testPrefersV2IssuerOverV1(): void
    {
        $der = $this->leafDer('bundle-provenance.json');
        $marker = substr(str_repeat('https://v2-issuer.example.test/', 4), 0, strlen(self::EXPECTED_ISSUER));

        $utf8String = "\x0c" . chr(strlen(self::EXPECTED_ISSUER)) . self::EXPECTED_ISSUER;
        $position = strpos($der, $utf8String);
        fact($position !== false)->true();

        $patched = substr_replace(
            $der,
            "\x0c" . chr(strlen($marker)) . $marker,
            (int) $position,
            strlen($utf8String),
        );

        fact(Certificate::fromDer($patched)->oidcIssuer())->is($marker);
    }

    public function testFallsBackToV1WhenV2Absent(): void
    {
        $der = $this->leafDer('bundle-provenance.json');

        // Break the v2 extension's OID so only v1 remains discoverable; the last
        // byte of …57264.1.8 is the arc "8", flip it so the OID no longer matches.
        $v2Oid = "\x06\x0a\x2b\x06\x01\x04\x01\x83\xbf\x30\x01\x08"; // OID 1.3.6.1.4.1.57264.1.8
        $position = strpos($der, $v2Oid);
        fact($position !== false)->true();

        $patched = $der[(int) $position + strlen($v2Oid) - 1] === "\x08"
            ? substr_replace($der, "\x07", (int) $position + strlen($v2Oid) - 1, 1)
            : $der;

        fact(Certificate::fromDer($patched)->oidcIssuer())->is(self::EXPECTED_ISSUER);
    }

    public function testReturnsNullWhenNoIssuerExtension(): void
    {
        fact($this->aCertificateAuthority()->oidcIssuer())->null();
    }

    #[DataProvider('realLeafFixtures')]
    public function testRealLeafIsValidForCodeSigning(string $fixture): void
    {
        fact($this->leaf($fixture)->hasCodeSigningExtendedKeyUsage())->true();
    }

    public function testCertificateAuthorityIsNotValidForCodeSigning(): void
    {
        fact($this->aCertificateAuthority()->hasCodeSigningExtendedKeyUsage())->false();
    }

    /** A root CA from the trusted root — no Fulcio issuer, no code-signing EKU. */
    private function aCertificateAuthority(): Certificate
    {
        foreach ($this->trustedRoot()->certificateAuthorities as $authority) {
            foreach ($authority->certificates() as $candidate) {
                if (! $candidate->hasCodeSigningExtendedKeyUsage()) {
                    return $candidate;
                }
            }
        }
        self::fail('No non-code-signing CA certificate in the trusted root.');
    }

    private function leaf(string $fixture): Certificate
    {
        return Certificate::fromDer($this->leafDer($fixture));
    }

    private function leafDer(string $fixture): string
    {
        $bundle = json_decode($this->fixture($fixture), true);
        fact($bundle)->isArray();
        $material = $bundle['verificationMaterial'];
        $raw = $material['certificate']['rawBytes']
            ?? $material['x509CertificateChain']['certificates'][0]['rawBytes'];
        fact($raw)->isString();
        $der = base64_decode($raw, true);
        fact($der)->isString();

        return $der;
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

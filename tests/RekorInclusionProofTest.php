<?php

declare(strict_types=1);

namespace K2gl\Sigstore\Tests;

use function K2gl\PHPUnitFluentAssertions\fact;

use K2gl\Sigstore\CertificateAuthority;
use K2gl\Sigstore\Checkpoint;
use K2gl\Sigstore\Exception\VerificationFailedException;
use K2gl\Sigstore\InclusionProof;
use K2gl\Sigstore\Internal\Ecdsa;
use K2gl\Sigstore\Internal\MerkleInclusion;
use K2gl\Sigstore\Internal\RekorVerifier;
use K2gl\Sigstore\TlogEntry;
use K2gl\Sigstore\TransparencyLogInstance;
use K2gl\Sigstore\TrustedRoot;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;

/**
 * Exercises the inclusion-proof path of {@see RekorVerifier} hermetically: a
 * freshly generated EC key plays the role of the log, signing a single-leaf
 * tree's checkpoint, so the Merkle recomputation, the checkpoint note signature
 * and the payload binding are all driven by real ECDSA — without depending on a
 * staging Rekor key.
 */
#[CoversClass(RekorVerifier::class)]
#[CoversClass(MerkleInclusion::class)]
#[CoversClass(Checkpoint::class)]
#[CoversClass(Ecdsa::class)]
#[CoversClass(TlogEntry::class)]
#[CoversClass(InclusionProof::class)]
#[CoversClass(TransparencyLogInstance::class)]
#[CoversClass(TrustedRoot::class)]
#[CoversClass(CertificateAuthority::class)]
#[CoversClass(VerificationFailedException::class)]
final class RekorInclusionProofTest extends TestCase
{
    private const PAYLOAD = 'the-attestation-payload';

    private \OpenSSLAsymmetricKey $logKey;
    private string $logId;
    private TrustedRoot $trustedRoot;
    private string $canonicalBody;
    private string $rootHash;

    protected function setUp(): void
    {
        $key = openssl_pkey_new(['private_key_type' => OPENSSL_KEYTYPE_EC, 'curve_name' => 'prime256v1']);
        fact($key)->instanceOf(\OpenSSLAsymmetricKey::class);
        $this->logKey = $key;

        $details = openssl_pkey_get_details($key);
        fact($details)->isArray();
        $publicKeyPem = $details['key'];

        $this->logId = random_bytes(32);
        $this->trustedRoot = new TrustedRoot(
            [new CertificateAuthority(certChainDer: [], validForStart: null, validForEnd: null)],
            [new TransparencyLogInstance($this->logId, $publicKeyPem)],
        );

        $this->canonicalBody = (string) json_encode([
            'kind' => 'intoto',
            'apiVersion' => '0.0.2',
            'spec' => ['content' => ['payloadHash' => [
                'algorithm' => 'sha256',
                'value' => hash('sha256', self::PAYLOAD),
            ]]],
        ]);
        // Single-leaf tree: the root is the leaf hash.
        $this->rootHash = MerkleInclusion::leafHash($this->canonicalBody);
    }

    private function checkpoint(string $rootHash): Checkpoint
    {
        $body = "test-log\n1\n" . base64_encode($rootHash);
        $signedBody = $body . "\n";
        openssl_sign($signedBody, $signature, $this->logKey, OPENSSL_ALGO_SHA256);
        $note = base64_encode("\x00\x00\x00\x00" . $signature);

        return new Checkpoint($body . "\n\n— test-log " . $note . "\n");
    }

    private function entry(string $rootHash, ?string $body = null): TlogEntry
    {
        return new TlogEntry(
            logIndex: 0,
            logId: $this->logId,
            kind: 'intoto',
            integratedTime: 1700000000,
            signedEntryTimestamp: null,
            inclusionProof: new InclusionProof(
                logIndex: 0,
                treeSize: 1,
                rootHash: $rootHash,
                hashes: [],
                checkpoint: $this->checkpoint($rootHash),
            ),
            canonicalizedBody: $body ?? $this->canonicalBody,
        );
    }

    public function testVerifiesInclusionProofPath(): void
    {
        (new RekorVerifier())->verify(
            entry: $this->entry($this->rootHash),
            trustedRoot: $this->trustedRoot,
            expectedHashHex: hash('sha256', self::PAYLOAD),
        );
        $this->addToAssertionCount(1);
    }

    public function testRejectsTamperedRoot(): void
    {
        $wrongRoot = strrev($this->rootHash);
        $this->expectException(VerificationFailedException::class);
        (new RekorVerifier())->verify(
            entry: $this->entry($wrongRoot),
            trustedRoot: $this->trustedRoot,
            expectedHashHex: hash('sha256', self::PAYLOAD),
        );
    }

    public function testRejectsPayloadBindingMismatch(): void
    {
        $this->expectException(VerificationFailedException::class);
        (new RekorVerifier())->verify(
            entry: $this->entry($this->rootHash),
            trustedRoot: $this->trustedRoot,
            expectedHashHex: hash('sha256', 'a-different-payload'),
        );
    }

    public function testRejectsCheckpointSignedByAnotherKey(): void
    {
        // A trusted root whose log key is unrelated to the checkpoint signer.
        $other = openssl_pkey_new(['private_key_type' => OPENSSL_KEYTYPE_EC, 'curve_name' => 'prime256v1']);
        fact($other)->instanceOf(\OpenSSLAsymmetricKey::class);
        $details = openssl_pkey_get_details($other);
        fact($details)->isArray();
        $foreignRoot = new TrustedRoot(
            [new CertificateAuthority(certChainDer: [], validForStart: null, validForEnd: null)],
            [new TransparencyLogInstance($this->logId, $details['key'])],
        );

        $this->expectException(VerificationFailedException::class);
        (new RekorVerifier())->verify(
            entry: $this->entry($this->rootHash),
            trustedRoot: $foreignRoot,
            expectedHashHex: hash('sha256', self::PAYLOAD),
        );
    }
}

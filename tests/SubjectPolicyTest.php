<?php

declare(strict_types=1);

namespace K2gl\Sigstore\Tests;

use K2gl\InToto\ResourceDescriptor;
use K2gl\InToto\Statement;
use K2gl\InToto\StatementVersion;
use K2gl\Sigstore\Exception\VerificationFailedException;
use K2gl\Sigstore\SubjectPolicy;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use InvalidArgumentException;

#[CoversClass(SubjectPolicy::class)]
#[CoversClass(VerificationFailedException::class)]
final class SubjectPolicyTest extends TestCase
{
    /** @param array<string, string> $digest */
    private function statement(array $digest): Statement
    {
        return new Statement(
            subject: [new ResourceDescriptor(name: 'artifact', digest: $digest)],
            predicateType: 'https://slsa.dev/provenance/v1',
            predicate: [],
            version: StatementVersion::V1,
        );
    }

    public function testAcceptsMatchingDigest(): void
    {
        $hex = str_repeat('ab', 32);
        (new SubjectPolicy('sha256', $hex))->verify($this->statement(['sha256' => $hex]));
        $this->addToAssertionCount(1);
    }

    public function testAcceptsDigestRegardlessOfCase(): void
    {
        $hex = str_repeat('ab', 32);
        (new SubjectPolicy('sha256', strtoupper($hex)))->verify($this->statement(['sha256' => $hex]));
        $this->addToAssertionCount(1);
    }

    public function testRejectsMissingDigest(): void
    {
        $this->expectException(VerificationFailedException::class);
        (new SubjectPolicy('sha256', str_repeat('ab', 32)))->verify($this->statement(['sha256' => str_repeat('cd', 32)]));
    }

    public function testRejectsDigestUnderAnotherAlgorithm(): void
    {
        $this->expectException(VerificationFailedException::class);
        (new SubjectPolicy('sha512', str_repeat('ab', 64)))->verify($this->statement(['sha256' => str_repeat('ab', 32)]));
    }

    public function testConstructorRejectsUnknownAlgorithm(): void
    {
        $this->expectException(InvalidArgumentException::class);
        new SubjectPolicy('md5', str_repeat('ab', 16));
    }

    public function testConstructorRejectsNonHexDigest(): void
    {
        $this->expectException(InvalidArgumentException::class);
        new SubjectPolicy('sha256', 'not-a-hex-digest');
    }
}

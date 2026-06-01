<?php

declare(strict_types=1);

namespace K2gl\Sigstore\Tests\Support;

/**
 * An Ed25519 key pair for building signed TUF metadata in tests, plus the
 * key-object and signing helpers the synthetic repository needs.
 */
final class SigningKey
{
    private function __construct(
        public readonly string $keyid,
        public readonly string $publicHex,
        private readonly string $secret,
    ) {}

    public static function generate(): self
    {
        $pair = sodium_crypto_sign_keypair();
        $public = sodium_crypto_sign_publickey($pair);

        return new self(
            keyid: hash('sha256', bin2hex($public)),
            publicHex: bin2hex($public),
            secret: sodium_crypto_sign_secretkey($pair),
        );
    }

    /** @return array<string, mixed> */
    public function keyObject(): array
    {
        return [
            'keytype' => 'ed25519',
            'scheme' => 'ed25519',
            'keyval' => ['public' => $this->publicHex],
        ];
    }

    /** Hex-encoded detached signature over the given bytes. */
    public function sign(string $message): string
    {
        \assert($this->secret !== '');

        return bin2hex(sodium_crypto_sign_detached($message, $this->secret));
    }
}

<?php

declare(strict_types=1);

namespace K2gl\Sigstore\Tests\Support;

use K2gl\Tuf\Internal\CanonicalJson;

/**
 * Low-level helper: wrap a `signed` payload into a fully signed TUF metadata
 * document, signing the canonical bytes with the given keys.
 */
final class Meta
{
    /** @param array<string, mixed> $signed */
    public static function document(array $signed, SigningKey ...$signers): string
    {
        $canonical = CanonicalJson::encode(self::toObjectTree($signed));
        $signatures = [];

        foreach ($signers as $signer) {
            $signatures[] = ['keyid' => $signer->keyid, 'sig' => $signer->sign($canonical)];
        }

        return self::json(['signed' => $signed, 'signatures' => $signatures]);
    }

    /** @param array<string, mixed> $value */
    public static function json(array $value): string
    {
        return json_encode($value, JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES);
    }

    public static function sha256(string $bytes): string
    {
        return hash('sha256', $bytes);
    }

    private static function toObjectTree(mixed $value): mixed
    {
        return json_decode(json_encode($value, JSON_THROW_ON_ERROR), false, flags: JSON_THROW_ON_ERROR);
    }
}

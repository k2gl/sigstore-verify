<?php

declare(strict_types=1);

namespace K2gl\Sigstore\Internal;

use K2gl\Sigstore\Exception\TrustRootException;
use DateTimeImmutable;
use Exception;
use JsonException;

/**
 * Strict field accessors for parsing trusted_root.json. Mirrors {@see Json} but
 * throws {@see TrustRootException}, and tolerates both the camelCase and
 * snake_case spellings that different Sigstore tools emit (for example
 * "certificateAuthorities" vs "certificate_authorities").
 *
 * @internal
 */
final class TrustRootJson
{
    /** @return array<string, mixed> */
    public static function decodeObject(string $json): array
    {
        try {
            /** @var mixed $data */
            $data = json_decode($json, true, 512, JSON_THROW_ON_ERROR);
        } catch (JsonException $e) {
            throw new TrustRootException('Trusted root is not valid JSON: ' . $e->getMessage(), previous: $e);
        }

        if (! is_array($data) || array_is_list($data)) {
            throw new TrustRootException('Trusted root must be a JSON object.');
        }

        /** @var array<string, mixed> $data */
        return $data;
    }

    /**
     * Read a value under any of the given key spellings.
     *
     * @param array<string, mixed> $data
     */
    private static function pick(array $data, string ...$keys): mixed
    {
        foreach ($keys as $key) {
            if (array_key_exists($key, $data)) {
                return $data[$key];
            }
        }

        return null;
    }

    /** @param array<string, mixed> $data */
    public static function string(array $data, string ...$keys): string
    {
        $value = self::pick($data, ...$keys);

        if (! is_string($value) || $value === '') {
            throw new TrustRootException(sprintf('Missing trusted-root string field "%s".', $keys[0]));
        }

        return $value;
    }

    /**
     * @param  array<string, mixed> $data
     * @return array<string, mixed>
     */
    public static function object(array $data, string ...$keys): array
    {
        $value = self::pick($data, ...$keys);

        if (! is_array($value) || array_is_list($value) && $value !== []) {
            throw new TrustRootException(sprintf('Trusted-root field "%s" must be a JSON object.', $keys[0]));
        }

        /** @var array<string, mixed> $value */
        return $value;
    }

    /**
     * @param  array<string, mixed> $data
     * @return list<mixed>
     */
    public static function list(array $data, string ...$keys): array
    {
        $value = self::pick($data, ...$keys);

        if (! is_array($value) || ! array_is_list($value)) {
            throw new TrustRootException(sprintf('Trusted-root field "%s" must be a JSON array.', $keys[0]));
        }

        return $value;
    }

    /** @param array<string, mixed> $data */
    public static function base64(array $data, string ...$keys): string
    {
        $value = self::pick($data, ...$keys);

        if (! is_string($value) || $value === '') {
            throw new TrustRootException(sprintf('Missing trusted-root base64 field "%s".', $keys[0]));
        }
        $decoded = base64_decode($value, true);

        if ($decoded === false) {
            throw new TrustRootException(sprintf('Trusted-root field "%s" is not valid base64.', $keys[0]));
        }

        return $decoded;
    }

    /** @param array<string, mixed> $data */
    public static function dateOrNull(array $data, string ...$keys): ?DateTimeImmutable
    {
        $value = self::pick($data, ...$keys);

        if ($value === null) {
            return null;
        }

        if (! is_string($value)) {
            throw new TrustRootException(sprintf('Trusted-root field "%s" must be an RFC 3339 timestamp.', $keys[0]));
        }
        try {
            return new DateTimeImmutable($value);
        } catch (Exception $e) {
            throw new TrustRootException(sprintf('Trusted-root field "%s" is not a valid timestamp.', $keys[0]), previous: $e);
        }
    }
}

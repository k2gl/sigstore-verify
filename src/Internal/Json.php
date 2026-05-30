<?php

declare(strict_types=1);

namespace K2gl\Sigstore\Internal;

use K2gl\Sigstore\Exception\InvalidBundleException;

/**
 * Small, strict JSON field accessors for parsing Sigstore bundles. Every getter
 * throws {@see InvalidBundleException} when the field is missing or has the
 * wrong shape, so bundle parsing fails closed.
 *
 * Sigstore encodes 64-bit integers (log index, integrated time, tree size) as
 * JSON strings; {@see self::int()} accepts both strings and native integers.
 *
 * @internal
 */
final class Json
{
    /** @return array<string, mixed> */
    public static function decodeObject(string $json): array
    {
        try {
            /** @var mixed $data */
            $data = json_decode($json, true, 512, JSON_THROW_ON_ERROR);
        } catch (\JsonException $e) {
            throw new InvalidBundleException('Bundle is not valid JSON: ' . $e->getMessage(), previous: $e);
        }
        if (!is_array($data) || array_is_list($data)) {
            throw new InvalidBundleException('Bundle must be a JSON object.');
        }
        /** @var array<string, mixed> $data */
        return $data;
    }

    /** @param array<mixed> $data */
    public static function string(array $data, string $key): string
    {
        $value = $data[$key] ?? null;
        if (!is_string($value) || $value === '') {
            throw new InvalidBundleException(sprintf('Missing or empty string field "%s".', $key));
        }
        return $value;
    }

    /** @param array<mixed> $data */
    public static function int(array $data, string $key): int
    {
        $value = $data[$key] ?? null;
        if (is_int($value)) {
            return $value;
        }
        if (is_string($value) && preg_match('/^-?\d+$/', $value) === 1) {
            return (int) $value;
        }
        throw new InvalidBundleException(sprintf('Field "%s" must be an integer.', $key));
    }

    /**
     * @param  array<mixed>          $data
     * @return array<string, mixed>
     */
    public static function object(array $data, string $key): array
    {
        $value = $data[$key] ?? null;
        if (!is_array($value) || array_is_list($value) && $value !== []) {
            throw new InvalidBundleException(sprintf('Field "%s" must be a JSON object.', $key));
        }
        /** @var array<string, mixed> $value */
        return $value;
    }

    /**
     * @param  array<mixed>  $data
     * @return list<mixed>
     */
    public static function list(array $data, string $key): array
    {
        $value = $data[$key] ?? null;
        if (!is_array($value) || !array_is_list($value)) {
            throw new InvalidBundleException(sprintf('Field "%s" must be a JSON array.', $key));
        }
        return $value;
    }

    /**
     * Decode a required base64 field into raw bytes.
     *
     * @param array<mixed> $data
     */
    public static function base64(array $data, string $key): string
    {
        $value = $data[$key] ?? null;
        if (!is_string($value) || $value === '') {
            throw new InvalidBundleException(sprintf('Missing or empty base64 field "%s".', $key));
        }
        $decoded = base64_decode($value, true);
        if ($decoded === false) {
            throw new InvalidBundleException(sprintf('Field "%s" is not valid base64.', $key));
        }
        return $decoded;
    }
}

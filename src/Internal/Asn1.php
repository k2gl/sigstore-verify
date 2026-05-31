<?php

declare(strict_types=1);

namespace K2gl\Sigstore\Internal;

use K2gl\Sigstore\Exception\UnsupportedBundleException;
use K2gl\Sigstore\Exception\VerificationFailedException;

/**
 * A tiny definite-length DER reader for the few places phpseclib does not reach:
 * walking a certificate's TBS to verify its embedded Signed Certificate
 * Timestamps. It reads one TLV at a time, lists the direct children of a
 * constructed value, decodes OBJECT IDENTIFIERs, and re-encodes a definite-form
 * length so callers can rebuild a structure with one element removed.
 *
 * Malformed input throws {@see VerificationFailedException}; well-formed but
 * unsupported encodings (multi-byte tags) throw {@see UnsupportedBundleException},
 * so untrusted bytes are never silently accepted.
 *
 * @phpstan-type Tlv array{class:int, constructed:bool, tag:int, start:int, headerLen:int, length:int, contentStart:int, contentLen:int}
 *
 * @internal
 */
final class Asn1
{
    public const CLASS_UNIVERSAL = 0;
    public const CLASS_CONTEXT = 2;

    public const TAG_BOOLEAN = 0x01;
    public const TAG_OID = 0x06;
    public const TAG_OCTET_STRING = 0x04;
    public const TAG_SEQUENCE = 0x10;

    /**
     * Read one DER TLV header at the given offset (definite length only).
     *
     * @return Tlv
     */
    public static function read(string $der, int $offset): array
    {
        $size = strlen($der);

        if ($offset + 2 > $size) {
            throw new VerificationFailedException('Truncated DER value.');
        }
        $tagByte = ord($der[$offset]);

        if (($tagByte & 0x1F) === 0x1F) {
            throw new UnsupportedBundleException('Multi-byte ASN.1 tags are not supported.');
        }
        $position = $offset + 1;
        $firstLengthByte = ord($der[$position]);
        $position++;

        if ($firstLengthByte < 0x80) {
            $contentLength = $firstLengthByte;
        } else {
            $lengthBytes = $firstLengthByte & 0x7F;

            if ($lengthBytes === 0 || $lengthBytes > 4 || $position + $lengthBytes > $size) {
                throw new VerificationFailedException('Unsupported or truncated DER length.');
            }
            $contentLength = 0;

            for ($i = 0; $i < $lengthBytes; $i++) {
                $contentLength = ($contentLength << 8) | ord($der[$position + $i]);
            }
            $position += $lengthBytes;
        }
        $headerLength = $position - $offset;

        if ($position + $contentLength > $size) {
            throw new VerificationFailedException('DER value content runs past its end.');
        }

        return [
            'class' => ($tagByte & 0xC0) >> 6,
            'constructed' => ($tagByte & 0x20) !== 0,
            'tag' => $tagByte & 0x1F,
            'start' => $offset,
            'headerLen' => $headerLength,
            'length' => $headerLength + $contentLength,
            'contentStart' => $position,
            'contentLen' => $contentLength,
        ];
    }

    /**
     * The direct children of a constructed value.
     *
     * @param  Tlv $node
     * @return list<Tlv>
     */
    public static function children(string $der, array $node): array
    {
        if (!$node['constructed']) {
            throw new VerificationFailedException('Expected a constructed ASN.1 value.');
        }
        $children = [];
        $position = $node['contentStart'];
        $end = $node['contentStart'] + $node['contentLen'];

        while ($position < $end) {
            $child = self::read($der, $position);
            $children[] = $child;
            $position += $child['length'];
        }

        return $children;
    }

    /** The dotted OBJECT IDENTIFIER string from a node's content bytes. */
    public static function decodeOid(string $bytes): string
    {
        $length = strlen($bytes);

        if ($length === 0) {
            throw new VerificationFailedException('Empty OBJECT IDENTIFIER.');
        }
        $subIdentifiers = [];
        $value = 0;
        $pending = false;

        for ($i = 0; $i < $length; $i++) {
            $byte = ord($bytes[$i]);
            $value = ($value << 7) | ($byte & 0x7F);
            $pending = true;

            if (($byte & 0x80) === 0) {
                $subIdentifiers[] = $value;
                $value = 0;
                $pending = false;
            }
        }

        if ($pending) {
            throw new VerificationFailedException('Malformed OBJECT IDENTIFIER.');
        }
        $first = $subIdentifiers[0];

        if ($first < 80) {
            $arcs = [intdiv($first, 40), $first % 40];
        } else {
            $arcs = [2, $first - 80];
        }

        foreach (array_slice($subIdentifiers, 1) as $sub) {
            $arcs[] = $sub;
        }

        return implode('.', array_map(strval(...), $arcs));
    }

    /** Encode a definite-form DER length, used to rebuild a structure. */
    public static function encodeLength(int $length): string
    {
        if ($length < 0x80) {
            return chr($length);
        }
        $bytes = '';

        while ($length > 0) {
            $bytes = chr($length & 0xFF) . $bytes;
            $length >>= 8;
        }

        return chr(0x80 | strlen($bytes)) . $bytes;
    }
}

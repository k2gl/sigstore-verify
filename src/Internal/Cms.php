<?php

declare(strict_types=1);

namespace K2gl\Sigstore\Internal;

use K2gl\Sigstore\Exception\UnsupportedBundleException;
use K2gl\Sigstore\Exception\VerificationFailedException;

/**
 * Parses an RFC 3161 time-stamp token — a CMS {@see https://www.rfc-editor.org/rfc/rfc5652 SignedData}
 * wrapping a TSTInfo — into the handful of fields {@see Rfc3161Verifier} needs.
 *
 * phpseclib has no CMS verifier, so this walks the DER directly with a tiny
 * definite-length reader. It extracts the eContent (the TSTInfo), the signer's
 * signature and algorithm, the signed attributes re-encoded as the SET the TSA
 * actually signed, and — from the TSTInfo — the message imprint and genTime.
 * Anything malformed throws {@see VerificationFailedException}; anything
 * well-formed but unsupported throws {@see UnsupportedBundleException}, so a
 * token is never silently accepted.
 *
 * @phpstan-type Tlv array{class:int, constructed:bool, tag:int, start:int, headerLen:int, length:int, contentStart:int, contentLen:int}
 *
 * @internal
 */
final class Cms
{
    private const OID_SIGNED_DATA = '1.2.840.113549.1.7.2';
    private const OID_TST_INFO = '1.2.840.113549.1.9.16.1.4';
    private const OID_ATTR_CONTENT_TYPE = '1.2.840.113549.1.9.3';
    private const OID_ATTR_MESSAGE_DIGEST = '1.2.840.113549.1.9.4';

    private const CLASS_UNIVERSAL = 0;
    private const CLASS_CONTEXT = 2;

    private const TAG_OCTET_STRING = 0x04;
    private const TAG_OID = 0x06;
    private const TAG_SEQUENCE = 0x10;
    private const TAG_SET = 0x11;
    private const TAG_GENERALIZED_TIME = 0x18;

    /** @throws VerificationFailedException|UnsupportedBundleException */
    public static function parse(string $tokenDer): TimeStampToken
    {
        // The token may be a bare ContentInfo or a TimeStampResp wrapping one.
        // ContentInfo ::= SEQUENCE { contentType OID, content [0] EXPLICIT SignedData }
        $contentInfo = self::children($tokenDer, self::locateContentInfo($tokenDer));

        $signedData = self::children($tokenDer, self::at(
            self::children($tokenDer, self::at($contentInfo, 1, 'SignedData wrapper')),
            0,
            'SignedData',
        ));

        $encapContentInfo = self::find($signedData, self::CLASS_UNIVERSAL, self::TAG_SEQUENCE, first: true);
        $signerInfos = self::find($signedData, self::CLASS_UNIVERSAL, self::TAG_SET, first: false);

        if ($encapContentInfo === null || $signerInfos === null) {
            throw new VerificationFailedException('SignedData is missing encapContentInfo or signerInfos.');
        }

        $tstInfoDer = self::eContent($tokenDer, $encapContentInfo);
        $signer = self::signerInfo($tokenDer, self::at(self::children($tokenDer, $signerInfos), 0, 'SignerInfo'));
        $imprint = self::messageImprint($tstInfoDer);

        return new TimeStampToken(
            signedAttributes: $signer['signedAttributes'],
            signature: $signer['signature'],
            signatureAlgorithmOid: $signer['signatureAlgorithmOid'],
            digestAlgorithmOid: $signer['digestAlgorithmOid'],
            tstInfoDer: $tstInfoDer,
            contentTypeOid: $signer['contentTypeOid'],
            messageDigest: $signer['messageDigest'],
            messageImprintHashOid: $imprint['hashOid'],
            messageImprintHash: $imprint['hash'],
            genTime: self::genTime($tstInfoDer),
        );
    }

    /**
     * Locate the CMS SignedData ContentInfo, whether the token is a bare
     * ContentInfo or a TimeStampResp { PKIStatusInfo, timeStampToken } wrapping it.
     *
     * @return Tlv
     */
    private static function locateContentInfo(string $der): array
    {
        $outer = self::read($der, 0);

        if (self::isSignedDataContentInfo($der, $outer)) {
            return $outer;
        }

        foreach (self::children($der, $outer) as $child) {
            if (self::isSignedDataContentInfo($der, $child)) {
                return $child;
            }
        }

        throw new UnsupportedBundleException('Time-stamp token is not a CMS SignedData.');
    }

    /** @param Tlv $node */
    private static function isSignedDataContentInfo(string $der, array $node): bool
    {
        if ($node['class'] !== self::CLASS_UNIVERSAL || $node['tag'] !== self::TAG_SEQUENCE) {
            return false;
        }
        $first = self::children($der, $node)[0] ?? null;

        if ($first === null || $first['class'] !== self::CLASS_UNIVERSAL || $first['tag'] !== self::TAG_OID) {
            return false;
        }

        return self::decodeOid(substr($der, $first['contentStart'], $first['contentLen'])) === self::OID_SIGNED_DATA;
    }

    /**
     * The DER-encoded TSTInfo carried in encapContentInfo's eContent.
     *
     * @param Tlv $encapContentInfo
     */
    private static function eContent(string $der, array $encapContentInfo): string
    {
        $children = self::children($der, $encapContentInfo);

        if (self::oid($der, self::at($children, 0, 'eContentType')) !== self::OID_TST_INFO) {
            throw new UnsupportedBundleException('Time-stamp token does not wrap a TSTInfo.');
        }
        $octet = self::at(self::children($der, self::at($children, 1, 'eContent wrapper')), 0, 'eContent');

        return self::octetString($der, $octet, 'eContent');
    }

    /**
     * @param  Tlv $signerInfo
     * @return array{signedAttributes:string, signature:string, signatureAlgorithmOid:string, digestAlgorithmOid:string, contentTypeOid:?string, messageDigest:?string}
     */
    private static function signerInfo(string $der, array $signerInfo): array
    {
        $fields = self::children($der, $signerInfo);

        // version, sid, digestAlgorithm, [signedAttrs], signatureAlgorithm, signature, [unsignedAttrs]
        $digestAlgorithmOid = self::oid($der, self::at(self::children($der, self::at($fields, 2, 'digestAlgorithm')), 0, 'digestAlgorithm OID'));

        $index = 3;
        $signedAttrs = self::at($fields, $index, 'signedAttrs');

        if ($signedAttrs['class'] !== self::CLASS_CONTEXT || $signedAttrs['tag'] !== 0) {
            throw new VerificationFailedException('Time-stamp token has no signed attributes.');
        }
        $index++;

        $contentTypeOid = null;
        $messageDigest = null;

        foreach (self::children($der, $signedAttrs) as $attribute) {
            $parts = self::children($der, $attribute);
            $attrOid = self::oid($der, self::at($parts, 0, 'attribute type'));
            $value = self::children($der, self::at($parts, 1, 'attribute values'))[0] ?? null;

            if ($value === null) {
                continue;
            }

            if ($attrOid === self::OID_ATTR_CONTENT_TYPE) {
                $contentTypeOid = self::oid($der, $value);
            } elseif ($attrOid === self::OID_ATTR_MESSAGE_DIGEST) {
                $messageDigest = self::octetString($der, $value, 'message-digest attribute');
            }
        }

        $signatureAlgorithm = self::at($fields, $index++, 'signatureAlgorithm');
        $signatureAlgorithmOid = self::oid($der, self::at(self::children($der, $signatureAlgorithm), 0, 'signatureAlgorithm OID'));
        $signature = self::octetString($der, self::at($fields, $index, 'signature'), 'signature');

        // The signer signs the signed attributes encoded as a SET OF; the token
        // carries them under an implicit [0] tag, so swap the tag byte back.
        $raw = substr($der, $signedAttrs['start'], $signedAttrs['length']);

        return [
            'signedAttributes' => "\x31" . substr($raw, 1),
            'signature' => $signature,
            'signatureAlgorithmOid' => $signatureAlgorithmOid,
            'digestAlgorithmOid' => $digestAlgorithmOid,
            'contentTypeOid' => $contentTypeOid,
            'messageDigest' => $messageDigest,
        ];
    }

    /** @return array{hashOid:string, hash:string} */
    private static function messageImprint(string $tstInfoDer): array
    {
        $fields = self::children($tstInfoDer, self::read($tstInfoDer, 0));
        $imprint = self::find($fields, self::CLASS_UNIVERSAL, self::TAG_SEQUENCE, first: true);

        if ($imprint === null) {
            throw new VerificationFailedException('TSTInfo has no messageImprint.');
        }
        $parts = self::children($tstInfoDer, $imprint);
        $hashOid = self::oid($tstInfoDer, self::at(self::children($tstInfoDer, self::at($parts, 0, 'imprint algorithm')), 0, 'imprint algorithm OID'));
        $hash = self::octetString($tstInfoDer, self::at($parts, 1, 'imprint hash'), 'messageImprint');

        return [
            'hashOid' => $hashOid,
            'hash' => $hash,
        ];
    }

    private static function genTime(string $tstInfoDer): \DateTimeImmutable
    {
        $fields = self::children($tstInfoDer, self::read($tstInfoDer, 0));
        $node = self::find($fields, self::CLASS_UNIVERSAL, self::TAG_GENERALIZED_TIME, first: true);

        if ($node === null) {
            throw new VerificationFailedException('TSTInfo has no genTime.');
        }
        $value = substr($tstInfoDer, $node['contentStart'], $node['contentLen']);

        if (preg_match('/^(\d{14})(?:\.\d+)?Z$/', $value, $matches) !== 1) {
            throw new UnsupportedBundleException('Unsupported TSTInfo genTime format.');
        }
        $time = \DateTimeImmutable::createFromFormat('!YmdHis', $matches[1], new \DateTimeZone('UTC'));

        if ($time === false) {
            throw new VerificationFailedException('Invalid TSTInfo genTime.');
        }

        return $time;
    }

    /**
     * The first (or last) direct child of the given class and universal tag.
     *
     * @param  list<Tlv> $nodes
     * @return Tlv|null
     */
    private static function find(array $nodes, int $class, int $tag, bool $first): ?array
    {
        $match = null;

        foreach ($nodes as $node) {
            if ($node['class'] === $class && $node['tag'] === $tag) {
                $match = $node;

                if ($first) {
                    return $match;
                }
            }
        }

        return $match;
    }

    /**
     * @param  list<Tlv> $nodes
     * @return Tlv
     */
    private static function at(array $nodes, int $index, string $what): array
    {
        return $nodes[$index] ?? throw new VerificationFailedException(
            sprintf('Time-stamp token is missing %s.', $what),
        );
    }

    /** @param Tlv $node */
    private static function octetString(string $der, array $node, string $what): string
    {
        if ($node['class'] !== self::CLASS_UNIVERSAL || $node['tag'] !== self::TAG_OCTET_STRING) {
            throw new VerificationFailedException(sprintf('Time-stamp token %s is not an OCTET STRING.', $what));
        }

        return substr($der, $node['contentStart'], $node['contentLen']);
    }

    /** @param Tlv $node */
    private static function oid(string $der, array $node): string
    {
        if ($node['class'] !== self::CLASS_UNIVERSAL || $node['tag'] !== self::TAG_OID) {
            throw new VerificationFailedException('Expected an OBJECT IDENTIFIER in the time-stamp token.');
        }

        return self::decodeOid(substr($der, $node['contentStart'], $node['contentLen']));
    }

    /**
     * Parse the direct children of a constructed value.
     *
     * @param  Tlv $node
     * @return list<Tlv>
     */
    private static function children(string $der, array $node): array
    {
        if (!$node['constructed']) {
            throw new VerificationFailedException('Expected a constructed ASN.1 value in the time-stamp token.');
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

    /**
     * Read one DER TLV header at the given offset (definite length only).
     *
     * @return Tlv
     */
    private static function read(string $der, int $offset): array
    {
        $size = strlen($der);

        if ($offset + 2 > $size) {
            throw new VerificationFailedException('Truncated time-stamp token.');
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
            throw new VerificationFailedException('Time-stamp token content runs past its end.');
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

    private static function decodeOid(string $bytes): string
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
}

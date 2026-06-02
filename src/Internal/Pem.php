<?php

declare(strict_types=1);

namespace K2gl\Sigstore\Internal;

/**
 * Wraps raw DER bytes in a PEM envelope so they can be handed to ext-openssl
 * and phpseclib.
 *
 * @internal
 */
final class Pem
{
    public static function fromDer(string $der, string $label): string
    {
        return "-----BEGIN {$label}-----\n"
            . chunk_split(base64_encode($der), 64, "\n")
            . "-----END {$label}-----\n";
    }

    /**
     * Extract the DER bytes from a PEM block (the base64 between the BEGIN/END
     * lines), or null if the input is not a PEM block.
     */
    public static function toDer(string $pem): ?string
    {
        if (preg_match('/-----BEGIN [^-]+-----(.+?)-----END [^-]+-----/s', $pem, $matches) !== 1) {
            return null;
        }
        $der = base64_decode(preg_replace('/\s+/', '', $matches[1]) ?? '', true);

        return $der === false || $der === '' ? null : $der;
    }
}

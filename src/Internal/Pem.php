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
}

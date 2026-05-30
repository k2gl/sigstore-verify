<?php

declare(strict_types=1);

namespace K2gl\Sigstore\Exception;

/**
 * The supplied trusted root (trusted_root.json) is malformed or cannot be used:
 * not valid JSON, missing certificate authorities or transparency logs, or
 * containing an unreadable certificate or key.
 */
final class TrustRootException extends \RuntimeException implements SigstoreException
{
}

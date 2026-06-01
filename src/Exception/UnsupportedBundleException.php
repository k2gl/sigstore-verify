<?php

declare(strict_types=1);

namespace K2gl\Sigstore\Exception;

use RuntimeException;

/**
 * The bundle is well-formed but uses a feature this version does not verify
 * (for example a message-signature artifact bundle, a non-P-256 key, or a
 * Rekor entry kind we cannot bind). Thrown rather than silently skipped: an
 * unsupported input is never reported as "verified".
 */
final class UnsupportedBundleException extends RuntimeException implements SigstoreException {}

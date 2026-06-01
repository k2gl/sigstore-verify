<?php

declare(strict_types=1);

namespace K2gl\Sigstore\Exception;

use RuntimeException;

/**
 * The Sigstore bundle is malformed: not valid JSON, missing required fields, or
 * structurally inconsistent. The input could not be understood as a bundle.
 */
final class InvalidBundleException extends RuntimeException implements SigstoreException {}

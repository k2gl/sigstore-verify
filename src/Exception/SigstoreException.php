<?php

declare(strict_types=1);

namespace K2gl\Sigstore\Exception;

use Throwable;

/**
 * Marker interface implemented by every exception thrown by this package, so a
 * caller can treat any verification problem with a single catch block.
 *
 * The verifier is fail-closed: a thrown {@see SigstoreException} always means
 * "not verified". It never returns a result on the unhappy path.
 */
interface SigstoreException extends Throwable {}

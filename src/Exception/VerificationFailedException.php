<?php

declare(strict_types=1);

namespace K2gl\Sigstore\Exception;

/**
 * A verification step failed: the certificate did not chain to a trusted Fulcio
 * root, the DSSE signature did not verify, the Rekor inclusion proof or signed
 * entry timestamp was invalid, or the certificate identity did not match the
 * policy. The bundle is not trustworthy.
 */
final class VerificationFailedException extends \RuntimeException implements SigstoreException
{
}

<?php

declare(strict_types=1);

namespace K2gl\Sigstore;

use K2gl\Sigstore\Internal\Certificate;
use K2gl\Sigstore\Internal\TrustRootJson;

/**
 * A certificate authority (Fulcio) from the trusted root: its certificate chain
 * (intermediates and root) and the time window during which it was a valid
 * issuer. A leaf certificate is trusted only if it chains to one of these and
 * the signing time falls inside the window.
 */
final class CertificateAuthority
{
    /** @var list<Certificate>|null */
    private ?array $certificates = null;

    /** @param list<string> $certChainDer DER certificates, leaf-most first, root last */
    public function __construct(
        public readonly array $certChainDer,
        public readonly ?\DateTimeImmutable $validForStart,
        public readonly ?\DateTimeImmutable $validForEnd,
    ) {
    }

    /** @param array<string, mixed> $data */
    public static function fromArray(array $data): self
    {
        $certChain = TrustRootJson::object($data, 'certChain', 'cert_chain');

        $der = [];
        foreach (TrustRootJson::list($certChain, 'certificates') as $entry) {
            if (!is_array($entry)) {
                throw new Exception\TrustRootException('Trusted-root certificate entry must be an object.');
            }
            /** @var array<string, mixed> $entry */
            $der[] = TrustRootJson::base64($entry, 'rawBytes', 'raw_bytes');
        }

        $validFor = TrustRootJson::object($data, 'validFor', 'valid_for');

        return new self(
            $der,
            TrustRootJson::dateOrNull($validFor, 'start'),
            TrustRootJson::dateOrNull($validFor, 'end'),
        );
    }

    public function isValidAt(\DateTimeImmutable $moment): bool
    {
        if ($this->validForStart !== null && $moment < $this->validForStart) {
            return false;
        }
        if ($this->validForEnd !== null && $moment > $this->validForEnd) {
            return false;
        }
        return true;
    }

    /**
     * The chain as parsed certificates (intermediates then root), built lazily.
     *
     * @return list<Certificate>
     */
    public function certificates(): array
    {
        if ($this->certificates === null) {
            $this->certificates = array_map(
                static fn (string $der): Certificate => Certificate::fromDer($der),
                $this->certChainDer,
            );
        }
        return $this->certificates;
    }
}

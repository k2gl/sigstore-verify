<?php

declare(strict_types=1);

namespace K2gl\Sigstore\Cli;

use InvalidArgumentException;

/**
 * Parsed command-line options for the `sigstore-verify` binary.
 */
final class Options
{
    private const DIGEST_ALGORITHMS = ['sha256', 'sha512'];

    public function __construct(
        public readonly string $artifact,
        public readonly string $bundle,
        public readonly ?string $repository,
        public readonly ?string $workflow,
        public readonly ?string $ref,
        public readonly ?string $san,
        public readonly ?string $issuer,
        public readonly ?string $trustedRoot,
        public readonly string $digestAlgorithm,
        public readonly bool $help,
    ) {}

    /**
     * @param list<string> $arguments argv without the script name
     */
    public static function parse(array $arguments): self
    {
        $positional = [];
        $named = [
            'repository' => null,
            'workflow' => null,
            'ref' => null,
            'san' => null,
            'issuer' => null,
            'trusted-root' => null,
            'digest-alg' => 'sha256',
        ];
        $help = false;

        for ($i = 0; $i < count($arguments); $i++) {
            $argument = $arguments[$i];

            if ($argument === '-h' || $argument === '--help') {
                $help = true;

                continue;
            }

            if (str_starts_with($argument, '--')) {
                $name = substr($argument, 2);

                if (! array_key_exists($name, $named)) {
                    throw new InvalidArgumentException(sprintf('Unknown option "%s".', $argument));
                }

                $value = $arguments[$i + 1] ?? null;

                if ($value === null || str_starts_with($value, '--')) {
                    throw new InvalidArgumentException(sprintf('Option "%s" expects a value.', $argument));
                }

                $named[$name] = $value;
                $i++;

                continue;
            }

            $positional[] = $argument;
        }

        if ($help) {
            return new self(
                artifact: '',
                bundle: '',
                repository: null,
                workflow: null,
                ref: null,
                san: null,
                issuer: null,
                trustedRoot: null,
                digestAlgorithm: 'sha256',
                help: true,
            );
        }

        if (count($positional) !== 2) {
            throw new InvalidArgumentException('Expected exactly two arguments: <artifact> <bundle>.');
        }

        $hasRepository = $named['repository'] !== null;
        $hasExactIdentity = $named['san'] !== null && $named['issuer'] !== null;

        if (! $hasRepository && ! $hasExactIdentity) {
            throw new InvalidArgumentException('Expected an identity: --repository <owner/repo>, or --san and --issuer.');
        }

        if ($hasRepository && ($named['san'] !== null || $named['issuer'] !== null)) {
            throw new InvalidArgumentException('Options --repository and --san/--issuer are mutually exclusive.');
        }

        if (! in_array($named['digest-alg'], self::DIGEST_ALGORITHMS, true)) {
            throw new InvalidArgumentException(sprintf(
                'Option --digest-alg expects one of: %s.',
                implode(', ', self::DIGEST_ALGORITHMS),
            ));
        }

        return new self(
            artifact: $positional[0],
            bundle: $positional[1],
            repository: $named['repository'],
            workflow: $named['workflow'],
            ref: $named['ref'],
            san: $named['san'],
            issuer: $named['issuer'],
            trustedRoot: $named['trusted-root'],
            digestAlgorithm: $named['digest-alg'],
            help: false,
        );
    }
}

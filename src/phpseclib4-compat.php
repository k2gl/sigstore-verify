<?php

declare(strict_types=1);

/**
 * phpseclib 4 moved everything from the `phpseclib3\` namespace to `phpseclib4\`.
 * Composer resolves the package to exactly one version, so when the 4.x line is
 * installed nothing else in the project can be holding a `phpseclib3\` class —
 * which makes aliasing the names this library uses safe rather than presumptuous.
 *
 * Only the parts whose API is identical across the two majors are aliased: key
 * loading, the key types and the big-integer/curve maths. The set is listed
 * whole rather than trimmed to the lines src/ happens to touch today, so it
 * stays predictable as the library grows. X.509 was reworked
 * in 4.0 and is handled explicitly in {@see \K2gl\Sigstore\Internal\Certificate},
 * so `File\X509` is aliased for its name alone and never for its behaviour.
 */
if (class_exists(\phpseclib3\Crypt\PublicKeyLoader::class)) {
    return;
}

foreach ([
    'Crypt\Common\AsymmetricKey',
    'Crypt\Common\PrivateKey',
    'Crypt\Common\PublicKey',
    'Crypt\DSA',
    'Crypt\EC',
    'Crypt\EC\BaseCurves\Prime',
    'Crypt\EC\Curves\secp256r1',
    'Crypt\EC\Curves\secp384r1',
    'Crypt\EC\Curves\secp521r1',
    'Crypt\PublicKeyLoader',
    'Crypt\RSA',
    'File\X509',
    'Math\BigInteger',
    'Math\PrimeField\Integer',
] as $name) {
    $v4 = 'phpseclib4\\' . $name;
    $v3 = 'phpseclib3\\' . $name;

    if (interface_exists($v4) || class_exists($v4)) {
        class_alias($v4, $v3);
    }
}

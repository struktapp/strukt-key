<?php

/** Pest configuration shared by the package test suite. */

use PHPUnit\Framework\TestCase;

pest()->extend(TestCase::class)->in('Feature', 'Unit');

/**
 * Path to a fresh temporary directory with a trailing separator.
 *
 * Every suite run works in its own scratch space so RSA key generation never
 * collides between tests or leaves private keys behind in the repository.
 */
function key_temp_dir(): string
{
    $dir = sys_get_temp_dir() . '/strukt-key-' . bin2hex(random_bytes(4));

    if (!is_dir($dir) && !mkdir($dir, 0775, true)) {
        throw new RuntimeException('Unable to create the key test scratch directory.');
    }

    return $dir . DIRECTORY_SEPARATOR;
}
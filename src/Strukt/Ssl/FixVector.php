<?php

declare(strict_types=1);

namespace Strukt\Ssl;

/**
 * Random IV generation for the symmetric ciphers.
 *
 * The name reads heavy, but the job is small: ask OpenSSL for the cipher's IV
 * length and fill it with CSPRNG bytes (random_bytes, not the legacy
 * openssl_random_pseudo_bytes call).
 */
final class FixVector
{
    /**
     * Random vector of the length the cipher expects.
     *
     * @param string $cipher Cipher name from openssl_get_cipher_methods().
     * @return string Raw IV bytes.
     */
    public static function make(string $cipher = 'AES-128-CBC'): string
    {
        return random_bytes(openssl_cipher_iv_length($cipher));
    }

    /**
     * Random vector as hex, convenient for configuration files.
     *
     * @param string $cipher Cipher name from openssl_get_cipher_methods().
     * @return string Hex IV.
     */
    public static function hex(string $cipher = 'AES-128-CBC'): string
    {
        return bin2hex(self::make($cipher));
    }
}
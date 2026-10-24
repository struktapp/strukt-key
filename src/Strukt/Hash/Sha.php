<?php

declare(strict_types=1);

namespace Strukt\Hash;

/**
 * Message digests and HMAC lines over the native hash() primitives.
 *
 * The one- and double-SHA256 forms match the legacy helper surface; the
 * generic methods cover the rest of the hash_algos() family.
 */
final class Sha
{
    /**
     * Single round digest.
     *
     * @param string $text Data to hash.
     * @param string $algo Hash algorithm from hash_algos().
     * @return string Hex digest.
     */
    public static function once(string $text, string $algo = 'sha256'): string
    {
        return hash($algo, $text, false);
    }

    /**
     * Double digest, `hash(hash($text))`.
     *
     * @param string $text Data to hash.
     * @param string $algo Hash algorithm from hash_algos().
     * @return string Hex digest.
     */
    public static function dbl(string $text, string $algo = 'sha256'): string
    {
        return self::once(self::once($text, $algo), $algo);
    }

    /**
     * Keyed message authentication code.
     *
     * @param string $key Secret key.
     * @param string $data Message.
     * @param string $algo Hash algorithm from hash_algos().
     * @return string Raw binary HMAC.
     */
    public static function hmac(string $key, string $data, string $algo = 'sha256'): string
    {
        return hash_hmac($algo, $data, $key, true);
    }

    /**
     * Single SHA-256 digest.
     *
     * @param string $text Data to hash.
     * @return string Hex digest.
     */
    public static function once256(string $text): string
    {
        return self::once($text, 'sha256');
    }

    /**
     * Double SHA-256 digest, as used by block-chain address derivation.
     *
     * @param string $text Data to hash.
     * @return string Hex digest.
     */
    public static function dbl256(string $text): string
    {
        return self::dbl($text, 'sha256');
    }
}
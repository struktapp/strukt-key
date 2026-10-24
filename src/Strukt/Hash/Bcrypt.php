<?php

declare(strict_types=1);

namespace Strukt\Hash;

/**
 * Password hashing with the native bcrypt implementation.
 *
 * The legacy package rolled its own crypt() salt with mt_rand(). This rebuild
 * delegates to password_hash()/password_verify(), which generate the salt
 * with the CSPRNG and store the cost alongside the digest so verification
 * always reuses the original work factor.
 */
final class Bcrypt
{
    /**
     * @param int $cost Work factor, power of two between 4 and 31.
     */
    public function __construct(private int $cost = 12)
    {
        if ($cost < 4 || $cost > 31) {
            throw new \InvalidArgumentException(sprintf('Bcrypt cost [%d] is outside 4..31.', $cost));
        }
    }

    /**
     * Hashes a password with a random salt.
     *
     * @param string $password Plain text password.
     * @return string Bcrypt digest with the cost embedded.
     */
    public function makeHash(string $password): string
    {
        $hash = password_hash($password, PASSWORD_BCRYPT, ['cost' => $this->cost]);

        if ($hash === false) {
            throw new \RuntimeException('Unable to hash the password.');
        }

        return $hash;
    }

    /**
     * Verifies a password against a stored bcrypt digest in constant time.
     *
     * @param string $password Candidate password.
     * @param string $hash Stored digest.
     * @return bool True when the password matches.
     */
    public function verify(string $password, string $hash): bool
    {
        return password_verify($password, $hash);
    }

    /**
     * Reports whether a stored digest needs to be re-hashed.
     *
     * @param string $hash Stored digest.
     * @param int $cost Target work factor.
     * @return bool True when the digest uses an older algorithm or cost.
     */
    public static function needsRehash(string $hash, int $cost = 12): bool
    {
        return password_needs_rehash($hash, PASSWORD_BCRYPT, ['cost' => $cost]);
    }
}
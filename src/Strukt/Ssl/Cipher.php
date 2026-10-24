<?php

declare(strict_types=1);

namespace Strukt\Ssl;

/**
 * Asymmetric encryption line.
 *
 * Encrypts with the public side only, so any holder of the public key can push
 * ciphertext at the pair, and decrypts with the private side. Errors are loud:
 * OpenSSL failure messages bubble up instead of a silent false.
 */
final class Cipher
{
    /**
     * @param KeyPairInterface $keys Pair carrying the public and private sides.
     */
    public function __construct(private KeyPairInterface $keys)
    {
    }

    /**
     * Decrypts ciphertext with the private key.
     *
     * @param string $encrypted Base64 ciphertext.
     * @return string Plain text.
     * @throws \RuntimeException When the payload cannot be decrypted.
     */
    public function decrypt(string $encrypted): string
    {
        $payload = base64_decode($encrypted, true);

        if ($payload === false) {
            throw new \RuntimeException('Unable to decrypt the payload [malformed base64].');
        }

        $plain = '';

        if (openssl_public_decrypt($payload, $plain, $this->keys->getPublic())) {
            return $plain;
        }

        $private = $this->keys->getPrivate();

        if ($private !== null && openssl_private_decrypt($payload, $plain, $private)) {
            return $plain;
        }

        throw new \RuntimeException('Unable to decrypt the payload [' . openssl_error_string() . '].');
    }

    /**
     * Encrypts data with the public key.
     *
     * @param string $data Plain text.
     * @return string Base64 ciphertext.
     */
    public function encrypt(string $data): string
    {
        if (!openssl_public_encrypt($data, $encrypted, $this->keys->getPublic())) {
            throw new \RuntimeException('Unable to encrypt the payload [' . openssl_error_string() . '].');
        }

        return base64_encode($encrypted);
    }

    /**
     * One-shot public-key encryption.
     *
     * @param PublicKey $pubKey Public half of the pair.
     * @param string $data Plain text.
     * @return string Base64 ciphertext.
     */
    public static function encryptWith(PublicKey $pubKey, string $data): string
    {
        if (!openssl_public_encrypt($data, $encrypted, $pubKey->get())) {
            throw new \RuntimeException('Unable to encrypt the payload [' . openssl_error_string() . '].');
        }

        return base64_encode($encrypted);
    }
}
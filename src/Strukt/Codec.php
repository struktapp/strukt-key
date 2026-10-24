<?php

declare(strict_types=1);

namespace Strukt;

/**
 * Symmetric AES encoder/decoder backed by the OpenSSL cipher API.
 *
 * The legacy class only worked when the caller supplied a fixed IV through a
 * config file. This rebuild keeps that mode for compatibility and adds the
 * safer default: when no vector is given, a fresh random IV is generated for
 * every message and carried along in the result, so the same key can be
 * reused without IV reuse.
 *
 * Result shapes
 * =============
 *
 * `encode()` with a provided vector returns the raw base64 ciphertext, exactly
 * as before. Without a vector it returns `<iv-hex>:<base64 ciphertext>`, which
 * `decode()` recognises and splits back apart.
 */
final class Codec
{
    private bool $wrap;

    /**
     * @param string $key Symmetric key.
     * @param string $cipher Cipher name from openssl_get_cipher_methods().
     * @param string|null $vector Fixed IV, hex bytes; `null` for a random IV per message.
     */
    public function __construct(
        private string $key,
        private string $cipher = 'AES-128-CBC',
        private ?string $vector = null,
    ) {
        if (!in_array(strtolower($cipher), array_map('strtolower', openssl_get_cipher_methods()), true)) {
            throw new \InvalidArgumentException(sprintf('Unsupported cipher [%s].', $cipher));
        }

        if ($vector !== null && $vector !== '') {
            $bytes = hex2bin($vector);

            if ($bytes === false) {
                throw new \InvalidArgumentException(sprintf('Vector [%s] is not valid hex.', $vector));
            }

            if (strlen($bytes) !== openssl_cipher_iv_length($cipher)) {
                throw new \InvalidArgumentException(sprintf(
                    'Vector length [%d] does not match cipher [%s].',
                    strlen($bytes),
                    $cipher,
                ));
            }

            $this->vector = $bytes;
        }

        $this->wrap = $this->vector === null;
    }

    /**
     * Creates a codec with the given key, cipher, and optional fixed vector.
     *
     * @param string $key Symmetric key.
     * @param string $cipher Cipher name.
     * @param string|null $vector Hex IV when a deterministic vector is wanted.
     * @return static New codec.
     */
    public static function make(string $key, string $cipher = 'AES-128-CBC', ?string $vector = null): static
    {
        return new self($key, $cipher, $vector);
    }

    /**
     * Encrypts data with AES.
     *
     * @param string $data Plain text.
     * @return string Base64 ciphertext, or `<iv-hex>:<base64>` when the codec generates its own IV.
     */
    public function encode(string $data): string
    {
        $vector = $this->vector ?? random_bytes(openssl_cipher_iv_length($this->cipher));
        $cipherText = openssl_encrypt(
            $data,
            $this->cipher,
            $this->key,
            OPENSSL_RAW_DATA,
            $vector,
        );

        if ($cipherText === false) {
            throw new \RuntimeException('Unable to encrypt the payload.');
        }

        return $this->wrap
            ? bin2hex($vector) . ':' . base64_encode($cipherText)
            : base64_encode($cipherText);
    }

    /**
     * Decrypts data produced by encode().
     *
     * @param string $encrypted Base64 ciphertext, or `<iv-hex>:<base64>`.
     * @return string Plain text.
     * @throws \RuntimeException When the payload cannot be decrypted.
     */
    public function decode(string $encrypted): string
    {
        [$vector, $payload] = $this->unwrap($encrypted);

        $decrypted = openssl_decrypt(
            base64_decode($payload, true),
            $this->cipher,
            $this->key,
            OPENSSL_RAW_DATA,
            $vector,
        );

        if ($decrypted === false) {
            throw new \RuntimeException('Unable to decrypt the payload [invalid key, IV, or tampered data].');
        }

        return $decrypted;
    }

    /**
     * Splits a wrapped value into the IV and ciphertext halves.
     *
     * @return array{0: string, 1: string} IV bytes and base64 ciphertext.
     */
    private function unwrap(string $encrypted): array
    {
        if (str_contains($encrypted, ':')) {
            [$hex, $payload] = explode(':', $encrypted, 2);
            $bytes = hex2bin($hex);

            if ($bytes === false) {
                throw new \RuntimeException('Unable to decrypt the payload [malformed IV].');
            }

            return [$bytes, $payload];
        }

        if ($this->vector === null) {
            throw new \RuntimeException('Unable to decrypt the payload [missing IV].');
        }

        return [$this->vector, $encrypted];
    }
}
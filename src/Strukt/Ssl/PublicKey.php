<?php

declare(strict_types=1);

namespace Strukt\Ssl;

/**
 * Public key wrapper.
 *
 * Mirrors PrivateKey: loads from a parsed OpenSSL object, a PEM string, or a
 * file, and re-exports the PEM. The derived bytes come straight from OpenSSL
 * so the format always matches what the rest of the toolchain emitted.
 */
final class PublicKey
{
    private function __construct(private string $pem, private \OpenSSLAsymmetricKey $key)
    {
    }

    /**
     * Creates a public key from a PEM string.
     *
     * @param string $pem PEM key material.
     * @return static New public key.
     */
    public static function make(string $pem): static
    {
        $key = openssl_pkey_get_public($pem);

        if (!$key) {
            throw new \RuntimeException('Unable to load the public key [' . openssl_error_string() . '].');
        }

        return new self($pem, $key);
    }

    /**
     * Creates a public key from a PEM file, given a size cap.
     *
     * @param string $path Path to the key file.
     * @return static New public key.
     */
    public static function read(string $path): static
    {
        if (!is_file($path)) {
            throw new \InvalidArgumentException(sprintf('Public key file [%s] not found.', $path));
        }

        $pem = file_get_contents($path);

        if ($pem === false) {
            throw new \RuntimeException(sprintf('Unable to read public key file [%s].', $path));
        }

        return self::make($pem);
    }

    /**
     * Wraps an already-parsed OpenSSL key object.
     *
     * @param \OpenSSLAsymmetricKey $key Parsed key object.
     * @return static New public key.
     */
    public static function fromKey(\OpenSSLAsymmetricKey $key): static
    {
        $details = openssl_pkey_get_details($key);
        $pem = $details['key'] ?? null;

        if ($pem === null) {
            throw new \RuntimeException('Unable to export the public key.');
        }

        return self::make($pem);
    }

    /**
     * Raw key object.
     */
    public function get(): \OpenSSLAsymmetricKey
    {
        return $this->key;
    }

    /**
     * Legacy alias of get().
     */
    public function getResource(): \OpenSSLAsymmetricKey
    {
        return $this->get();
    }

    /**
     * Key details as OpenSSL reports them.
     *
     * @return array<string, mixed>|false
     */
    public function getKey(): array|false
    {
        return openssl_pkey_get_details($this->key);
    }

    /**
     * PEM serialization.
     */
    public function toString(): string
    {
        return $this->pem;
    }

    /**
     * Legacy alias of toString().
     */
    public function getPem(): string
    {
        return $this->toString();
    }

    public function __toString(): string
    {
        return $this->toString();
    }
}
<?php

declare(strict_types=1);

namespace Strukt\Ssl;

/**
 * OpenSSL key generation options.
 *
 * The defaults mirror the legacy configuration file but default to 2048-bit
 * RSA keys (fast to generate, still beyond the reach of general attack) and a
 * bundled openssl.cnf so generation never depends on the system's default
 * config being present.
 */
final class Config
{
    /** @var array<string, mixed> Effective options. */
    private array $config;

    /**
     * @param array<string, mixed> $config Overrides merged over the defaults.
     */
    public function __construct(array $config = [])
    {
        $this->config = array_merge(self::dump(), $config);
    }

    /**
     * Base OpenSSL option set.
     *
     * @return array<string, mixed> OpenSSL configuration.
     */
    public static function dump(): array
    {
        return [
            'config' => dirname(__DIR__, 3) . '/asset/openssl.cnf',
            'digest_alg' => 'sha256',
            'x509_extensions' => 'v3_ca',
            'req_extensions' => 'v3_req',
            'private_key_bits' => 2048,
            'private_key_type' => OPENSSL_KEYTYPE_RSA,
            'encrypt_key' => false,
        ];
    }

    /**
     * Returns the effective option map for the OpenSSL calls.
     *
     * @return array<string, mixed> OpenSSL configuration.
     */
    public function getAll(): array
    {
        return $this->config;
    }

    /**
     * Returns a single option.
     */
    public function get(string $key): mixed
    {
        return $this->config[$key] ?? null;
    }

    /**
     * Copies the config with one option replaced.
     *
     * @return static New config.
     */
    public function with(string $key, mixed $value): static
    {
        $clone = clone $this;
        $clone->config[$key] = $value;

        return $clone;
    }
}
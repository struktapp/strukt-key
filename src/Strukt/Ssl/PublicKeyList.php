<?php

declare(strict_types=1);

namespace Strukt\Ssl;

/**
 * Ordered collection of public keys, used as the recipient set for sealing.
 *
 * Members may be added as PublicKey objects or as PEM strings; `getKeys()`
 * always hands back fingerprint-stable PublicKey objects to feed OpenSSL.
 */
final class PublicKeyList
{
    /** @var PublicKey[] */
    private array $keys = [];

    /**
     * @param array<int, PublicKey|string|array> $keyList Members to start with.
     */
    public function __construct(array $keyList = [])
    {
        foreach ($keyList as $key) {
            $this->addKey($key);
        }
    }

    /**
     * Creates an empty list.
     *
     * @return static New list.
     */
    public static function make(array $keyList = []): static
    {
        return new self($keyList);
    }

    /**
     * Adds a key from a PublicKey object or PEM string.
     *
     * @param PublicKey|string $key Public key material.
     */
    public function addKey(PublicKey|string $key): void
    {
        $this->keys[] = is_string($key) ? PublicKey::make($key) : $key;
    }

    /**
     * The collector PublicKey objects.
     *
     * @return PublicKey[]
     */
    public function getKeys(): array
    {
        return $this->keys;
    }

    /**
     * Number of keys in the list.
     */
    public function count(): int
    {
        return count($this->keys);
    }
}
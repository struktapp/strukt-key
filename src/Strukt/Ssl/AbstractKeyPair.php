<?php

declare(strict_types=1);

namespace Strukt\Ssl;

/**
 * Shared key-pair shape: directory, base name, and the concrete private and
 * public file paths derived from them.
 *
 * Legacy naming kept the private and public key under one `.pem` path; this
 * rebuild splits them (`<name>.pem` vs `<name>.pub.pem`) so either file can be
 * handed out independently without a slicing convention.
 */
abstract class AbstractKeyPair implements KeyPairInterface
{
    public function __toString(): string
    {
        return $this->privateKeyFile();
    }

    public function getPrivate(): ?\OpenSSLAsymmetricKey
    {
        return $this->privateKey()->get();
    }

    public function getPublic(): \OpenSSLAsymmetricKey
    {
        return $this->publicKey()->get();
    }

    public function privateKeyFile(): string
    {
        return rtrim($this->dir(), '/') . '/' . $this->keyName() . '.pem';
    }

    public function publicKeyFile(): string
    {
        return rtrim($this->dir(), '/') . '/' . $this->keyName() . '.pub.pem';
    }

    /**
     * Directory the key files live in.
     */
    abstract public function dir(): string;

    /**
     * Base name shared by the key files, without an extension.
     */
    abstract public function keyName(): string;

    /**
     * OpenSSL options used to build the pair.
     */
    abstract public function config(): Config;
}
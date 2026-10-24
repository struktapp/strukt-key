<?php

declare(strict_types=1);

namespace Strukt\Ssl;

/**
 * Contract every key carrier upholds.
 *
 * Splits the pair into the OpenSSL objects it wraps and the concrete key
 * files it can be written to, so the certificate and CSR paths never care
 * whether they hold an on-disk file or an in-memory pair.
 */
interface KeyPairInterface
{
    public function __toString(): string;

    public function getPrivate(): ?\OpenSSLAsymmetricKey;

    public function getPublic(): \OpenSSLAsymmetricKey;

    public function privateKeyFile(): string;

    public function publicKeyFile(): string;

    public function privateKey(): PrivateKey;

    public function publicKey(): PublicKey;
}
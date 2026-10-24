<?php

declare(strict_types=1);

namespace Strukt\Ssl;

/**
 * A key pair bound to a directory and base name.
 *
 * Creation can follow two routes: generation (a fresh pair is created in
 * memory, written out only when make*File() is called) or adoption (an
 * existing private key backs the pair and its public half is derived).
 */
final class KeyPair extends AbstractKeyPair
{
    private PrivateKey $privateKey;

    private PublicKey $publicKey;

    private Config $options;

    private function __construct(
        private string $dir,
        private string $name,
        array $configOptions = [],
        ?PrivateKey $existing = null,
    ) {
        $this->options = new Config($configOptions);

        if ($existing !== null) {
            $this->privateKey = $existing;
            $this->publicKey = $existing->getPublicKey();

            return;
        }

        $resource = openssl_pkey_new($this->options->getAll());

        if ($resource === false) {
            throw new \RuntimeException('Unable to generate the key pair [' . openssl_error_string() . '].');
        }

        $this->privateKey = PrivateKey::fromKey($resource);
        $this->publicKey = PublicKey::fromKey($resource);
    }

    /**
     * Generates a fresh pair.
     *
     * @param string $dir Directory the files will be written to.
     * @param string $name Base file name without extension.
     * @param array<string, mixed> $configOptions OpenSSL overrides.
     * @return KeyPair New pair.
     */
    public static function make(string $dir, string $name, array $configOptions = []): KeyPair
    {
        return new self($dir, $name, $configOptions);
    }

    /**
     * Adopts an existing private key and derives the public half.
     *
     * @param PrivateKey $private Half already on hand.
     * @param string $dir Directory the files will be written to.
     * @param string $name Base file name without extension.
     * @return KeyPair Adopted pair.
     */
    public static function fromPrivate(PrivateKey $private, string $dir, string $name): KeyPair
    {
        return new self($dir, $name, [], $private);
    }

    public function dir(): string
    {
        return $this->dir;
    }

    public function keyName(): string
    {
        return $this->name;
    }

    public function config(): Config
    {
        return $this->options;
    }

    public function privateKey(): PrivateKey
    {
        return $this->privateKey;
    }

    public function publicKey(): PublicKey
    {
        return $this->publicKey;
    }

    /**
     * Writes the private key file, creating the directory when needed.
     *
     * @return string Path written.
     */
    public function makePrivateKeyFile(): string
    {
        $this->ensureDir();
        file_put_contents($this->privateKeyFile(), $this->privateKey->toString());

        return $this->privateKeyFile();
    }

    /**
     * Writes the public key file.
     *
     * @return string Path written.
     */
    public function makePublicKeyFile(): string
    {
        $this->ensureDir();
        file_put_contents($this->publicKeyFile(), $this->publicKey->toString());

        return $this->publicKeyFile();
    }

    private function ensureDir(): void
    {
        if (!is_dir($this->dir) && !mkdir($this->dir, 0775, true) && !is_dir($this->dir)) {
            throw new \RuntimeException(sprintf('Unable to create key directory [%s].', $this->dir));
        }
    }
}
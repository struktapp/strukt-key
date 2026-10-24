<?php

declare(strict_types=1);

namespace Strukt\Ssl;

/**
 * Facade over the key toolbox.
 *
 * Static entry points decide where the key material comes from; methods chain
 * into a named Request or useCipher for the operations. The anonymous chain
 * classes of the legacy facade are replaced by the compact value objects in
 * this package.
 */
final class All
{
    private static ?Config $config = null;

    private function __construct(private KeyPairInterface $keys)
    {
    }

    /**
     * Starts with a freshly generated pair on disk (`keys/key`).
     */
    public static function makeKeys(): static
    {
        return new self(KeyPairBuilder::make()->makeKeyPair());
    }

    /**
     * Starts with an existing pair.
     */
    public static function useKeys(KeyPair $keys): static
    {
        return new self($keys);
    }

    /**
     * Starts from a private key path.
     */
    public static function keyPath(string $path): static
    {
        $dir = dirname($path);
        $name = pathinfo($path, PATHINFO_FILENAME);

        return new self(KeyPair::fromPrivate(PrivateKey::read($path), $dir, $name));
    }

    /**
     * The key carrier this facade is built on.
     */
    public function getKeys(): KeyPairInterface
    {
        return $this->keys;
    }

    /**
     * Envelope twin: caller picks the recipient half.
     */
    public static function withEnvl(?string $iv = null, ?PrivateKey $privKey = null): Envelope\Pockets
    {
        $envelope = Envelope::withAlgo($iv);

        if ($privKey !== null) {
            return $envelope->usePrivKey($privKey);
        }

        return $envelope->useKeys(PublicKeyList::make());
    }

    /**
     * Certificate flow for an on-disk certificate.
     *
     * @return Request Pipeline carrying the certificate.
     */
    public function withCert(string $path, array $names = ['common' => 'test']): Request
    {
        return $this->useCsr($names)->importCert($path);
    }

    /**
     * Builds a CSR pipeline from the facade's keys.
     *
     * @return Request Pipeline carrying the request.
     */
    public function useCsr(array $names = ['common' => 'test']): Request
    {
        return new Request($this->keys, new Csr\UniqueName($names), static::$config);
    }

    /**
     * Symmetric/asymmetric cipher line on the facade's keys.
     */
    public function useCipher(): Cipher
    {
        return new Cipher($this->keys);
    }

    /**
     * Encrypts a message for the pair's public half.
     *
     * @param string $message Plain text.
     * @return string Base64 ciphertext.
     */
    public function toSend(string $message): string
    {
        return Cipher::encryptWith($this->keys->publicKey(), $message);
    }

    /**
     * Starts over with a fresh pair honouring the given OpenSSL config.
     *
     * @param Config|null $config OpenSSL overrides; defaults to the package set.
     * @return static New facade.
     */
    public static function makeKeysByCfg(?Config $config = null): static
    {
        $cfg = $config ?? new Config();
        static::$config = $cfg;

        return new self(KeyPairBuilder::make()
            ->setDirectory('keys/')
            ->setName('key')
            ->setConfigOptions($cfg->getAll())
            ->makeKeyPair());
    }
}
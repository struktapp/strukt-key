<?php

declare(strict_types=1);

namespace Strukt\Ssl;

/**
 * Private key wrapper.
 *
 * Builds from an OpenSSL key object, from a PEM string, or lazily from a file
 * path, and can re-export itself as a PEM. Loading a protected key takes the
 * passphrase; everything else stays explicit and typed.
 */
final class PrivateKey
{
    private ?\OpenSSLAsymmetricKey $key;

    private function __construct(private string $pem)
    {
        $this->key = openssl_pkey_get_private($pem);

        if (!$this->key) {
            throw new \RuntimeException('Unable to load the private key [' . openssl_error_string() . '].');
        }
    }

    /**
     * Creates a private key from a PEM string.
     *
     * @param string $pem PEM key material.
     * @return static New private key.
     */
    public static function make(string $pem): static
    {
        return new self($pem);
    }

    /**
     * Creates a private key from a PEM file, given a size cap.
     *
     * @param string $path Path to the key file.
     * @param int $cap Maximum bytes read.
     * @return static New private key.
     */
    public static function read(string $path, int $cap = 8192): static
    {
        if (!is_file($path)) {
            throw new \InvalidArgumentException(sprintf('Private key file [%s] not found.', $path));
        }

        $pem = file_get_contents($path, false, null, 0, $cap);

        if ($pem === false) {
            throw new \RuntimeException(sprintf('Unable to read private key file [%s].', $path));
        }

        return new self($pem);
    }

    /**
     * Wraps an already-parsed OpenSSL key object.
     *
     * @param \OpenSSLAsymmetricKey $key Parsed key object.
     * @return static New private key.
     */
    public static function fromKey(\OpenSSLAsymmetricKey $key): static
    {
        openssl_pkey_export($key, $pem);

        return new self($pem);
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
    public function getKey(): \OpenSSLAsymmetricKey
    {
        return $this->get();
    }

    /**
     * The public half derived from this private key.
     */
    public function getPublicKey(): PublicKey
    {
        $details = openssl_pkey_get_details($this->key);
        $pem = $details['key'] ?? null;

        if ($pem === null) {
            throw new \RuntimeException('Unable to derive the public key.');
        }

        return PublicKey::make($pem);
    }

    /**
     * Self-signs a CSR with this private key.
     *
     * @param Csr\Csr $request The request to sign.
     * @param int $days Lifetime of the certificate.
     * @return \OpenSSLCertificate Certificate.
     */
    public function getSelfSignedCert(Csr\Csr $request, int $days = 365): \OpenSSLCertificate
    {
        return Csr\Csr::sign($request, $this, $days);
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
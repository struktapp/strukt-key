<?php

declare(strict_types=1);

namespace Strukt\Ssl;

use OpenSSLAsymmetricKey as SslAsymKey;
use Strukt\Fs\Fs;

/**
 * Certificate file carrier.
 *
 * Loads certificate PEM from a path and pulls the public half out of it —
 * the stepping stone used whenever a certificate has to encrypt or verify
 * without exposing the private side.
 */
final class Cert
{
    private function __construct(private string $data)
    {
    }

    /**
     * Creates a certificate carrier from a file path.
     *
     * @param string $path Path to the certificate PEM.
     * @return static New carrier.
     */
    public static function withPath(string $path): static
    {
        if (!Fs::isPath($path)) {
            throw new \InvalidArgumentException(sprintf('Certificate file [%s] not found.', $path));
        }

        $data = Fs::cat($path);

        if ($data === false) {
            throw new \RuntimeException(sprintf('Unable to read certificate file [%s].', $path));
        }

        return new self($data);
    }

    /**
     * Creates a carrier from certificate PEM directly.
     *
     * @param string $pem Certificate material.
     * @return static New carrier.
     */
    public static function withPem(string $pem): static
    {
        return new self($pem);
    }

    /**
     * The certificate's public key object.
     */
    public function getResource(): SslAsymKey
    {
        $key = openssl_pkey_get_public($this->data);

        if (!$key) {
            throw new \RuntimeException('Unable to extract a public key from the certificate [' . openssl_error_string() . '].');
        }

        return $key;
    }

    /**
     * The public key wrapped as a PublicKey value object.
     */
    public function extractPublicKey(): PublicKey
    {
        return PublicKey::fromKey($this->getResource());
    }

    /**
     * A parser bound to this certificate.
     */
    public function parser(): Certificate\Parser
    {
        return new Certificate\Parser($this->data);
    }
}
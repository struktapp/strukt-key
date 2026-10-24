<?php

declare(strict_types=1);

namespace Strukt\Ssl;

use OpenSSLCertificate as SslCert;
use Strukt\Fs\Fs;
use Strukt\Ssl\Csr\Csr;
use Strukt\Ssl\Csr\CsrBuilder;
use Strukt\Ssl\Csr\UniqueName;

/**
 * Request pipeline: subject name, key pair, and the CSR they produce.
 *
 * Replaces the two anonymous chain classes the facade used to hand back. The
 * one object serves both flows:
 *
 *   ->useCsr($names)   send the CSR to a CA and later sign() it
 *   ->withCert($path)  adopt on-disk certificate material and verify it
 *
 * All entries are typed and loud; nothing returns a "true"/"false" string.
 */
final class Request
{
    private Csr $csr;

    private ?SslCert $xCert = null;

    /**
     * @param KeyPairInterface $keys Pair whose private key grounds the request.
     * @param UniqueName $names Subject fields.
     * @param Config|null $config OpenSSL overrides.
     */
    public function __construct(
        private KeyPairInterface $keys,
        UniqueName $names,
        private ?Config $config = null,
    ) {
        $builder = new CsrBuilder($names, $keys, $config);
        $this->csr = $builder->toCsr();
    }

    /**
     * The wrapped request.
     */
    public function getCsr(): Csr
    {
        return $this->csr;
    }

    /**
     * The certificate produced by selfSign(), if any.
     */
    public function getXCert(): ?SslCert
    {
        return $this->xCert;
    }

    /**
     * PEM serialization of the current certificate.
     */
    public function getCert(): ?string
    {
        return $this->csr->getCertPem();
    }

    /**
     * Signs the request with the pair's own private key.
     *
     * @param int $days Lifetime of the certificate.
     * @return static This request, now carrying its certificate.
     */
    public function selfSign(int $days = 365): static
    {
        $cert = Csr::sign($this->csr, $this->keys->privateKey(), $days);

        $this->xCert = $cert;
        $this->csr->exportCert($cert);

        return $this;
    }

    /**
     * Signs the request as a CA with the pair's private key and returns it.
     *
     * @param int $days Lifetime of the certificate.
     * @param int $serial Serial number; the OpenSSL default when 0.
     * @return SslCert Certificate.
     */
    public function sign(int $days = 365, int $serial = 0): SslCert
    {
        $cert = Csr::sign($this->csr, $this->keys->privateKey(), $days, $serial);

        $this->xCert = $cert;
        $this->csr->exportCert($cert);

        return $cert;
    }

    /**
     * Checks that the certificate belongs to the pair's private key.
     *
     * @param SslCert|string|null $cert Certificate or PEM; the stored one when null.
     * @return bool True when they form a pair.
     */
    public function verify(SslCert|string|null $cert = null): bool
    {
        $material = $cert ?? $this->csr->getCertPem();

        if ($material === null) {
            throw new \RuntimeException('No certificate to verify.');
        }

        return Csr::verifyCert($this->keys->privateKey(), $material);
    }

    /**
     * Adopts certificate material from a file on disk.
     *
     * @param string $path Path to a PEM certificate.
     * @return static This request, now carrying the file's certificate.
     */
    public function importCert(string $path): static
    {
        if (!Fs::isPath($path)) {
            throw new \InvalidArgumentException(sprintf('Certificate file [%s] not found.', $path));
        }

        $pem = Fs::cat($path);

        if ($pem === false) {
            throw new \RuntimeException(sprintf('Unable to read certificate file [%s].', $path));
        }

        $this->csr->exportCert($pem);

        return $this;
    }
}
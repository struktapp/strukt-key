<?php

declare(strict_types=1);

namespace Strukt\Ssl\Csr;

use OpenSSLCertificate as SslCert;
use OpenSSLCertificateSigningRequest as SslCsr;
use Strukt\Ssl\Config;
use Strukt\Ssl\PrivateKey;

/**
 * Certificate signing request value object.
 *
 * Wraps a CSR and, once signed, the resulting certificate. Keeps the legacy
 * surface (`getSubject`, `parse`, `verifyWith`, `sign`) but returns real
 * values and typed OpenSSL objects instead of opaque strings.
 */
final class Csr
{
    private ?string $csrPem = null;

    private ?string $certPem = null;

    private function __construct(SslCsr|string|null $csr = null)
    {
        if ($csr !== null) {
            $this->setCsr($csr);
        }
    }

    /**
     * Creates a request.
     *
     * @param \OpenSSLCertificateSigningRequest|string|null $csr OpenSSL CSR object or PEM.
     * @return static New request.
     */
    public static function make(SslCsr|string|null $csr = null): static
    {
        return new self($csr);
    }

    /**
     * PEM serialization of the request.
     */
    public function getCsr(): ?string
    {
        return $this->csrPem;
    }

    /**
     * Stores the request, accepting an OpenSSL object or PEM string.
     *
     * @param \OpenSSLCertificateSigningRequest|string $csr Request material.
     */
    public function setCsr(SslCsr|string $csr): void
    {
        if (is_string($csr)) {
            $this->csrPem = $csr;

            return;
        }

        if (!openssl_csr_export($csr, $pem)) {
            throw new \RuntimeException('Unable to export the csr [' . openssl_error_string() . '].');
        }

        $this->csrPem = $pem;
    }

    /**
     * Certificate PEM carried by the request.
     */
    public function getCertPem(): ?string
    {
        return $this->certPem;
    }

    /**
     * Stores a certificate alongside the request.
     *
     * @param \OpenSSLCertificate|string $cert Certificate object or PEM.
     */
    public function exportCert(SslCert|string $cert): void
    {
        if (is_string($cert)) {
            $this->certPem = $cert;

            return;
        }

        if (!openssl_x509_export($cert, $pem)) {
            throw new \RuntimeException('Unable to export the certificate [' . openssl_error_string() . '].');
        }

        $this->certPem = $pem;
    }

    /**
     * Subject fields of the request.
     *
     * @return array<string, string|array<string, string>>|null
     */
    public function getSubject(): ?array
    {
        $subject = openssl_csr_get_subject($this->csrPem ?? throw new \RuntimeException('No csr loaded.'));

        return is_array($subject) ? $subject : null;
    }

    /**
     * Parsed certificate fields, when a certificate is stored.
     *
     * @return array<string, mixed>|null
     */
    public function parse(): ?array
    {
        if ($this->certPem === null) {
            return null;
        }

        $cert = openssl_x509_parse($this->certPem);

        return is_array($cert) ? $cert : null;
    }

    /**
     * Checks whether the stored certificate matches the given private key.
     *
     * @param PrivateKey $privKey Private half to match.
     * @return bool True when they are the same pair.
     */
    public function verifyWith(PrivateKey $privKey): bool
    {
        return self::verifyCert($privKey, $this->certPem ?? throw new \RuntimeException('No certificate loaded.'));
    }

    /**
     * Parses certificate material into its fields.
     *
     * @param \OpenSSLCertificate|string $cert Certificate object or PEM.
     * @return array<string, mixed>|null
     */
    public static function parseCert(SslCert|string $cert): ?array
    {
        $parsed = openssl_x509_parse($cert);

        return is_array($parsed) ? $parsed : null;
    }

    /**
     * Checks whether certificate material matches a private key.
     *
     * @param PrivateKey $privKey Private half to match.
     * @param SslCert|string $cert Certificate object or PEM.
     * @return bool True when they form a pair.
     */
    public static function verifyCert(PrivateKey $privKey, SslCert|string $cert): bool
    {
        return (bool) openssl_x509_check_private_key($cert, $privKey->get());
    }

    /**
     * Signs the request with a private key (the CA's).
     *
     * @param Csr $request Request to sign.
     * @param PrivateKey $privKey Signing (CA) key.
     * @param int $days Lifetime of the certificate.
     * @param int $serial Serial number; the OpenSSL default when 0.
     * @return SslCert Certificate.
     */
    public static function sign(Csr $request, PrivateKey $privKey, int $days = 365, int $serial = 0): SslCert
    {
        $cert = openssl_csr_sign(
            $request->getCsr() ?? throw new \RuntimeException('No csr loaded.'),
            null,
            $privKey->get(),
            $days,
            Config::dump(),
            $serial,
        );

        if (!$cert) {
            throw new \RuntimeException('Unable to sign the csr [' . openssl_error_string() . '].');
        }

        $request->exportCert($cert);

        return $cert;
    }
}
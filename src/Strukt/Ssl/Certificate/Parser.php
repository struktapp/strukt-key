<?php

declare(strict_types=1);

namespace Strukt\Ssl\Certificate;

use OpenSSLCertificate as SslCert;
use Strukt\Ssl\PublicKey;

/**
 * Certificate field reader.
 *
 * Parses certificate material and hands back the interesting parts as typed
 * values. The legacy parser returned "true"/"false" strings for booleans;
 * here every answer is a real bool, string, or DateTime.
 */
final class Parser
{
    /** @var array<string, mixed> Parsed certificate fields. */
    private array $cert;

    private string $fingerprint;

    /**
     * @param \OpenSSLCertificate|string $source Certificate object or PEM.
     */
    public function __construct(private SslCert|string $source)
    {
        $parsed = openssl_x509_parse($source);

        if (!is_array($parsed)) {
            throw new \RuntimeException('Unable to parse the certificate [' . openssl_error_string() . '].');
        }

        $this->cert = $parsed;
        $this->fingerprint = (string) openssl_x509_fingerprint($source);
    }

    /**
     * Common name of the issuer.
     */
    public function getIssuer(): ?string
    {
        return $this->cert['issuer']['CN'] ?? null;
    }

    /**
     * Common name of the subject, i.e. the domain.
     */
    public function getDomain(): ?string
    {
        return $this->cert['subject']['CN'] ?? null;
    }

    /**
     * Signature type, e.g. `RSA-SHA256`.
     */
    public function getSignatureAlgo(): ?string
    {
        return $this->cert['signatureTypeSN'] ?? null;
    }

    /**
     * Validity start as a DateTime in the current timezone.
     */
    public function getFromDate(): \DateTime
    {
        return $this->now((int) ($this->cert['validFrom_time_t'] ?? 0));
    }

    /**
     * Validity end as a DateTime in the current timezone.
     */
    public function getToDate(): \DateTime
    {
        return $this->now((int) ($this->cert['validTo_time_t'] ?? 0));
    }

    /**
     * Whether the certificate has expired.
     */
    public function isExpired(): bool
    {
        return $this->getToDate() < new \DateTime();
    }

    /**
     * Whether the issuer and subject common names match.
     */
    public function isSelfSigned(): bool
    {
        return $this->getDomain() === $this->getIssuer();
    }

    /**
     * Whether the certificate carries the pre-certificate poison extension.
     */
    public function isPreCertificate(): bool
    {
        return isset($this->cert['extensions']['ct_precert_poison']);
    }

    /**
     * SHA-1 fingerprint (hex).
     */
    public function getFingerPrint(): string
    {
        return $this->fingerprint;
    }

    /**
     * Public key embedded in the certificate.
     */
    public function getPublicKey(): PublicKey
    {
        $key = openssl_pkey_get_public($this->source);

        if (!$key instanceof \OpenSSLAsymmetricKey) {
            throw new \RuntimeException('Unable to extract a public key from the certificate.');
        }

        return PublicKey::fromKey($key);
    }

    private function now(int $timestamp): \DateTime
    {
        return (new \DateTime())->setTimestamp($timestamp);
    }
}
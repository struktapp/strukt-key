<?php

declare(strict_types=1);

namespace Strukt\Ssl\Csr;

use Strukt\Ssl\Config;
use Strukt\Ssl\KeyPairInterface;

/**
 * Builds a certificate signing request from a subject and the pair's private
 * key, honouring the pair's OpenSSL config (which carries the bundled
 * openssl.cnf and digest).
 */
final class CsrBuilder
{
    private \OpenSSLCertificateSigningRequest $csr;

    /**
     * @param UniqueName $unique Subject fields.
     * @param KeyPairInterface $keys Pair whose private key signs the request.
     * @param Config|null $config OpenSSL overrides.
     */
    public function __construct(UniqueName $unique, KeyPairInterface $keys, ?Config $config = null)
    {
        $dn = $unique->getDetails();

        if ($dn === []) {
            throw new \InvalidArgumentException('Csr subject details cannot be empty.');
        }

        $private = $keys->getPrivate();
        $csr = openssl_csr_new($dn, $private, $config?->getAll() ?? Config::dump());

        if (!$csr) {
            throw new \RuntimeException('Unable to build the csr [' . openssl_error_string() . '].');
        }

        $this->csr = $csr;
    }

    /**
     * The generated request.
     *
     * @return \OpenSSLCertificateSigningRequest OpenSSL CSR object.
     */
    public function getCsr(): \OpenSSLCertificateSigningRequest
    {
        return $this->csr;
    }

    /**
     * The request wrapped in the Csr value object.
     */
    public function toCsr(): Csr
    {
        return Csr::make($this->csr);
    }
}
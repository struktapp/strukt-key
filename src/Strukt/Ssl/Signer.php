<?php

declare(strict_types=1);

namespace Strukt\Ssl;

/**
 * Asymmetric signature line.
 *
 * Signs with the private half and verifies with the public half. One-shot
 * helpers let a bare PublicKey verify without a full pair in hand, which
 * covers the common "I only trust this peer's cert" workflow.
 */
final class Signer
{
    /**
     * @param KeyPairInterface $keys Pair carrying the private and public sides.
     */
    public function __construct(private KeyPairInterface $keys)
    {
    }

    /**
     * Signs data with the private key.
     *
     * @param string $data Data to sign.
     * @return string Base64 signature.
     * @throws \RuntimeException When there is no private key to sign with.
     */
    public function create(string $data): string
    {
        $private = $this->keys->getPrivate();

        if (!$private) {
            throw new \RuntimeException('No private key available for signing.');
        }

        if (!openssl_sign($data, $signature, $private, OPENSSL_ALGO_SHA256)) {
            throw new \RuntimeException('Unable to sign the data [' . openssl_error_string() . '].');
        }

        return base64_encode($signature);
    }

    /**
     * Verifies a signature against data.
     *
     * @param string $data Data that was signed.
     * @param string $signature Base64 signature.
     * @param PublicKey $pubKey Public half of the signing pair.
     * @return bool True when the signature checks out.
     */
    public static function verify(string $data, string $signature, PublicKey $pubKey): bool
    {
        return (bool) openssl_verify(
            $data,
            base64_decode($signature, true),
            $pubKey->get(),
            OPENSSL_ALGO_SHA256,
        );
    }

    /**
     * Verifies with the pair's public half.
     *
     * @param string $data Data that was signed.
     * @param string $signature Base64 signature.
     * @return bool True when the signature checks out.
     */
    public function check(string $data, string $signature): bool
    {
        return self::verify($data, $signature, $this->keys->publicKey());
    }
}
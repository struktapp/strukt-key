<?php

declare(strict_types=1);

namespace Strukt\Ssl;

use Strukt\Ssl\Envelope\Pockets;

/**
 * Digital envelope: message sealing for a set of recipients.
 *
 * `openssl_seal` picks a fresh symmetric session key, encrypts the message
 * with it, and encrypts the session key once per recipient. The envelope keys
 * are ordered the same way the recipients were given, so each holder recovers
 * the message with their own envelope key and the matching private key.
 *
 * The IV is generated randomly per close operation and always returned, so the
 * same envelope can be reused for many messages without IV reuse.
 */
final class Envelope
{
    private ?string $iv = null;

    /**
     * @param string $cipher Symmetric cipher from openssl_get_cipher_methods().
     * @param string|null $iv Fixed IV; a random one is used and returned when null.
     */
    public function __construct(private string $cipher = 'AES-128-CBC', ?string $iv = null)
    {
        if (!in_array(strtolower($cipher), array_map('strtolower', openssl_get_cipher_methods()), true)) {
            throw new \InvalidArgumentException(sprintf('Unsupported cipher [%s].', $cipher));
        }

        $this->iv = $iv;
    }

    /**
     * Creates an envelope.
     *
     * @param string|null $iv Fixed IV or null for a random per-operation IV.
     * @param string $cipher Symmetric cipher.
     * @return static New envelope.
     */
    public static function withAlgo(?string $iv = null, string $cipher = 'AES-128-CBC'): static
    {
        return new self($cipher, $iv);
    }

    /**
     * Targets a set of recipient certificates.
     *
     * @param array<int, string> $paths Paths to recipient certificate PEMs.
     * @return Pockets Sealing pocket.
     */
    public function useCerts(array $paths): Pockets
    {
        $list = PublicKeyList::make();

        foreach ($paths as $path) {
            $list->addKey(Cert::withPath($path)->extractPublicKey());
        }

        return new Pockets($list, $this->cipher, $this->iv);
    }

    /**
     * Targets a set of recipient public keys, as list members or PEM strings.
     *
     * @return Pockets Sealing pocket.
     */
    public function useKeys(PublicKeyList|array $keys): Pockets
    {
        $list = is_array($keys) ? PublicKeyList::make($keys) : $keys;

        return new Pockets($list, $this->cipher, $this->iv);
    }

    /**
     * Targets the pair's own private key for opening.
     *
     * @param PrivateKey $privKey Recipient's private key.
     * @return Pockets Opening pocket.
     */
    public function usePrivKey(PrivateKey $privKey): Pockets
    {
        return new Pockets($privKey, $this->cipher, $this->iv);
    }

    /**
     * One-shot sealing against a recipient list.
     *
     * @return array{0: string[], 1: string, 2: string} Envelope keys (base64), sealed data (base64), and the IV used.
     */
    public static function closeAllWith(PublicKeyList $pubKeyList, string $data, string $cipher = 'AES-128-CBC'): array
    {
        $pockets = new Pockets($pubKeyList, $cipher, null);

        [$envKeys, $sealed, $iv] = $pockets->closeWithIv($data);

        return [$envKeys, $sealed, $iv];
    }
}
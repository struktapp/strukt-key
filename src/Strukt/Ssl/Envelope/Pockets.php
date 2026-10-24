<?php

declare(strict_types=1);

namespace Strukt\Ssl\Envelope;

use Strukt\Ssl\FixVector;
use Strukt\Ssl\PrivateKey;
use Strukt\Ssl\PublicKeyList;

/**
 * One half of an envelope operation.
 *
 * Constructed with either the recipient public-key set (to `close`) or a
 * private key (to `open`). Returned by Envelope::useCerts/usePrivKey.
 */
final class Pockets
{
    private ?PublicKeyList $recipients;

    private ?PrivateKey $private = null;

    /**
     * @param PublicKeyList|PrivateKey $target Recipient set or private key.
     * @param string $cipher Symmetric cipher.
     * @param string|null $iv Fixed IV, or null to generate and return one.
     */
    public function __construct(PublicKeyList|PrivateKey $target, private string $cipher, private ?string $iv)
    {
        if ($target instanceof PublicKeyList) {
            $this->recipients = $target;

            return;
        }

        $this->private = $target;
    }

    /**
     * Seals data for every recipient.
     *
     * @return array{0: string[], 1: string} Envelope keys (base64) and sealed data (base64).
     */
    public function close(string $data): array
    {
        [$envKeys, $sealed] = $this->closeWithIv($data);

        return [$envKeys, $sealed];
    }

    /**
     * Seals data and also reports the IV that was used.
     *
     * @return array{0: string[], 1: string, 2: string}
     */
    public function closeWithIv(string $data): array
    {
        if ($this->recipients === null) {
            throw new \RuntimeException('No recipients loaded for sealing.');
        }

        $pubKeys = array_map(
            static fn ($pubKey) => $pubKey->get(),
            $this->recipients->getKeys(),
        );

        $iv = $this->iv ?? FixVector::make($this->cipher);

        if (!openssl_seal($data, $sealed, $envKeys, $pubKeys, $this->cipher, $iv)) {
            throw new \RuntimeException('Unable to seal the message [' . openssl_error_string() . '].');
        }

        return [
            array_map(fn ($key) => base64_encode($key), $envKeys),
            base64_encode($sealed),
            $iv,
        ];
    }

    /**
     * Opens a sealed body with the pocket's private key.
     *
     * @param string $envKey The recipient's envelope key (base64).
     * @param string $sealed Sealed data (base64).
     * @return string The original message.
     */
    public function open(string $envKey, string $sealed): string
    {
        if ($this->private === null) {
            throw new \RuntimeException('No private key loaded for opening.');
        }

        $iv = $this->iv ?? FixVector::make($this->cipher);

        $message = openssl_open(
            base64_decode($sealed, true),
            $opened,
            base64_decode($envKey, true),
            $this->private->get(),
            $this->cipher,
            $iv,
        );

        if (!$message) {
            throw new \RuntimeException('Unable to open the message [' . openssl_error_string() . '].');
        }

        return $opened;
    }
}
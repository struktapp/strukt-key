<?php

declare(strict_types=1);

namespace Strukt;

/**
 * Cross-site request forgery token.
 *
 * A token wraps the submitted data with issued-at and expires-at timestamps,
 * JSON-encodes them, and signs them with an AES codec under a caller-provided
 * key. The claim set is returned on decode and validity is decided by the
 * window `iat <= now <= eat`, so a token cannot outlive its slot even though
 * the ciphertext itself is unreadable without the key.
 */
final class Csrf
{
    /**
     * @param string $key Symmetric key used to seal the token.
     * @param array|string $data Payload embedded in the token.
     * @param int $duration Seconds the token stays valid.
     */
    public function __construct(
        private string $key,
        private array|string $data,
        private int $duration = 300,
    ) {
        if ($duration < 1) {
            throw new \InvalidArgumentException(sprintf('Csrf duration [%d] must be positive.', $duration));
        }
    }

    /**
     * Builds a new token for the given payload.
     *
     * @param array|string $data Payload to embed.
     * @param string $key Symmetric key.
     * @param int $duration Seconds the token stays valid.
     * @return static New token.
     */
    public static function make(array|string $data, string $key, int $duration = 300): static
    {
        return new self($key, $data, $duration);
    }

    /**
     * Encodes the token.
     *
     * @return string Signed token string.
     */
    public function encode(): string
    {
        $now = time();

        return Codec::make($this->key)->encode(json_encode([
            'data' => $this->data,
            'iat' => $now,
            'eat' => \Strukt\Number::create($now)->add($this->duration)->yield(),
        ], JSON_THROW_ON_ERROR));
    }

    /**
     * Decodes a token into its claim set.
     *
     * @param string $token Token string.
     * @param string $key Symmetric key used to create it.
     * @return array{data: array|string, iat: int, eat: int} Claim set.
     * @throws \RuntimeException When the token cannot be unwrapped.
     */
    public static function decode(string $token, string $key): array
    {
        $claims = json_decode(Codec::make($key)->decode($token), true, 512, JSON_THROW_ON_ERROR);

        if (!isset($claims['iat'], $claims['eat'], $claims['data'])) {
            throw new \RuntimeException('Unable to read the csrf token [missing claims].');
        }

        return $claims;
    }

    /**
     * Checks that a token is structurally sound and inside its validity window.
     *
     * @param string $token Token string.
     * @param string $key Symmetric key used to create it.
     * @param int|null $now Clock to test against.
     * @return bool True when the token is valid.
     */
    public static function valid(string $token, string $key, ?int $now = null): bool
    {
        $now ??= time();

        try {
            $claims = self::decode($token, $key);
        } catch (\Throwable) {
            return false;
        }

        return $claims['iat'] <= $now && $now <= $claims['eat'];
    }

    /**
     * Encodes the token.
     *
     * @return string Signed token string.
     */
    public function __toString(): string
    {
        return $this->encode();
    }
}
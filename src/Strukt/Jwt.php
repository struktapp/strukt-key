<?php

declare(strict_types=1);

namespace Strukt;

use Strukt\Hash\Sha;

/**
 * Self-contained JSON Web Token signer.
 *
 * The legacy package wrapped firebase/php-jwt. This rebuild drops the external
 * dependency and implements the codec line directly over the Strukt SHA/HMAC
 * primitives: an HS256/384/512 token is `base64url(header).base64url(payload)`
 * signed with `hash_hmac`, and signatures are compared in constant time with
 * hash_equals(). No network calls, no service, no configuration file.
 *
 * Claims carried by every token: `iss`, `aud` (mirrors the issuer), `iat`,
 * `exp`, and `data` (the caller's payload).
 */
final class Jwt
{
    /** @var array<string, string> Supported algorithms to digest lines. */
    private const ALGOS = [
        'HS256' => 'sha256',
        'HS384' => 'sha384',
        'HS512' => 'sha512',
    ];

    /**
     * @param string $secret Signing key.
     * @param string $algo Algorithm from `HS256`, `HS384`, `HS512`.
     * @param int $expire Default validity in seconds.
     * @param string $issuer Issuer and audience claim.
     * @param string $timezone Timezone the token timestamps are expressed in.
     */
    public function __construct(
        private string $secret,
        private string $algo = 'HS256',
        private int $expire = 3600,
        private string $issuer = 'strukt/key',
        private string $timezone = 'UTC',
    ) {
        if (!isset(self::ALGOS[$algo])) {
            throw new \InvalidArgumentException(sprintf('Unsupported jwt algorithm [%s].', $algo));
        }

        if ($expire < 1) {
            throw new \InvalidArgumentException(sprintf('Jwt expire [%d] must be positive.', $expire));
        }

        if ($this->timezone !== 'UTC') {
            date_default_timezone_set($this->timezone ?? 'UTC');
        }
    }

    /**
     * Builds a signer from an options map.
     *
     * @param array{secret: string, algo?: string, expire?: int, issuer?: string, timezone?: string} $options Signer options.
     * @return static New signer.
     */
    public static function make(array $options): static
    {
        return new self(
            (string) ($options['secret'] ?? throw new \InvalidArgumentException('Jwt secret is required.')),
            (string) ($options['algo'] ?? 'HS256'),
            (int) ($options['expire'] ?? 3600),
            (string) ($options['issuer'] ?? 'strukt/key'),
            (string) ($options['timezone'] ?? 'UTC'),
        );
    }

    /**
     * Encodes a token.
     *
     * @param array|string $data Payload embedded under `data`.
     * @param int|null $issuedAt Unix timestamp, now when null.
     * @param int|null $expiresAt Unix timestamp, default expiry when null.
     * @return string Signed token.
     */
    public function encode(array|string $data, ?int $issuedAt = null, ?int $expiresAt = null): string
    {
        $iat = $issuedAt ?? time();

        $payload = [
            'iss' => $this->issuer,
            'aud' => $this->issuer,
            'iat' => $iat,
            'exp' => $expiresAt ?? \Strukt\Number::create($iat)->add($this->expire)->yield(),
            'data' => $data,
        ];

        $header = $this->segment(['typ' => 'JWT', 'alg' => $this->algo]);
        $body = $this->segment($payload);
        $signature = $this->sign("$header.$body");

        return "$header.$body.$signature";
    }

    /**
     * Decodes and validates a token.
     *
     * @param string $token Token string.
     * @param int|null $now Clock to test against.
     * @return \stdClass|null Claims, or `null` when malformed, unsigned, or expired.
     */
    public function decode(string $token, ?int $now = null): ?\stdClass
    {
        $now ??= time();

        try {
            $segments = explode('.', $token);
            if (count($segments) !== 3) {
                return null;
            }

            [$headerJson, $payloadJson, $given] = $segments;
            $header = json_decode($this->unSegment($headerJson), true, 512, JSON_THROW_ON_ERROR);
            $claims = json_decode($this->unSegment($payloadJson), true, 512, JSON_THROW_ON_ERROR);

            if (!is_array($header) || !is_array($claims)) {
                return null;
            }

            $algo = (string) ($header['alg'] ?? '');

            if ($algo !== $this->algo || !isset(self::ALGOS[$algo])) {
                return null;
            }

            $expected = $this->sign("$headerJson.$payloadJson");

            if (!hash_equals($expected, $given)) {
                return null;
            }

            $exp = (int) ($claims['exp'] ?? 0);

            if ($now > $exp) {
                return null;
            }

            if (isset($claims['nbf']) && $now < (int) $claims['nbf']) {
                return null;
            }

            return (object) $claims;
        } catch (\Throwable) {
            return null;
        }
    }

    /**
     * Reports whether a token decodes to valid, unexpired claims.
     *
     * @param string $token Token string.
     * @param int|null $now Clock to test against.
     * @return bool True when the token is valid.
     */
    public function valid(string $token, ?int $now = null): bool
    {
        return $this->decode($token, $now) !== null;
    }

    /**
     * Legacy check on an already decoded claim set.
     *
     * @param \stdClass $claims Claims from decode().
     * @return bool True when the token has not expired.
     */
    public static function validClaims(\stdClass $claims): bool
    {
        $exp = (int) ($claims->exp ?? 0);

        return $exp === 0 || time() <= $exp;
    }

    /**
     * Signs a signed-content string.
     *
     * @return string Base64url signature segment.
     */
    private function sign(string $content): string
    {
        return $this->segment(Sha::hmac($this->secret, $content, self::ALGOS[$this->algo]));
    }

    /**
     * Serializes a value into a base64url segment.
     */
    private function segment(mixed $value): string
    {
        $raw = is_string($value) ? $value : json_encode($value, JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR);

        return rtrim(strtr(base64_encode($raw), '+/', '-_'), '=');
    }

    /**
     * Restores raw bytes from a base64url segment.
     */
    private function unSegment(string $segment): string
    {
        $padded = str_pad(strtr($segment, '-_', '+/'), strlen($segment) + (4 - strlen($segment) % 4) % 4, '=');

        return base64_decode($padded, true);
    }
}
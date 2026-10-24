<?php

use Strukt\Codec;
use Strukt\Csrf;
use Strukt\Hash\Bcrypt;
use Strukt\Hash\Sha;
use Strukt\Jwt;
use Strukt\Ssl\All;
use Strukt\Ssl\Config;
use Strukt\Ssl\KeyPair;
use Strukt\Ssl\KeyPairBuilder;
use Strukt\Ssl\KeyPairInterface;
use Strukt\Ssl\PrivateKey;
use Strukt\Ssl\PublicKey;

if (function_exists('helper')) {
    helper('key');
}

if (!function_exists('codec') && helper_add('codec')) {
    /**
     * AES encoder/decoder with an explicitly supplied key.
     *
     * Needs no config file, unlike the legacy helper. With no vector a random
     * IV is generated per message and carried in the output.
     *
     * @param string $key Symmetric key.
     * @param string $cipher Cipher name.
     * @param string|null $vector Hex IV or null for a random one.
     * @return Codec New codec.
     */
    function codec(string $key, string $cipher = 'AES-128-CBC', ?string $vector = null): Codec
    {
        return Codec::make($key, $cipher, $vector);
    }
}

if (!function_exists('bcry') && helper_add('bcry')) {
    /**
     * Bcrypt hasher bound to one password.
     *
     * @param string $password Plain text password.
     * @param int $cost Work factor.
     * @return object With encode(): string and verify(string $hash): bool.
     */
    function bcry(string $password, int $cost = 12): object
    {
        $hash = new Bcrypt($cost);

        return new class($hash, $password) {
            public function __construct(private Bcrypt $hash, private string $password)
            {
            }

            /**
             * @return string Bcrypt digest.
             */
            public function encode(): string
            {
                return $this->hash->makeHash($this->password);
            }

            /**
             * @param string $hash Stored digest.
             * @return bool True when the password matches.
             */
            public function verify(string $hash): bool
            {
                return $this->hash->verify($this->password, $hash);
            }
        };
    }
}

if (!function_exists('sha256') && helper_add('sha256')) {
    /**
     * Single SHA-256 digest.
     *
     * @param string $input Data to hash.
     * @return string Hex digest.
     */
    function sha256(string $input): string
    {
        return Sha::once256($input);
    }
}

if (!function_exists('sha256dbl') && helper_add('sha256dbl')) {
    /**
     * Double SHA-256 digest.
     *
     * @param string $input Data to hash.
     * @return string Hex digest.
     */
    function sha256dbl(string $input): string
    {
        return Sha::dbl256($input);
    }
}

if (!function_exists('csrf') && helper_add('csrf')) {
    /**
     * CSRF token maker or validator.
     *
     * Give the payload as an array to mint a token, or pass a token string to
     * decode/validate it. The key is always explicit.
     *
     * @param array|string $data Payload to embed, or token to inspect.
     * @param string $key Symmetric key.
     * @param int $duration Seconds the token stays valid.
     * @return object With encode(): string, decode(): array, and valid(): bool.
     */
    function csrf(array|string $data, string $key = 'csrf', int $duration = 300): object
    {
        return new class($data, $key, $duration) {
            public function __construct(
                private array|string $data,
                private string $key,
                private int $duration,
            ) {
            }

            /**
             * @return string New token.
             */
            public function encode(): string
            {
                return Csrf::make($this->data, $this->key, $this->duration)->encode();
            }

            /**
             * @return array{data: array|string, iat: int, eat: int} Claim set.
             */
            public function decode(): array
            {
                return Csrf::decode($this->data, $this->key);
            }

            /**
             * @return bool True when the token is valid.
             */
            public function valid(): bool
            {
                return Csrf::valid($this->data, $this->key);
            }
        };
    }
}

if (!function_exists('jwt') && helper_add('jwt')) {
    /**
     * JSON web token maker or validator.
     *
     * Pass an array to mint a token; pass the token string to inspect it. The
     * secret is always explicit.
     *
     * @param array|string $data Payload to embed, or token to inspect.
     * @param string $secret Signing key.
     * @param string $algo Algorithm from HS256/384/512.
     * @param int $expire Validity in seconds.
     * @return string|object Token, or an object with valid(): bool and yield(): \stdClass.
     */
    function jwt(array|string $data, string $secret, string $algo = 'HS256', int $expire = 3600): string|object
    {
        $signer = Jwt::make([
            'secret' => $secret,
            'algo' => $algo,
            'expire' => $expire,
        ]);

        if (is_array($data)) {
            return $signer->encode($data);
        }

        return new class($signer->decode($data)) {
            public function __construct(private ?\stdClass $claims)
            {
            }

            /**
             * @return bool True when the token decoded.
             */
            public function valid(): bool
            {
                return $this->claims !== null;
            }

            /**
             * @return \stdClass Claim set.
             */
            public function yield(): \stdClass
            {
                return $this->claims;
            }
        };
    }
}

if (!function_exists('ssl') && helper_add('ssl')) {
    /**
     * Entry point into the ssl facade.
     *
     * @param KeyPair|KeyPairInterface|Config|string|null $arg Pair, config, private-key path, or null for a fresh pair.
     * @return All Facade.
     */
    function ssl(KeyPair|KeyPairInterface|Config|string|null $arg = null): All
    {
        if ($arg instanceof KeyPair) {
            return All::useKeys($arg);
        }

        if ($arg instanceof KeyPairInterface) {
            return new All($arg);
        }

        if ($arg instanceof Config) {
            return All::makeKeysByCfg($arg);
        }

        if (is_string($arg) && is_file($arg)) {
            return All::keyPath($arg);
        }

        return All::makeKeys();
    }
}

if (!function_exists('keypair') && helper_add('keypair')) {
    /**
     * Builds or adopts a key pair.
     *
     * @param string|null $privateKeyPath Adopt an existing private key when given.
     * @param string $dir Directory for generated files.
     * @param string $name Base file name without extension.
     * @return KeyPair Pair.
     */
    function keypair(?string $privateKeyPath = null, string $dir = 'keys/', string $name = 'key'): KeyPair
    {
        if ($privateKeyPath !== null) {
            return KeyPair::fromPrivate(PrivateKey::read($privateKeyPath), $dir, $name);
        }

        return KeyPairBuilder::make($dir, $name)->makeKeyPair();
    }
}

if (!function_exists('pubkey') && helper_add('pubkey')) {
    /**
     * Loads a public key from a PEM file.
     *
     * @param string $path Path to the public key file.
     * @return PublicKey Public key.
     */
    function pubkey(string $path): PublicKey
    {
        return PublicKey::read($path);
    }
}